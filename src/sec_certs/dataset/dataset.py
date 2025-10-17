from __future__ import annotations

import logging
import shutil
import tarfile
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Generic, TypeVar, cast

import pandas as pd
import requests
from packaging.version import parse as parse_version
from pydantic import AnyHttpUrl

from sec_certs._version import __version__
from sec_certs.dataset.auxiliary_dataset_handling import AuxiliaryDatasetHandler
from sec_certs.sample.certificate import Certificate
from sec_certs.serialization.json import (
    ComplexSerializableType,
    get_class_fullname,
    only_backed,
    serialize,
)
from sec_certs.utils import helpers
from sec_certs.utils.profiling import staged

logger = logging.getLogger(__name__)

CertSubType = TypeVar("CertSubType", bound=Certificate)
DatasetSubType = TypeVar("DatasetSubType", bound="Dataset")


class Dataset(Generic[CertSubType], ComplexSerializableType, ABC):
    """
    Base class for dataset of certificates from CC and FIPS 140 schemes. Layouts public
    functions, the processing pipeline and common operations on the dataset and certs.
    """

    FULL_ARCHIVE_URL: ClassVar[AnyHttpUrl]
    SNAPSHOT_URL: ClassVar[AnyHttpUrl]

    @dataclass
    class DatasetInternalState(ComplexSerializableType):
        meta_sources_parsed: bool = False
        artifacts_downloaded: bool = False
        pdfs_converted: bool = False
        auxiliary_datasets_processed: bool = False
        certs_analyzed: bool = False
        sec_certs_version: str | None = None

        def __init__(
            self,
            meta_sources_parsed: bool = False,
            artifacts_downloaded: bool = False,
            pdfs_converted: bool = False,
            auxiliary_datasets_processed: bool = False,
            certs_analyzed: bool = False,
            sec_certs_version: str | None = None,
        ):
            self.meta_sources_parsed = meta_sources_parsed
            self.artifacts_downloaded = artifacts_downloaded
            self.pdfs_converted = pdfs_converted
            self.auxiliary_datasets_processed = auxiliary_datasets_processed
            self.certs_analyzed = certs_analyzed
            self.sec_certs_version = sec_certs_version if sec_certs_version is not None else __version__

    def __init__(
        self,
        certs: dict[str, CertSubType] | None = None,
        root_dir: str | Path | None = None,
        name: str | None = None,
        description: str = "",
        state: DatasetInternalState | None = None,
        aux_handlers: dict[type[AuxiliaryDatasetHandler], AuxiliaryDatasetHandler] | None = None,
    ):
        super().__init__()
        self.certs = certs if certs is not None else {}
        self.timestamp = datetime.now()
        self.name = name if name else type(self).__name__
        self.description = description if description else datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.state = state if state else self.DatasetInternalState()
        self.root_dir = Path(root_dir) if root_dir is not None else None  # type: ignore
        self.aux_handlers = aux_handlers if aux_handlers is not None else {}
        # Make sure that the auxiliary handlers (if supplied by the user) have the correct root_dir
        self._set_local_paths()

    @property
    def is_backed(self) -> bool:
        """
        Returns whether the dataset is backed by a directory.
        """
        return self.root_dir is not None

    @property
    def root_dir(self) -> Path:
        """
        Directory that will hold the serialized dataset files.
        """
        return self._root_dir  # type: ignore

    @root_dir.setter
    def root_dir(self, new_dir: str | Path | None) -> None:
        """
        This setter will only set the root dir and all internal paths so that they point
        to the new root dir. No data is being moved around.
        """
        if new_dir is None:
            self._root_dir = None
            return

        new_dir = Path(new_dir)
        if new_dir.is_file():
            raise ValueError(f"Root dir of {get_class_fullname(self)} cannot be a file.")

        self._root_dir = new_dir
        self._set_local_paths()

    @property
    @only_backed(throw=False)
    def web_dir(self) -> Path:
        """
        Path to certification-artifacts posted on web.
        """
        return self.root_dir / "web"

    @property
    @only_backed(throw=False)
    def auxiliary_datasets_dir(self) -> Path:
        """
        Path to directory with auxiliary datasets.
        """
        return self.root_dir / "auxiliary_datasets"

    @property
    @only_backed(throw=False)
    def certs_dir(self) -> Path:
        """
        Returns directory that holds files associated with certificates
        """
        return self.root_dir / "certs"

    @property
    @only_backed(throw=False)
    def json_path(self) -> Path:
        return self.root_dir / (self.name + ".json")

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, Certificate):
            raise TypeError(
                f"You attempted to check if {type(item)} is member of {type(self)}, but only {type(Certificate)} are allowed to be members."
            )
        return item.dgst in self.certs

    def __iter__(self) -> Iterator[CertSubType]:
        yield from self.certs.values()

    def __getitem__(self, item: str) -> CertSubType:
        return self.certs.__getitem__(item.lower())

    def __setitem__(self, key: str, value: CertSubType):
        self.certs.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.certs)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dataset):
            return NotImplemented
        return self.certs == other.certs

    def __str__(self) -> str:
        return str(type(self).__name__) + ":" + self.name + ", " + str(len(self)) + " certificates"

    @classmethod
    def from_web(  # noqa
        cls: type[DatasetSubType],
        archive_url: AnyHttpUrl | None = None,
        snapshot_url: AnyHttpUrl | None = None,
        progress_bar_desc: str | None = None,
        path: str | Path | None = None,
        auxiliary_datasets: bool = False,
        artifacts: bool = False,
    ) -> DatasetSubType:
        """
        Fetches the fresh dataset snapshot from sec-certs.org.

        Optionally stores it at the given path (a directory) and also downloads auxiliary datasets and artifacts (PDFs).

        .. note::
            Note that including the auxiliary datasets adds several gigabytes and including artifacts adds tens of gigabytes.

        :param archive_url: The URL of the full dataset archive. If `None` provided, defaults to `cls.FULL_ARCHIVE_URL`.
        :param snapshot_url: The URL of the full dataset snapshot. If `None` provided, defaults to `cls.SNAPSHOT_URL`.
        :param progress_bar_desc: Description of the download progress bar. If `None`, will pick reasonable default.
        :param path: Path to a directory where to store the dataset, or `None` if it should not be stored.
        :param auxiliary_datasets: Whether to also download auxiliary datasets (CVE, CPE, CPEMatch datasets).
        :param artifacts: Whether to also download artifacts (i.e. PDFs).
        """
        if not archive_url:
            archive_url = cls.FULL_ARCHIVE_URL
        if not snapshot_url:
            snapshot_url = cls.SNAPSHOT_URL
        if not progress_bar_desc:
            progress_bar_desc = f"Downloading: {cls.__name__}"

        if (artifacts or auxiliary_datasets) and path is None:
            raise ValueError("Path needs to be defined if artifacts or auxiliary datasets are to be downloaded.")
        if artifacts and not auxiliary_datasets:
            raise ValueError("Auxiliary datasets need to be downloaded if artifacts are to be downloaded.")
        if path is not None:
            path = Path(path)
            if not path.exists():
                path.mkdir(parents=True)
            if not path.is_dir():
                raise ValueError("Path needs to be a directory.")
        if artifacts:
            fsize = helpers.query_file_size(str(archive_url))
            base_tmpdir = tempfile.gettempdir() if fsize is None else helpers.tempdir_for(fsize)
            with tempfile.TemporaryDirectory(dir=base_tmpdir) as tmp_dir:
                dset_path = Path(tmp_dir) / "dataset.tar.gz"
                res = helpers.download_file(
                    str(archive_url),
                    dset_path,
                    show_progress_bar=True,
                    progress_bar_desc=progress_bar_desc,
                )
                if res != requests.codes.ok:
                    raise ValueError(f"Download failed: {res}")
                with tarfile.open(dset_path, "r:gz") as tar:
                    tar.extractall(str(path))
                dset = cls.from_json(path / "dataset.json")  # type: ignore
                if auxiliary_datasets:
                    dset.process_auxiliary_datasets(download_fresh=False)
        else:
            with tempfile.TemporaryDirectory() as tmp_dir:
                dset_path = Path(tmp_dir) / "dataset.json"
                helpers.download_file(
                    str(snapshot_url),
                    dset_path,
                    show_progress_bar=True,
                    progress_bar_desc=progress_bar_desc,
                )
                dset = cls.from_json(dset_path)
                if path:
                    dset.move_dataset(path)
                else:
                    # Clear the path, as it points to temporary file
                    dset._root_dir = None
            if auxiliary_datasets:
                dset.process_auxiliary_datasets(download_fresh=True)
        return dset

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "timestamp": self.timestamp,
            "name": self.name,
            "description": self.description,
            "n_certs": len(self),
            "certs": list(self.certs.values()),
        }

    @classmethod
    def from_dict(cls, dct: dict) -> Dataset:
        certs = {x.dgst: x for x in dct["certs"]}
        dset = cls(certs, name=dct["name"], description=dct["description"], state=dct["state"])
        if len(dset) != (claimed := dct["n_certs"]):
            logger.error(
                f"The actual number of certs in dataset ({len(dset)}) does not match the claimed number ({claimed})."
            )
        # Version check and warning
        try:
            from sec_certs._version import __version__ as current_version
        except ImportError:
            current_version = "unknown"
        dset_version = getattr(getattr(dset, "state", None), "sec_certs_version", None)
        if dset_version and current_version != "unknown" and dset_version != current_version:
            try:
                dset_v = parse_version(dset_version)
                curr_v = parse_version(current_version)
                if dset_v > curr_v:
                    which = "newer than"
                elif dset_v < curr_v:
                    which = "older than"
                else:
                    which = "equal to"
                logger.warning(
                    f"Dataset was created with sec-certs version {dset_version} ({which} your version {current_version}). To install the matching version: pip install sec-certs=={dset_version}"
                )
            except Exception:
                logger.warning(
                    f"Dataset was created with sec-certs version {dset_version}, but you are running version {current_version}. To install the matching version: pip install sec-certs=={dset_version}"
                )
        return dset

    @classmethod
    def from_json(cls: type[DatasetSubType], input_path: str | Path, is_compressed: bool = False) -> DatasetSubType:
        dset = cast(
            "DatasetSubType",
            ComplexSerializableType.from_json(input_path, is_compressed),
        )
        dset._root_dir = Path(input_path).parent.absolute()
        dset._set_local_paths()
        return dset

    def _set_local_paths(self) -> None:
        if self.root_dir is None:
            return
        if hasattr(self, "aux_handlers") and self.aux_handlers:
            for handler in self.aux_handlers.values():
                handler.set_local_paths(self.auxiliary_datasets_dir)

    @only_backed()
    def move_dataset(self, new_root_dir: str | Path) -> None:
        """
        Moves all dataset files to `new_root_dir` and adjusts all paths internally. Deletes the artifacts from the original location.

        :param str | Path new_root_dir: path to directory where the new dataset shall be stored.
        """
        new_root_dir = Path(new_root_dir)
        if new_root_dir.is_file():
            raise ValueError("New root dir must be a directory, not an existing file.")
        new_root_dir.mkdir(parents=True, exist_ok=True)

        shutil.copytree(str(self.root_dir), str(new_root_dir), dirs_exist_ok=True)
        shutil.rmtree(self.root_dir)
        self.root_dir = new_root_dir

    @only_backed()
    def copy_dataset(self, new_root_dir: str | Path) -> None:
        """
        Copies all dataset files to `new_root_dir` and adjusts all paths internally. Keeps the artifacts from the original location.

        :param str | Path new_root_dir: path to directory where the new dataset shall be stored.
        """
        new_root_dir = Path(new_root_dir)
        if new_root_dir.is_file():
            raise ValueError("New root dir must be a directory, not an existing file.")
        new_root_dir.mkdir(parents=True, exist_ok=True)

        shutil.copytree(str(self.root_dir), str(new_root_dir), dirs_exist_ok=True)
        self.root_dir = new_root_dir

    def get_certs_by_name(self, name: str) -> set[CertSubType]:
        """
        Returns list of certificates that match given name.
        """
        return {crt for crt in self if crt.name and crt.name == name}

    @abstractmethod
    def get_certs_from_web(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @staged(logger, "Processing auxiliary datasets")
    @serialize
    @only_backed()
    def process_auxiliary_datasets(self, download_fresh: bool = False, **kwargs) -> None:
        """
        Processes all auxiliary datasets (CPE, CVE, ...) that are required during computation.
        """
        logger.info("Processing auxiliary datasets.")
        for handler in self.aux_handlers.values():
            handler.process_dataset(download_fresh)
        self.state.auxiliary_datasets_processed = True

    @only_backed()
    def load_auxiliary_datasets(self) -> None:
        logger.info("Loading auxiliary datasets into memory.")
        for handler in self.aux_handlers.values():
            if not hasattr(handler, "dset"):
                try:
                    handler.load_dataset()
                except Exception:
                    logger.warning(
                        f"Failed to load auxiliary dataset bound to {handler}, some functionality may not work."
                    )

    @serialize
    @only_backed()
    def download_all_artifacts(self, fresh: bool = True) -> None:
        """
        Downloads all artifacts related to certification in the given scheme.
        """
        if not self.state.meta_sources_parsed:
            logger.error("Attempting to download pdfs while not having csv/html meta-sources parsed. Returning.")
            return

        logger.info("Attempting to download certification artifacts.")
        self._download_all_artifacts_body(fresh)
        if fresh:
            self._download_all_artifacts_body(False)

        self.state.artifacts_downloaded = True

    @abstractmethod
    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @serialize
    @only_backed()
    def convert_all_pdfs(self, fresh: bool = True) -> None:
        """
        Converts all pdf artifacts to txt and json, given the certification scheme.
        """
        if not self.state.artifacts_downloaded:
            logger.error("Attempting to convert pdfs while not having the artifacts downloaded. Returning.")
            return

        logger.info("Converting all PDFs to txt and json")
        self._convert_all_pdfs_body(fresh)

        self.state.pdfs_converted = True

    @abstractmethod
    def _convert_all_pdfs_body(self, fresh: bool = True) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @serialize
    @only_backed()
    def analyze_certificates(self) -> None:
        """
        Does two things:
            - Extracts data from certificates (keywords, etc.)
            - Computes various heuristics on the certificates.
        """
        if not self.state.pdfs_converted:
            logger.info(
                "Attempting run analysis of txt files while not having the pdf->txt conversion done. Returning."
            )
            return
        if not self.state.auxiliary_datasets_processed:
            logger.info(
                "Attempting to run analysis of certifies while not having the auxiliary datasets processed. Returning."
            )

        logger.info("Analyzing certificates.")
        self._analyze_certificates_body()
        self.state.certs_analyzed = True

    def _analyze_certificates_body(self) -> None:
        logger.info("Extracting data and heuristics")
        self.extract_data()
        self.compute_heuristics()

    @abstractmethod
    @only_backed()
    def extract_data(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @serialize
    @only_backed()
    def compute_heuristics(self) -> None:
        logger.info("Computing various heuristics from the certificates.")
        self.load_auxiliary_datasets()
        self._compute_heuristics_body()

    @abstractmethod
    def _compute_heuristics_body(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    def get_keywords_df(self, var: str) -> pd.DataFrame:
        """
        Get dataframe of keyword hits for attribute (var) that is member of PdfData class.
        """
        data = [dict({"dgst": x.dgst}, **x.pdf_data.get_keywords_df_data(var)) for x in self]
        return pd.DataFrame(data).set_index("dgst")

    def update_with_certs(self, certs: list[CertSubType]) -> None:
        """
        Enriches the dataset with `certs`
        :param List[Certificate] certs: new certs to include into the dataset.
        """
        if any(x not in self for x in certs):
            logger.warning("Updating dataset with certificates outside of the dataset!")
        self.certs.update({x.dgst: x for x in certs})

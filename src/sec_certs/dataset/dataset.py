from __future__ import annotations

import gzip
import itertools
import json
import logging
import re
import shutil
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Generic, TypeVar, cast

import pandas as pd

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.cpe import CPE
from sec_certs.serialization.json import ComplexSerializableType, get_class_fullname, serialize
from sec_certs.utils import helpers
from sec_certs.utils.nvd_dataset_builder import CpeMatchNvdDatasetBuilder, CpeNvdDatasetBuilder, CveNvdDatasetBuilder
from sec_certs.utils.profiling import staged
from sec_certs.utils.tqdm import tqdm

logger = logging.getLogger(__name__)


@dataclass
class AuxiliaryDatasets:
    cpe_dset: CPEDataset | None = None
    cve_dset: CVEDataset | None = None


CertSubType = TypeVar("CertSubType", bound=Certificate)
AuxiliaryDatasetsSubType = TypeVar("AuxiliaryDatasetsSubType", bound=AuxiliaryDatasets)
DatasetSubType = TypeVar("DatasetSubType", bound="Dataset")


class Dataset(Generic[CertSubType, AuxiliaryDatasetsSubType], ComplexSerializableType, ABC):
    """
    Base class for dataset of certificates from CC and FIPS 140 schemes. Layouts public
    functions, the processing pipeline and common operations on the dataset and certs.
    """

    @dataclass
    class DatasetInternalState(ComplexSerializableType):
        meta_sources_parsed: bool = False
        artifacts_downloaded: bool = False
        pdfs_converted: bool = False
        auxiliary_datasets_processed: bool = False
        certs_analyzed: bool = False

    def __init__(
        self,
        certs: dict[str, CertSubType] = {},
        root_dir: str | Path = constants.DUMMY_NONEXISTING_PATH,
        name: str | None = None,
        description: str = "",
        state: DatasetInternalState | None = None,
        auxiliary_datasets: AuxiliaryDatasetsSubType | None = None,
    ):
        self.certs = certs

        self.timestamp = datetime.now()
        self.sha256_digest = "not implemented"
        self.name = name if name else type(self).__name__.lower() + "_dataset"
        self.description = description if description else "No description provided"
        self.state = state if state else self.DatasetInternalState()

        if not auxiliary_datasets:
            self.auxiliary_datasets = AuxiliaryDatasets()
        else:
            self.auxiliary_datasets = auxiliary_datasets

        self.root_dir = Path(root_dir)

    @property
    def root_dir(self) -> Path:
        """
        Directory that will hold the serialized dataset files.
        """
        return self._root_dir

    @root_dir.setter
    def root_dir(self: DatasetSubType, new_dir: str | Path) -> None:
        """
        This setter will only set the root dir and all internal paths so that they point
        to the new root dir. No data is being moved around.
        """
        new_dir = Path(new_dir)
        if new_dir.is_file():
            raise ValueError(f"Root dir of {get_class_fullname(self)} cannot be a file.")

        self._root_dir = new_dir
        self._set_local_paths()

    @property
    def web_dir(self) -> Path:
        """
        Path to certification-artifacts posted on web.
        """
        return self.root_dir / "web"

    @property
    def auxiliary_datasets_dir(self) -> Path:
        """
        Path to directory with auxiliary datasets.
        """
        return self.root_dir / "auxiliary_datasets"

    @property
    def certs_dir(self) -> Path:
        """
        Returns directory that holds files associated with certificates
        """
        return self.root_dir / "certs"

    @property
    def cpe_dataset_path(self) -> Path:
        return self.auxiliary_datasets_dir / "cpe_dataset.json"

    @property
    def cpe_match_json_path(self) -> Path:
        return self.auxiliary_datasets_dir / "cpe_match_feed.json"

    @property
    def cve_dataset_path(self) -> Path:
        return self.auxiliary_datasets_dir / "cve_dataset.json"

    @property
    def nist_cve_cpe_matching_dset_path(self) -> Path:
        return self.auxiliary_datasets_dir / "nvdcpematch-1.0.json"

    @property
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
    def from_web(cls: type[DatasetSubType], url: str, progress_bar_desc: str, filename: str) -> DatasetSubType:
        """
        Fetches a fully processed dataset instance from static site that hosts it.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / filename
            helpers.download_file(url, dset_path, show_progress_bar=True, progress_bar_desc=progress_bar_desc)
            dset = cls.from_json(dset_path)
            dset.root_dir = constants.DUMMY_NONEXISTING_PATH
            return dset

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "timestamp": self.timestamp,
            "sha256_digest": self.sha256_digest,
            "name": self.name,
            "description": self.description,
            "n_certs": len(self),
            "certs": list(self.certs.values()),
        }

    @classmethod
    def from_dict(cls: type[DatasetSubType], dct: dict) -> DatasetSubType:
        certs = {x.dgst: x for x in dct["certs"]}
        dset = cls(certs, name=dct["name"], description=dct["description"], state=dct["state"])
        if len(dset) != (claimed := dct["n_certs"]):
            logger.error(
                f"The actual number of certs in dataset ({len(dset)}) does not match the claimed number ({claimed})."
            )
        return dset

    @classmethod
    def from_json(cls: type[DatasetSubType], input_path: str | Path, is_compressed: bool = False) -> DatasetSubType:
        dset = cast("DatasetSubType", ComplexSerializableType.from_json(input_path, is_compressed))
        dset._root_dir = Path(input_path).parent.absolute()
        dset._set_local_paths()
        return dset

    def _set_local_paths(self) -> None:
        if self.auxiliary_datasets.cpe_dset:
            self.auxiliary_datasets.cpe_dset.json_path = self.cpe_dataset_path
        if self.auxiliary_datasets.cve_dset:
            self.auxiliary_datasets.cve_dset.json_path = self.cve_dataset_path

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

    def _get_certs_by_name(self, name: str) -> set[CertSubType]:
        """
        Returns list of certificates that match given name.
        """
        return {crt for crt in self if crt.name and crt.name == name}

    @abstractmethod
    def get_certs_from_web(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @serialize
    @abstractmethod
    def process_auxiliary_datasets(self, download_fresh: bool = False) -> None:
        """
        Processes all auxiliary datasets (CPE, CVE, ...) that are required during computation.
        """
        logger.info("Processing auxiliary datasets.")
        self.auxiliary_datasets_dir.mkdir(parents=True, exist_ok=True)
        self.auxiliary_datasets.cpe_dset = self._prepare_cpe_dataset(download_fresh)
        self.auxiliary_datasets.cve_dset = self._prepare_cve_dataset(download_fresh)

        if download_fresh or not self.cpe_match_json_path.exists():
            self._prepare_cpe_match_dict(download_fresh=download_fresh)

        self.state.auxiliary_datasets_processed = True

    @serialize
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
    def convert_all_pdfs(self, fresh: bool = True) -> None:
        """
        Converts all pdf artifacts to txt, given the certification scheme.
        """
        if not self.state.artifacts_downloaded:
            logger.error("Attempting to convert pdfs while not having the artifacts downloaded. Returning.")
            return

        logger.info("Converting all PDFs to txt")
        self._convert_all_pdfs_body(fresh)

        self.state.pdfs_converted = True

    @abstractmethod
    def _convert_all_pdfs_body(self, fresh: bool = True) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @serialize
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
        self.extract_data()
        self._compute_heuristics()

    @abstractmethod
    def extract_data(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    def _compute_heuristics(self) -> None:
        logger.info("Computing various heuristics from the certificates.")
        self.compute_cpe_heuristics()
        self.compute_related_cves()
        self._compute_references()
        self._compute_transitive_vulnerabilities()

    @abstractmethod
    def _compute_references(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @abstractmethod
    def _compute_transitive_vulnerabilities(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @staged(logger, "Processing CPEDataset.")
    def _prepare_cpe_dataset(self, download_fresh: bool = False) -> CPEDataset:
        if not self.auxiliary_datasets_dir.exists():
            self.auxiliary_datasets_dir.mkdir(parents=True)

        if self.cpe_dataset_path.exists():
            logger.info("Preparing CPEDataset from json.")
            cpe_dataset = CPEDataset.from_json(self.cpe_dataset_path)
        else:
            cpe_dataset = CPEDataset(json_path=self.cpe_dataset_path)
            download_fresh = True

        if download_fresh:
            if config.preferred_source_nvd_datasets == "api":
                logger.info("Fetching new CPE records from NVD API.")
                with CpeNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
                    cpe_dataset = builder.build_dataset(cpe_dataset)
            else:
                logger.info("Preparing CPEDataset from seccerts.org.")
                cpe_dataset = CPEDataset.from_web(self.cpe_dataset_path)
            cpe_dataset.to_json()

        return cpe_dataset

    @staged(logger, "Processing CVEDataset.")
    def _prepare_cve_dataset(self, download_fresh: bool = False) -> CVEDataset:
        if not self.auxiliary_datasets_dir.exists():
            logger.info("Loading CVEDataset from json.")
            self.auxiliary_datasets_dir.mkdir(parents=True)

        if self.cve_dataset_path.exists():
            logger.info("Preparing CVEDataset from json.")
            cve_dataset = CVEDataset.from_json(self.cve_dataset_path)
        else:
            cve_dataset = CVEDataset(json_path=self.cve_dataset_path)
            download_fresh = True

        if download_fresh:
            if config.preferred_source_nvd_datasets == "api":
                logger.info("Fetching new CVE records from NVD API.")
                with CveNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
                    cve_dataset = builder.build_dataset(cve_dataset)
            else:
                logger.info("Preparing CVEDataset from seccerts.org")
                cve_dataset = CVEDataset.from_web(self.cve_dataset_path)
            cve_dataset.to_json()

        return cve_dataset

    @staged(logger, "Processing CPE match dict.")
    def _prepare_cpe_match_dict(self, download_fresh: bool = False) -> dict:
        if self.cpe_match_json_path.exists():
            logger.info("Preparing CPE Match feed from json.")
            with self.cpe_match_json_path.open("r") as handle:
                cpe_match_dict = json.load(handle)
        else:
            cpe_match_dict = CpeMatchNvdDatasetBuilder._init_new_dataset()
            download_fresh = True

        if download_fresh:
            if config.preferred_source_nvd_datasets == "api":
                logger.info("Fetchnig CPE Match feed from NVD APi.")
                with CpeMatchNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
                    cpe_match_dict = builder.build_dataset(cpe_match_dict)
            else:
                logger.info("Preparing CPE Match feed from seccerts.org.")
                with tempfile.TemporaryDirectory() as tmp_dir:
                    dset_path = Path(tmp_dir) / "cpe_match_feed.json.gz"
                    if (
                        not helpers.download_file(
                            config.cpe_match_latest_snapshot,
                            dset_path,
                            progress_bar_desc="Downloading CPE Match feed from web",
                        )
                        == constants.RESPONSE_OK
                    ):
                        raise RuntimeError(
                            f"Could not download CPE Match feed from {config.cpe_match_latest_snapshot}."
                        )
                    with gzip.open(str(dset_path)) as handle:
                        json_str = handle.read().decode("utf-8")
                        cpe_match_dict = json.loads(json_str)
            with self.cpe_match_json_path.open("w") as handle:
                json.dump(cpe_match_dict, handle, indent=4)

        return cpe_match_dict

    @serialize
    @staged(logger, "Computing heuristics: Finding CPE matches for certificates")
    def compute_cpe_heuristics(self) -> CPEClassifier:
        """
        Computes matching CPEs for the certificates.
        """
        WINDOWS_WEAK_CPES: set[CPE] = {
            CPE("", "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x64:*", "Microsoft Windows on X64"),
            CPE("", "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x86:*", "Microsoft Windows on X86"),
        }

        def filter_condition(cpe: CPE) -> bool:
            """
            Filters out very weak CPE matches that don't improve our database.
            """
            if (
                cpe.title
                and (cpe.version == "-" or cpe.version == "*")
                and not any(char.isdigit() for char in cpe.title)
            ):
                return False
            if (
                not cpe.title
                and cpe.item_name
                and (cpe.version == "-" or cpe.version == "*")
                and not any(char.isdigit() for char in cpe.item_name)
            ):
                return False
            if re.match(constants.RELEASE_CANDIDATE_REGEX, cpe.update):
                return False
            if cpe in WINDOWS_WEAK_CPES:
                return False
            return True

        if not self.auxiliary_datasets.cpe_dset:
            self.auxiliary_datasets.cpe_dset = self._prepare_cpe_dataset()

        clf = CPEClassifier(config.cpe_matching_threshold, config.cpe_n_max_matches)

        if self.auxiliary_datasets.cpe_dset is None:
            raise ValueError("CPE dataset cannot be None")

        clf.fit([x for x in self.auxiliary_datasets.cpe_dset if filter_condition(x)])

        cert: CertSubType
        for cert in tqdm(self, desc="Predicting CPE matches with the classifier"):
            cert.compute_heuristics_version()

            cert.heuristics.cpe_matches = (
                clf.predict_single_cert(cert.manufacturer, cert.name, cert.heuristics.extracted_versions)
                if cert.name
                else None
            )

        return clf

    @serialize
    def to_label_studio_json(self, output_path: str | Path) -> None:
        cpe_dset = self._prepare_cpe_dataset()

        lst = []
        for cert in [x for x in self if x.heuristics.cpe_matches]:
            dct = {"text": cert.label_studio_title}
            candidates = [cpe_dset[x].title for x in cert.heuristics.cpe_matches]
            candidates += ["No good match"] * (config.cpe_n_max_matches - len(candidates))
            options = ["option_" + str(x) for x in range(1, config.cpe_n_max_matches)]
            dct.update(dict(zip(options, candidates)))
            lst.append(dct)

        with Path(output_path).open("w") as handle:
            json.dump(lst, handle, indent=4)

    @serialize
    def load_label_studio_labels(self, input_path: str | Path) -> set[str]:
        with Path(input_path).open("r") as handle:
            data = json.load(handle)

        cpe_dset = self._prepare_cpe_dataset()
        title_to_cpes_dict = cpe_dset.get_title_to_cpes_dict()
        labeled_cert_digests: set[str] = set()

        logger.info("Translating label studio matches into their CPE representations and assigning to certificates.")
        for annotation in tqdm(data, desc="Translating label studio matches"):
            cpe_candidate_keys = {key for key in annotation if "option_" in key and annotation[key] != "No good match"}

            if "verified_cpe_match" not in annotation:
                incorrect_keys: set[str] = set()
            elif isinstance(annotation["verified_cpe_match"], str):
                incorrect_keys = {annotation["verified_cpe_match"]}
            else:
                incorrect_keys = set(annotation["verified_cpe_match"]["choices"])

            incorrect_keys = {x.lstrip("$") for x in incorrect_keys}
            predicted_annotations = {annotation[x] for x in cpe_candidate_keys - incorrect_keys}

            cpes: set[CPE] = set()
            for x in predicted_annotations:
                if x not in title_to_cpes_dict:
                    logger.error(f"{x} not in dataset")
                else:
                    to_update = title_to_cpes_dict[x]
                    if to_update and not cpes:
                        cpes = to_update
                    elif to_update and cpes:
                        cpes.update(to_update)

            # distinguish between FIPS and CC
            if "\n" in annotation["text"]:
                cert_name = annotation["text"].split("\nModule name: ")[1].split("\n")[0]
            else:
                cert_name = annotation["text"]

            certs = self._get_certs_by_name(cert_name)
            labeled_cert_digests.update({x.dgst for x in certs})

            for c in certs:
                c.heuristics.verified_cpe_matches = {x.uri for x in cpes if x is not None} if cpes else None

        return labeled_cert_digests

    def enrich_automated_cpes_with_manual_labels(self) -> None:
        """
        Prior to CVE matching, it is wise to expand the database of automatic CPE matches with those that were manually assigned.
        """
        for cert in cast(Iterator[Certificate], self):
            if not cert.heuristics.cpe_matches and cert.heuristics.verified_cpe_matches:
                cert.heuristics.cpe_matches = cert.heuristics.verified_cpe_matches
            elif cert.heuristics.cpe_matches and cert.heuristics.verified_cpe_matches:
                cert.heuristics.cpe_matches = set(cert.heuristics.cpe_matches).union(
                    set(cert.heuristics.verified_cpe_matches)
                )

    def _get_all_cpes_in_dataset(self) -> set[CPE]:
        if not self.auxiliary_datasets.cpe_dset:
            raise ValueError(
                "Cannot retrieve all cpes in dataset when cpe_dset is not set. You can prepare it with obj._prepare_cpe_dataset()"
            )

        cpe_matches = [
            [self.auxiliary_datasets.cpe_dset.cpes[y] for y in x.heuristics.cpe_matches]
            for x in self
            if x.heuristics.cpe_matches
        ]
        return set(itertools.chain.from_iterable(cpe_matches))

    @serialize
    @staged(logger, "Computing heuristics: CVEs in certificates.")
    def compute_related_cves(self) -> None:
        """
        Computes CVEs for the certificates, given their CPE matches.
        """

        if not self.auxiliary_datasets.cpe_dset:
            self.auxiliary_datasets.cpe_dset = self._prepare_cpe_dataset()

        if not self.auxiliary_datasets.cve_dset:
            self.auxiliary_datasets.cve_dset = self._prepare_cve_dataset()

        if self.auxiliary_datasets.cve_dset is None:
            raise ValueError("CVE dataset cannot be None")

        if not self.auxiliary_datasets.cve_dset.look_up_dicts_built:
            cpe_match_dict = self._prepare_cpe_match_dict()
            all_cpes = self._get_all_cpes_in_dataset()
            self.auxiliary_datasets.cve_dset.build_lookup_dict(cpe_match_dict, all_cpes)

        self.enrich_automated_cpes_with_manual_labels()
        cpe_rich_certs = [x for x in cast(Iterator[Certificate], self) if x.heuristics.cpe_matches]

        if not cpe_rich_certs:
            logger.error(
                "No certificates with verified CPE match detected. You must run dset.manually_verify_cpe_matches() first. Returning."
            )
            return

        cert: Certificate
        for cert in tqdm(cpe_rich_certs, desc="Computing related CVES"):
            related_cves = self.auxiliary_datasets.cve_dset.get_cves_from_matched_cpe_uris(cert.heuristics.cpe_matches)
            cert.heuristics.related_cves = related_cves if related_cves else None

        n_vulnerable = len([x for x in cpe_rich_certs if x.heuristics.related_cves])
        n_vulnerabilities = sum([len(x.heuristics.related_cves) for x in cpe_rich_certs if x.heuristics.related_cves])
        logger.info(
            f"In total, we identified {n_vulnerabilities} vulnerabilities in {n_vulnerable} vulnerable certificates."
        )

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

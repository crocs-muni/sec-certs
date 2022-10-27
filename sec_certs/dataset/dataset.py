import copy
import itertools
import json
import logging
import re
import shutil
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Pattern,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

import pandas as pd
import requests

import sec_certs.constants as constants
import sec_certs.utils.helpers as helpers
import sec_certs.utils.parallel_processing as cert_processing
from sec_certs.config.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.cpe import CPE
from sec_certs.serialization.json import ComplexSerializableType, serialize

logger = logging.getLogger(__name__)

T = TypeVar("T")
CertSubType = TypeVar("CertSubType", bound=Certificate)
DatasetSubType = TypeVar("DatasetSubType", bound="Dataset")


class Dataset(Generic[CertSubType], ComplexSerializableType, ABC):
    @dataclass
    class DatasetInternalState(ComplexSerializableType):
        meta_sources_parsed: bool = False
        artifacts_downloaded: bool = False
        pdfs_converted: bool = False
        certs_analyzed: bool = False

        def __bool__(self):
            return any(vars(self))

    def __init__(
        self,
        certs: Dict[str, CertSubType] = dict(),
        root_dir: Optional[Union[str, Path]] = None,
        name: Optional[str] = None,
        description: str = None,
        state: Optional[DatasetInternalState] = None,
        auxillary_datasets: Optional[Any] = None,
    ):
        if state is None:
            state = self.DatasetInternalState()
        self.state = state

        if not root_dir:
            root_dir = Path.cwd() / (type(self).__name__).lower()
        self._root_dir = Path(root_dir)
        self.timestamp = datetime.now()
        self.sha256_digest = "not implemented"

        if not name:
            name = type(self).__name__ + " dataset"
        self.name = name

        if not description:
            description = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.description = description

        self.name = name
        self.description = description

        self.certs = certs
        self.auxillary_datasets = auxillary_datasets

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    @root_dir.setter
    def root_dir(self, new_dir: Union[str, Path]) -> None:
        old_dset = copy.deepcopy(self)
        self._root_dir = Path(new_dir)
        self.root_dir.mkdir(exist_ok=True)
        self._set_local_paths()

        if old_dset.root_dir != self.root_dir:
            logger.info(f"Changing root dir of partially processed dataset. All contents will get copied to {new_dir}")
            self._copy_dataset_contents(old_dset)
            self.to_json()

    @property
    def web_dir(self) -> Path:
        return self.root_dir / "web"

    @property
    def auxillary_datasets_dir(self) -> Path:
        return self.root_dir / "auxillary_datasets"

    @property
    def certs_dir(self) -> Path:
        """
        Returns directory that holds files associated with certificates
        """
        return self.root_dir / "certs"

    @property
    def cpe_dataset_path(self) -> Path:
        return self.auxillary_datasets_dir / "cpe_dataset.json"

    @property
    def cve_dataset_path(self) -> Path:
        return self.auxillary_datasets_dir / "cve_dataset.json"

    @property
    def nist_cve_cpe_matching_dset_path(self) -> Path:
        return self.auxillary_datasets_dir / "nvdcpematch-1.0.json"

    @property
    def json_path(self) -> Path:
        return self.root_dir / (self.name + ".json")

    @property
    @abstractmethod
    def artifact_download_methods(self) -> List[Callable]:
        raise NotImplementedError("Not meant to be implemented by the base class.")

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
    def from_web(cls: Type[DatasetSubType], url: str, progress_bar_desc: str, filename: str) -> DatasetSubType:
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / filename
            helpers.download_file(url, dset_path, show_progress_bar=True, progress_bar_desc=progress_bar_desc)
            return cls.from_json(dset_path)

    def to_dict(self) -> Dict[str, Any]:
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
    def from_dict(cls: Type[DatasetSubType], dct: Dict) -> DatasetSubType:
        certs = {x.dgst: x for x in dct["certs"]}
        dset = cls(certs, Path("../"), dct["name"], dct["description"], dct["state"])
        if len(dset) != (claimed := dct["n_certs"]):
            logger.error(
                f"The actual number of certs in dataset ({len(dset)}) does not match the claimed number ({claimed})."
            )
        return dset

    @classmethod
    def from_json(cls: Type[DatasetSubType], input_path: Union[str, Path]) -> DatasetSubType:
        dset = cast("DatasetSubType", ComplexSerializableType.from_json(input_path))
        dset._root_dir = Path(input_path).parent.absolute()
        dset._set_local_paths()
        return dset

    def _set_local_paths(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    # Workaround from https://peps.python.org/pep-0673/ applied.
    def _copy_dataset_contents(self: DatasetSubType, old_dset: DatasetSubType) -> None:
        try:
            shutil.copytree(old_dset.root_dir, self.root_dir, dirs_exist_ok=True)
        except FileNotFoundError as e:
            logger.error(f"Attempted to copy dataset from {old_dset.root_dir}, but it's not there ({e}).")

    def _get_certs_by_name(self, name: str) -> Set[CertSubType]:
        """
        Returns list of certificates that match given name.
        """
        return {crt for crt in self if crt.name and crt.name == name}

    @abstractmethod
    def get_certs_from_web(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @abstractmethod
    def process_auxillary_datasets(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @serialize
    def download_all_artifacts(self, fresh: bool = True) -> None:
        if self.state.meta_sources_parsed is False:
            logger.error("Attempting to download pdfs while not having csv/html meta-sources parsed. Returning.")
            return

        for method in self.artifact_download_methods:
            method(fresh)

        if fresh:
            for method in self.artifact_download_methods:
                method(False)

        self.state.artifacts_downloaded = True

    @abstractmethod
    def convert_all_pdfs(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @abstractmethod
    def analyze_certificates(self) -> None:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @staticmethod
    def _download_parallel(urls: Collection[str], paths: Collection[Path], prune_corrupted: bool = True) -> None:
        exit_codes = cert_processing.process_parallel(
            helpers.download_file, list(zip(urls, paths)), config.n_threads, unpack=True
        )
        n_successful = len([e for e in exit_codes if e == requests.codes.ok])
        logger.info(f"Successfully downloaded {n_successful} files, {len(exit_codes) - n_successful} failed.")

        for url, e in zip(urls, exit_codes):
            if e != requests.codes.ok:
                logger.error(f"Failed to download {url}, exit code: {e}")

        if prune_corrupted is True:
            for p in paths:
                if p.exists() and p.stat().st_size < constants.MIN_CORRECT_CERT_SIZE:
                    logger.error(f"Corrupted file at: {p}")
                    p.unlink()

    def _prepare_cpe_dataset(self, download_fresh_cpes: bool = False, init_lookup_dicts: bool = True) -> CPEDataset:
        logger.info("Preparing CPE dataset.")
        if not self.auxillary_datasets_dir.exists():
            self.auxillary_datasets_dir.mkdir(parents=True)

        if not self.cpe_dataset_path.exists() or download_fresh_cpes is True:
            cpe_dataset = CPEDataset.from_web(self.cpe_dataset_path, init_lookup_dicts)
            cpe_dataset.to_json(str(self.cpe_dataset_path))
        else:
            cpe_dataset = CPEDataset.from_json(str(self.cpe_dataset_path))

        return cpe_dataset

    def _prepare_cve_dataset(
        self, download_fresh_cves: bool = False, use_nist_cpe_matching_dict: bool = True
    ) -> CVEDataset:
        logger.info("Preparing CVE dataset.")
        if not self.auxillary_datasets_dir.exists():
            self.auxillary_datasets_dir.mkdir(parents=True)

        if not self.cve_dataset_path.exists() or download_fresh_cves is True:
            cve_dataset = CVEDataset.from_web()
            cve_dataset.to_json(str(self.cve_dataset_path))
        else:
            cve_dataset = CVEDataset.from_json(str(self.cve_dataset_path))

        cve_dataset.build_lookup_dict(use_nist_cpe_matching_dict, self.nist_cve_cpe_matching_dset_path)
        return cve_dataset

    @serialize
    def compute_cpe_heuristics(
        self, download_fresh_cpes: bool = False
    ) -> Tuple[CPEClassifier, CPEDataset, Optional[CVEDataset]]:
        RELEASE_CANDIDATE_REGEX: Pattern = re.compile(r"rc\d{0,2}$", re.IGNORECASE)
        WINDOWS_WEAK_CPES: Set[CPE] = {
            CPE("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x64:*", "Microsoft Windows on X64", None, None),
            CPE("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x86:*", "Microsoft Windows on X86", None, None),
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
            elif (
                not cpe.title
                and cpe.item_name
                and (cpe.version == "-" or cpe.version == "*")
                and not any(char.isdigit() for char in cpe.item_name)
            ):
                return False
            elif re.match(RELEASE_CANDIDATE_REGEX, cpe.update):
                return False
            elif cpe in WINDOWS_WEAK_CPES:
                return False
            return True

        logger.info("Computing heuristics: Finding CPE matches for certificates")
        cpe_dset = self._prepare_cpe_dataset(download_fresh_cpes, init_lookup_dicts=False)
        cve_dset = None

        cpe_dset.build_lookup_dicts()
        # Temporarily disabled, see: https://github.com/crocs-muni/sec-certs/issues/173
        # if not cpe_dset.was_enhanced_with_vuln_cpes:
        #     cve_dset = self._prepare_cve_dataset(download_fresh_cves=False)
        #     cpe_dset.enhance_with_cpes_from_cve_dataset(cve_dset)  # this also calls build_lookup_dicts() on cpe_dset
        # else:
        #     cpe_dset.build_lookup_dicts()

        clf = CPEClassifier(config.cpe_matching_threshold, config.cpe_n_max_matches)
        clf.fit([x for x in cpe_dset if filter_condition(x)])

        cert: CertSubType
        for cert in helpers.tqdm(self, desc="Predicting CPE matches with the classifier"):
            cert.compute_heuristics_version()

            cert.heuristics.cpe_matches = (
                clf.predict_single_cert(cert.manufacturer, cert.name, cert.heuristics.extracted_versions)
                if cert.name
                else None
            )

        return clf, cpe_dset, cve_dset

    def to_label_studio_json(self, output_path: Union[str, Path]) -> None:
        cpe_dset = self._prepare_cpe_dataset()

        lst = []
        for cert in [x for x in cast(Iterator[Certificate], self) if x.heuristics.cpe_matches]:
            dct = {"text": cert.label_studio_title}
            candidates = [cpe_dset[x].title for x in cert.heuristics.cpe_matches]
            candidates += ["No good match"] * (config.cpe_n_max_matches - len(candidates))
            options = ["option_" + str(x) for x in range(1, config.cpe_n_max_matches)]
            dct.update({o: c for o, c in zip(options, candidates)})
            lst.append(dct)

        with Path(output_path).open("w") as handle:
            json.dump(lst, handle, indent=4)

    @serialize
    def load_label_studio_labels(self, input_path: Union[str, Path]) -> Set[str]:
        with Path(input_path).open("r") as handle:
            data = json.load(handle)

        cpe_dset = self._prepare_cpe_dataset()
        labeled_cert_digests: Set[str] = set()

        logger.info("Translating label studio matches into their CPE representations and assigning to certificates.")
        for annotation in helpers.tqdm(data, desc="Translating label studio matches"):
            cpe_candidate_keys = {
                key for key in annotation.keys() if "option_" in key and annotation[key] != "No good match"
            }

            if "verified_cpe_match" not in annotation:
                incorrect_keys: Set[str] = set()
            elif isinstance(annotation["verified_cpe_match"], str):
                incorrect_keys = {annotation["verified_cpe_match"]}
            else:
                incorrect_keys = set(annotation["verified_cpe_match"]["choices"])

            incorrect_keys = {x.lstrip("$") for x in incorrect_keys}
            predicted_annotations = {annotation[x] for x in cpe_candidate_keys - incorrect_keys}

            cpes: Set[CPE] = set()
            for x in predicted_annotations:
                if x not in cpe_dset.title_to_cpes:
                    logger.error(f"{x} not in dataset")
                else:
                    to_update = cpe_dset.title_to_cpes[x]
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

    @serialize
    def compute_related_cves(
        self,
        download_fresh_cves: bool = False,
        use_nist_cpe_matching_dict: bool = True,
        cve_dset: Optional[CVEDataset] = None,
    ) -> None:
        logger.info("Retrieving related CVEs to verified CPE matches")
        if download_fresh_cves or not cve_dset:
            cve_dset = self._prepare_cve_dataset(download_fresh_cves, use_nist_cpe_matching_dict)

        self.enrich_automated_cpes_with_manual_labels()
        cpe_rich_certs = [x for x in cast(Iterator[Certificate], self) if x.heuristics.cpe_matches]

        if not cpe_rich_certs:
            logger.error(
                "No certificates with verified CPE match detected. You must run dset.manually_verify_cpe_matches() first. Returning."
            )
            return

        relevant_cpes = set(itertools.chain.from_iterable([x.heuristics.cpe_matches for x in cpe_rich_certs]))
        cve_dset.filter_related_cpes(relevant_cpes)

        cert: Certificate
        for cert in helpers.tqdm(cpe_rich_certs, desc="Computing related CVES"):
            if cert.heuristics.cpe_matches:
                related_cves = [cve_dset.get_cve_ids_for_cpe_uri(x) for x in cert.heuristics.cpe_matches]
                related_cves = list(filter(lambda x: x is not None, related_cves))
                if related_cves:
                    cert.heuristics.related_cves = set(
                        itertools.chain.from_iterable([x for x in related_cves if x is not None])
                    )
            else:
                cert.heuristics.related_cves = None

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

import gzip
import itertools
import json
import logging
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path
from typing import Any, ClassVar

import requests

from sec_certs.configuration import config
from sec_certs.dataset.cc_scheme import CCSchemeDataset
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cc_maintenance_update import CCMaintenanceUpdate
from sec_certs.utils import helpers
from sec_certs.utils.nvd_dataset_builder import CpeMatchNvdDatasetBuilder, CpeNvdDatasetBuilder, CveNvdDatasetBuilder
from sec_certs.utils.profiling import staged

logger = logging.getLogger(__name__)


class AuxiliaryDatasetHandler(ABC):
    RELATIVE_DIR: ClassVar[str | None] = None
    aux_datasets_dir: Path
    dset: Any

    def __init__(self, aux_datasets_dir: str | Path | None) -> None:
        self.aux_datasets_dir = Path(aux_datasets_dir) if aux_datasets_dir is not None else None  # type: ignore

    @property
    def root_dir(self) -> Path:
        if self.RELATIVE_DIR:
            return self.aux_datasets_dir / Path(self.RELATIVE_DIR)
        return self.aux_datasets_dir

    @property
    @abstractmethod
    def dset_path(self) -> Path:
        raise NotImplementedError("Not meant to be implemented by base class")

    def set_local_paths(self, aux_datasets_dir: str | Path | None) -> None:
        self.aux_datasets_dir = Path(aux_datasets_dir) if aux_datasets_dir is not None else None  # type: ignore

    def process_dataset(self, download_fresh: bool = False) -> None:
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._process_dataset_body(download_fresh)

    @abstractmethod
    def load_dataset(self) -> None:
        raise NotImplementedError("Not meant to be implemented by base class")

    @abstractmethod
    def _process_dataset_body(self, download_fresh: bool = False) -> None:
        raise NotImplementedError("Not meant to be implemented by base class")


class CPEDatasetHandler(AuxiliaryDatasetHandler):
    @property
    def dset_path(self) -> Path:
        return self.root_dir / "cpe_dataset.json"

    @staged(logger, "Processing CPE dataset")
    def _process_dataset_body(self, download_fresh: bool = False) -> None:
        if not download_fresh and self.dset_path.exists():
            logger.info("Preparing CPEDataset from json.")
            self.load_dataset()
            return

        if config.preferred_source_remote_datasets == "origin":
            logger.info("Fetching new CPE records from NVD API")
            with CpeNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
                self.dset = builder.build_dataset()
        else:
            logger.info("Preparing CPEDataset from sec-certs.org.")
            self.dset = CPEDataset.from_web(self.dset_path)

        self.dset.to_json()
        self.dset.json_path = self.dset_path

    def load_dataset(self) -> None:
        self.dset = CPEDataset.from_json(self.dset_path)


class CVEDatasetHandler(AuxiliaryDatasetHandler):
    @property
    def dset_path(self) -> Path:
        return self.root_dir / "cve_dataset.json"

    @staged(logger, "Processing CVE dataset")
    def _process_dataset_body(self, download_fresh: bool = False) -> None:
        if not download_fresh and self.dset_path.exists():
            logger.info("Preparing CVEDataset from json.")
            self.load_dataset()
            return

        if config.preferred_source_remote_datasets == "origin":
            logger.info("Fetching new CVE records from NVD API.")
            with CveNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
                self.dset = builder.build_dataset()
        else:
            logger.info("Preparing CVEDataset from sec-certs.org.")
            self.dset = CVEDataset.from_web(self.dset_path)

        self.dset.to_json()
        self.dset.json_path = self.dset_path

    def load_dataset(self):
        self.dset = CVEDataset.from_json(self.dset_path)


class CPEMatchDictHandler(AuxiliaryDatasetHandler):
    @property
    def dset_path(self) -> Path:
        return self.root_dir / "cpe_match.json"

    @staged(logger, "Processing CPE Match dictionary")
    def _process_dataset_body(self, download_fresh: bool = False) -> None:
        if not download_fresh and self.dset_path.exists():
            logger.info("Preparing CPE Match feed from json.")
            self.load_dataset()
            return

        if config.preferred_source_remote_datasets == "origin":
            logger.info("Fetchnig CPE Match feed from NVD APi.")
            with CpeMatchNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
                self.dset = builder.build_dataset()
        else:
            logger.info("Preparing CPE Match feed from sec-certs.org.")
            with tempfile.TemporaryDirectory() as tmp_dir:
                dset_path = Path(tmp_dir) / "cpe_match_feed.json.gz"
                if (
                    not helpers.download_file(
                        config.cpe_match_latest_snapshot,
                        dset_path,
                        progress_bar_desc="Downloading CPE Match feed from web",
                    )
                    == requests.codes.ok
                ):
                    raise RuntimeError(f"Could not download CPE Match feed from {config.cpe_match_latest_snapshot}.")
                with gzip.open(str(dset_path)) as handle:
                    json_str = handle.read().decode("utf-8")
                    self.dset = json.loads(json_str)

        with self.dset_path.open("w") as handle:
            json.dump(self.dset, handle, indent=4)

    def load_dataset(self):
        with self.dset_path.open("r") as handle:
            self.dset = json.load(handle)


class FIPSAlgorithmDatasetHandler(AuxiliaryDatasetHandler):
    @property
    def dset_path(self) -> Path:
        return self.root_dir / "algorithms.json"

    @staged(logger, "Processing FIPS Algorithms")
    def _process_dataset_body(self, download_fresh: bool = False) -> None:
        if not download_fresh and self.dset_path.exists():
            logger.info("Preparing FIPSAlgorithmDataset from json.")
            self.load_dataset()
            return

        self.dset = FIPSAlgorithmDataset.from_web(self.dset_path)
        self.dset.to_json()
        self.dset.json_path = self.dset_path

    def load_dataset(self):
        self.dset = FIPSAlgorithmDataset.from_json(self.dset_path)


class CCSchemeDatasetHandler(AuxiliaryDatasetHandler):
    def __init__(
        self,
        aux_datasets_dir: str | Path | None,
        only_schemes: set[str] | None = None,
    ):
        super().__init__(aux_datasets_dir)
        self.only_schemes = only_schemes

    @property
    def dset_path(self) -> Path:
        return self.root_dir / "cc_scheme.json"

    @staged(logger, "Processing CC Schemes")
    def _process_dataset_body(self, download_fresh: bool = False) -> None:
        if not download_fresh and self.dset_path.exists():
            logger.info("Preparing CCSchemeDataset from json.")
            self.load_dataset()
            return

        self.dset = CCSchemeDataset.from_web(self.dset_path, self.only_schemes)
        self.dset.to_json()
        self.dset.json_path = self.dset_path

    def load_dataset(self):
        self.dset = CCSchemeDataset.from_json(self.dset_path)


class CCMaintenanceUpdateDatasetHandler(AuxiliaryDatasetHandler):
    RELATIVE_DIR: ClassVar[str] = "maintenances"
    certs_with_updates: Iterable[CCCertificate]

    def __init__(
        self,
        aux_datasets_dir: str | Path | None,
        certs_with_updates: Iterable[CCCertificate] | None = None,
    ) -> None:
        super().__init__(aux_datasets_dir)
        if certs_with_updates is None:
            self.certs_with_updates = []
        else:
            self.certs_with_updates = certs_with_updates

    @property
    def dset_path(self) -> Path:
        return self.root_dir / "maintenance_updates.json"

    def load_dataset(self) -> None:
        from sec_certs.dataset.cc import CCDatasetMaintenanceUpdates

        self.dset = CCDatasetMaintenanceUpdates.from_json(self.dset_path)

    @staged(logger, "Processing CC Maintenance updates")
    def _process_dataset_body(self, download_fresh: bool = False):
        from sec_certs.dataset.cc import CCDatasetMaintenanceUpdates

        if not download_fresh and self.dset_path.exists():
            logger.info("Preparing CCDatasetMaintenanceUpdates from json.")
            self.load_dataset()
            return

        updates = list(
            itertools.chain.from_iterable(
                CCMaintenanceUpdate.get_updates_from_cc_cert(x) for x in self.certs_with_updates
            )
        )
        self.dset = CCDatasetMaintenanceUpdates(
            {x.dgst: x for x in updates},
            root_dir=self.dset_path.parent,
            name="maintenance_updates",
        )
        self.dset.download_all_artifacts()
        self.dset.convert_all_pdfs()
        self.dset.extract_data()
        self.dset.to_json()


class ProtectionProfileDatasetHandler(AuxiliaryDatasetHandler):
    RELATIVE_DIR: ClassVar[str] = "protection_profiles"

    @property
    def dset_path(self) -> Path:
        return self.root_dir / "dataset.json"

    def load_dataset(self) -> None:
        from sec_certs.dataset.protection_profile import ProtectionProfileDataset

        self.dset = ProtectionProfileDataset.from_json(self.dset_path)

    @staged(logger, "Processing Protection profiles")
    def _process_dataset_body(self, download_fresh: bool = False):
        from sec_certs.dataset.protection_profile import ProtectionProfileDataset

        if not download_fresh and self.dset_path.exists():
            logger.info("Preparing ProtectionProfileDataset from json.")
            self.load_dataset()
            return

        self.dset_path.parent.mkdir(exist_ok=True, parents=True)
        self.dset = ProtectionProfileDataset(root_dir=self.dset_path.parent)
        self.dset.get_certs_from_web()
        self.dset.download_all_artifacts()
        self.dset.convert_all_pdfs()
        self.dset.analyze_certificates()

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from bs4 import BeautifulSoup

import sec_certs.utils.extract
from sec_certs import constants as constants
from sec_certs.config.configuration import config
from sec_certs.dataset.dataset import Dataset
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.sample.fips_algorithm import FIPSAlgorithm
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers as helpers
from sec_certs.utils import parallel_processing as cert_processing

logger = logging.getLogger(__name__)


class FIPSAlgorithmDataset(Dataset, ComplexSerializableType):
    certs: Dict[str, FIPSAlgorithm]

    def __init__(
        self,
        certs: Dict[str, FIPSAlgorithm] = dict(),
        root_dir: Optional[Path] = None,
        name: str = "dataset name",
        description: str = "dataset_description",
    ):
        super().__init__(certs, root_dir, name, description)
        self._id_map: Dict[int, List[str]] = {}

    def get_certs_from_web(self):
        self.root_dir.mkdir(exist_ok=True)
        algs_paths, algs_urls = [], []

        # get first page to find out how many pages there are
        res = helpers.download_file(constants.FIPS_ALG_SEARCH_URL + "1", self.root_dir / "page1.html")
        if res != 200:
            logger.error("Couldn't download first page of algo dataset")

        with open(self.root_dir / "page1.html", "r") as alg_file:
            soup = BeautifulSoup(alg_file.read(), "html.parser")
            num_pages_elem = soup.select("span[data-total-pages]")[0].attrs

        num_pages = int(num_pages_elem["data-total-pages"])

        for i in range(2, num_pages + 1):
            if not (self.root_dir / f"page{i}.html").exists():
                algs_urls.append(constants.FIPS_ALG_SEARCH_URL + str(i))
                algs_paths.append(self.root_dir / f"page{i}.html")

        # get the last page, always
        algs_urls.append(constants.FIPS_ALG_SEARCH_URL + str(num_pages))
        algs_paths.append(self.root_dir / f"page{num_pages}.html")

        logger.info(f"Downloading {len(algs_urls)} algo html files")
        cert_processing.process_parallel(
            FIPSCertificate.download_html_page, list(zip(algs_urls, algs_paths)), config.n_threads
        )

        logger.info(f"Parsing {len(algs_urls)} algo html files")
        self.parse_html()

    @staticmethod
    def _extract_algorithm_information(elements, vendor, date, product, validation):
        for elem in elements:
            # td > a > (vendor or date)
            attachments = elem.find_all("a")

            if len(attachments) == 0:
                vendor = elem.text.strip() if "vendor-name" in elem["id"] else vendor
                date = elem.text.strip() if "validation-date" in elem["id"] else date
                continue

            for attachment in attachments:
                product = elem.text.strip() if "product-name" in attachment["id"] else product
                validation = elem.text.strip() if "validation-number" in attachment["id"] else validation
        return vendor, date, product, validation

    def parse_html(self):
        def split_alg(alg_string):
            cert_type = alg_string.rstrip("0123456789")
            cert_id = alg_string[len(cert_type) :]
            return cert_type.strip(), cert_id.strip()

        for f in sec_certs.utils.extract.search_files(self.root_dir):
            if not f.endswith("html"):
                continue

            with open(f, "r", encoding="utf-8") as handle:
                html_soup = BeautifulSoup(handle.read(), "html.parser")

            table = html_soup.find("table", class_="table table-condensed publications-table table-bordered")
            tbody_contents = table.find("tbody").find_all("tr")
            vendor = product = validation = date = ""
            for tr in tbody_contents:
                elements = tr.find_all("td")
                vendor, date, product, validation = FIPSAlgorithmDataset._extract_algorithm_information(
                    elements, vendor, date, product, validation
                )

                alg_type, alg_id = split_alg(validation)
                fips_alg = FIPSAlgorithm(alg_id, vendor, product, alg_type, date)
                self.certs[fips_alg.dgst] = fips_alg
        # And now rebuild the id map
        self._build_id_map()

    def _build_id_map(self):
        for cert in self.certs.values():
            self._id_map.setdefault(cert.cert_id, [])
            self._id_map[cert.cert_id].append(cert.dgst)

    def _get_certs_from_name(self, name: str) -> List[FIPSAlgorithm]:
        raise NotImplementedError("Not meant to be implemented")

    def _set_local_paths(self) -> None:
        pass

    @classmethod
    def from_dict(cls, dct: Dict[str, Any]) -> "FIPSAlgorithmDataset":
        dset: FIPSAlgorithmDataset = super().from_dict(dct)
        dset._build_id_map()
        return dset

    def convert_all_pdfs(self):
        raise NotImplementedError("Not meant to be implemented")

    def download_all_pdfs(self, cert_ids: Optional[Set[str]] = None) -> None:
        raise NotImplementedError("Not meant to be implemented")

    def __getitem__(self, item: str) -> FIPSAlgorithm:
        return self.certs.__getitem__(item)

    def __setitem__(self, key: str, value: FIPSAlgorithm):
        self.certs.__setitem__(key, value)

    def certs_for_id(self, cert_id: int) -> List[FIPSAlgorithm]:
        if cert_id in self._id_map:
            return [self.certs[x] for x in self._id_map[cert_id]]
        else:
            return []

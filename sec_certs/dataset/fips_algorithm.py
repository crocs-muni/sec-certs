import json
import logging
from pathlib import Path
from typing import Dict, List, Union

from bs4 import BeautifulSoup

from sec_certs import constants as constants
from sec_certs import helpers as helpers
from sec_certs import parallel_processing as cert_processing
from sec_certs.config.configuration import config
from sec_certs.dataset.dataset import Dataset
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONDecoder, CustomJSONEncoder

logger = logging.getLogger(__name__)


class FIPSAlgorithmDataset(Dataset, ComplexSerializableType):

    certs: Dict[str, List]  # type: ignore # noqa

    def get_certs_from_web(self):
        self.root_dir.mkdir(exist_ok=True)
        algs_paths, algs_urls = [], []

        # get first page to find out how many pages there are
        helpers.download_file(constants.FIPS_ALG_URL + "1", self.root_dir / "page1.html")

        with open(self.root_dir / "page1.html", "r") as alg_file:
            soup = BeautifulSoup(alg_file.read(), "html.parser")
            num_pages = soup.select("span[data-total-pages]")[0].attrs

        for i in range(2, int(num_pages["data-total-pages"]) + 1):
            if not (self.root_dir / f"page{i}.html").exists():
                algs_urls.append(constants.FIPS_ALG_URL + str(i))
                algs_paths.append(self.root_dir / f"page{i}.html")

        # get the last page, always
        helpers.download_file(
            constants.FIPS_ALG_URL + num_pages["data-total-pages"],
            self.root_dir / f"page{int(num_pages['data-total-pages'])}.html",
        )
        logger.info(f"downloading {len(algs_urls)} algs html files")
        cert_processing.process_parallel(
            FIPSCertificate.download_html_page, list(zip(algs_urls, algs_paths)), config.n_threads
        )

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

        for f in helpers.search_files(self.root_dir):
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
                fips_alg = FIPSCertificate.Algorithm(alg_id, vendor, product, alg_type, date)
                if alg_id not in self.certs:
                    self.certs[alg_id] = []
                self.certs[alg_id].append(fips_alg)

    def convert_all_pdfs(self):
        raise NotImplementedError("Not meant to be implemented")

    def download_all_pdfs(self):
        raise NotImplementedError("Not meant to be implemented")

    @property
    def serialized_attributes(self) -> List[str]:
        return ["certs"]

    @classmethod
    def from_dict(cls, dct: Dict):
        certs = dct["certs"]

        directory = dct["_root_dir"] if "_root_dir" in dct else ""
        dset = cls(certs, Path(directory), "algorithms", "algorithms used in dataset")
        return dset

    def to_dict(self):
        return self.__dict__

    def to_json(self, output_path: Union[str, Path] = None):
        if not output_path:
            output_path = self.json_path
        with Path(output_path).open("w") as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        input_path = Path(input_path)
        with input_path.open("r") as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        dset.root_dir = input_path.parent.absolute()
        return dset

import json
import logging
from pathlib import Path
from typing import Dict, Union, List

from bs4 import BeautifulSoup

import sec_certs.helpers
from sec_certs import helpers as helpers, constants as constants, parallel_processing as cert_processing
from sec_certs.dataset.dataset import Dataset
from sec_certs.serialization import ComplexSerializableType, CustomJSONEncoder, CustomJSONDecoder
from sec_certs.certificate.fips import FIPSCertificate
from sec_certs.configuration import config


class FIPSAlgorithmDataset(Dataset, ComplexSerializableType):
    def get_certs_from_web(self):
        self.root_dir.mkdir(exist_ok=True)
        algs_paths, algs_urls = [], []

        # get first page to find out how many pages there are
        helpers.download_file(
            constants.FIPS_ALG_URL + '1',
            self.root_dir / "page1.html")

        with open(self.root_dir / "page1.html", "r") as alg_file:
            soup = BeautifulSoup(alg_file.read(), 'html.parser')
            num_pages = soup.select('span[data-total-pages]')[0].attrs

        for i in range(1, int(num_pages['data-total-pages'])):
            if not (self.root_dir / f'page{i}.html').exists():
                algs_urls.append(
                    constants.FIPS_ALG_URL + str(i))
                algs_paths.append(self.root_dir / f"page{i}.html")

        logging.info(f"downloading {len(algs_urls)} algs html files")
        cert_processing.process_parallel(FIPSCertificate.download_html_page, list(zip(algs_urls, algs_paths)),
                                         config.n_threads)

        self.parse_html()

    def parse_html(self):
        def split_alg(alg_string):
            cert_type = alg_string.rstrip('0123456789')
            cert_id = alg_string[len(cert_type):]
            return cert_type.strip(), cert_id.strip()

        for f in sec_certs.helpers.search_files(self.root_dir):
            with open(f, 'r', encoding='utf-8') as handle:
                html_soup = BeautifulSoup(handle.read(), 'html.parser')

            table = html_soup.find('table', class_='table table-condensed publications-table table-bordered')
            spans = table.find_all('span')
            for span in spans:
                elements = span.find_all('td')
                vendor, implementation = elements[0].text, elements[1].text
                elements_sliced = elements[2:]
                for i in range(0, len(elements_sliced), 2):
                    alg_type, alg_id = split_alg(elements_sliced[i].text.strip())
                    validation_date = elements_sliced[i + 1].text.strip()
                    fips_alg = FIPSCertificate.Algorithm(alg_id, vendor, implementation, alg_type, validation_date)
                    if alg_id not in self.certs:
                        self.certs[alg_id] = []
                    self.certs[alg_id].append(fips_alg)

    def convert_all_pdfs(self):
        raise NotImplementedError('Not meant to be implemented')

    def download_all_pdfs(self):
        raise NotImplementedError('Not meant to be implemented')

    @property
    def serialized_attributes(self) -> List[str]:
        return ['certs']

    @classmethod
    def from_dict(cls, dct: Dict):
        certs = dct['certs']
        dset = cls(certs, Path('../'), 'algorithms', 'algorithms used in dataset')
        return dset

    def to_json(self, output_path: Union[str, Path]):
        with Path(output_path).open('w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        input_path = Path(input_path)
        with input_path.open('r') as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        dset.root_dir = input_path.parent.absolute()
        return dset
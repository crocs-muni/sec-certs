from datetime import datetime
import logging
from typing import Dict, Collection, Union

import json
from abc import ABC, abstractmethod
from pathlib import Path

import requests

import sec_certs.helpers as helpers
import sec_certs.constants as constants
import sec_certs.parallel_processing as cert_processing

from sec_certs.certificate.certificate import Certificate
from sec_certs.serialization import CustomJSONDecoder, CustomJSONEncoder
from sec_certs.configuration import config
from sec_certs.serialization import serialize
from sec_certs.dataset.cpe import CPEDataset

logger = logging.getLogger(__name__)


class Dataset(ABC):
    def __init__(self, certs: Dict[str, 'Certificate'], root_dir: Path, name: str = 'dataset name',
                 description: str = 'dataset_description'):
        self._root_dir = root_dir
        self.timestamp = datetime.now()
        self.sha256_digest = 'not implemented'
        self.name = name
        self.description = description
        self.certs = certs

    @property
    def root_dir(self):
        return self._root_dir

    @root_dir.setter
    def root_dir(self, new_dir: Union[str, Path]):
        new_dir = Path(new_dir)
        new_dir.mkdir(exist_ok=True)
        self._root_dir = new_dir

    @property
    def web_dir(self) -> Path:
        return self.root_dir / 'web'

    @property
    def auxillary_datasets_dir(self) -> Path:
        return self.root_dir / 'auxillary_datasets'

    @property
    def cpe_dataset_path(self) -> Path:
        return self.auxillary_datasets_dir / 'cpe_dataset.json'

    @property
    def json_path(self) -> Path:
        return self.root_dir / (self.name + '.json')

    def __contains__(self, item):
        if not issubclass(type(item), Certificate):
            return False
        return item.dgst in self.certs

    def __iter__(self):
        yield from self.certs.values()

    def __getitem__(self, item: str):
        return self.certs.__getitem__(item.lower())

    def __setitem__(self, key: str, value: 'Certificate'):
        self.certs.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.certs)

    def __eq__(self, other: 'Dataset') -> bool:
        return self.certs == other.certs

    def __str__(self) -> str:
        return str(type(self).__name__) + ':' + self.name + ', ' + str(len(self)) + ' certificates'

    def to_dict(self):
        return {'timestamp': self.timestamp, 'sha256_digest': self.sha256_digest,
                'name': self.name, 'description': self.description,
                'n_certs': len(self), 'certs': list(self.certs.values())}

    @classmethod
    def from_dict(cls, dct: Dict):
        certs = {x.dgst: x for x in dct['certs']}
        dset = cls(certs, Path('../'), dct['name'], dct['description'])
        if len(dset) != (claimed := dct['n_certs']):
            logger.error(
                f'The actual number of certs in dataset ({len(dset)}) does not match the claimed number ({claimed}).')
        return dset

    def to_json(self, output_path: Union[str, Path] = None):
        if not output_path:
            output_path = self.json_path

        with Path(output_path).open('w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        input_path = Path(input_path)
        with input_path.open('r') as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        dset.root_dir = input_path.parent.absolute()
        return dset

    @abstractmethod
    def get_certs_from_web(self):
        raise NotImplementedError('Not meant to be implemented by the base class.')

    @abstractmethod
    def convert_all_pdfs(self):
        raise NotImplementedError('Not meant to be implemented by the base class.')

    @abstractmethod
    def download_all_pdfs(self):
        raise NotImplementedError('Not meant to be implemented by the base class.')

    @staticmethod
    def _download_parallel(urls: Collection[str], paths: Collection[Path], prune_corrupted: bool = True):
        exit_codes = cert_processing.process_parallel(helpers.download_file,
                                                      list(zip(urls, paths)),
                                                      config.n_threads,
                                                      unpack=True)
        n_successful = len([e for e in exit_codes if e == requests.codes.ok])
        logger.info(f'Successfully downloaded {n_successful} files, {len(exit_codes) - n_successful} failed.')

        for url, e in zip(urls, exit_codes):
            if e != requests.codes.ok:
                logger.error(f'Failed to download {url}, exit code: {e}')

        if prune_corrupted is True:
            for p in paths:
                if p.exists() and p.stat().st_size < constants.MIN_CORRECT_CERT_SIZE:
                    logger.error(f'Corrupted file at: {p}')
                    p.unlink()

    def _prepare_cpe_dataset(self, download_fresh_cpes: bool = False):
        logger.info('Preparing CPE dataset.')
        if not self.auxillary_datasets_dir.exists():
            self.auxillary_datasets_dir.mkdir(parents=True)

        if not self.cpe_dataset_path.exists() or download_fresh_cpes is True:
            cpe_dataset = CPEDataset.from_web()
            cpe_dataset.to_json(str(self.cpe_dataset_path))
        else:
            cpe_dataset = CPEDataset.from_json(str(self.cpe_dataset_path))

        return cpe_dataset

    def _compute_candidate_versions(self):
        logger.info('Computing heuristics: possible product versions in certificate name')
        for cert in self:
            cert.compute_heuristics_version()

    def _compute_cpe_matches(self, download_fresh_cpes: bool = False):
        logger.info('Computing heuristics: Finding CPE matches for certificates')
        cpe_dset = self._prepare_cpe_dataset(download_fresh_cpes)
        for cert in self:
            cert.compute_heuristics_cpe_match(cpe_dset)

    @serialize
    def compute_cpe_heuristics(self):
        self._compute_candidate_versions()
        self._compute_cpe_matches()

    def to_label_studio_json(self, output_path: Union[str, Path]):
        lst = []
        for cert in [x for x in self if x.heuristics.cpe_matches and not x.heuristics.labeled]:
            dct = {'text': cert.label_studio_title}
            candidates = [x[1].title for x in cert.heuristics.cpe_matches]
            candidates += ['No good match'] * (config.cc_cpe_max_matches - len(candidates))
            options = ['option_' + str(x) for x in range(1, 21)]
            dct.update({o: c for o, c in zip(options, candidates)})
            lst.append(dct)

        with Path(output_path).open('w') as handle:
            json.dump(lst, handle, indent=4)
from datetime import datetime
import logging
from typing import Dict, Collection, Union

import json
from abc import ABC, abstractmethod
from pathlib import Path

import requests

import sec_certs.helpers as helpers
import sec_certs.constants as constants
import sec_certs.cert_processing as cert_processing

from sec_certs.certificate import Certificate
from sec_certs.serialization import CustomJSONDecoder, CustomJSONEncoder

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
        if not (new_path := Path(new_dir)).exists():
            raise FileNotFoundError('Root directory for Dataset does not exist')
        self._root_dir = new_path

    @property
    def json_path(self) -> Path:
        return self.root_dir / (self.name + '.json')

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
                                                      constants.N_THREADS,
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
                    # TODO: Delete



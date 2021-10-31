import logging
from pathlib import Path
import copy
import json

from abc import ABC, abstractmethod
from typing import Union, TypeVar, Type

from sec_certs.serialization import CustomJSONDecoder, CustomJSONEncoder, ComplexSerializableType
from sec_certs.dataset.cpe import CPEDataset

logger = logging.getLogger(__name__)


class Certificate(ABC, ComplexSerializableType):
    T = TypeVar('T', bound='Certificate')

    def __init__(self, *args, **kwargs):
        pass

    def __repr__(self) -> str:
        return str(self.to_dict())

    def __str__(self) -> str:
        return 'Not implemented'

    @property
    @abstractmethod
    def dgst(self):
        raise NotImplementedError('Not meant to be implemented')

    @property
    @abstractmethod
    def label_studio_title(self):
        raise NotImplementedError('Not meant to be implemented')

    def __eq__(self, other: 'Certificate') -> bool:
        return self.dgst == other.dgst

    def to_dict(self):
        return {**{'dgst': self.dgst}, **{key: val for key, val in copy.deepcopy(self.__dict__).items() if key in self.serialized_attributes}}

    @classmethod
    def from_dict(cls: Type[T], dct: dict) -> T:
        dct.pop('dgst')
        return cls(*(tuple(dct.values())))

    def to_json(self, output_path: Union[Path, str]):
        with Path(output_path).open('w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)

    @classmethod
    def from_json(cls, input_path: Union[Path, str]):
        with Path(input_path).open('r') as handle:
            return json.load(handle, csl=CustomJSONDecoder)

    @abstractmethod
    def compute_heuristics_version(self):
        raise NotImplementedError('Not meant to be implemented')

    @abstractmethod
    def compute_heuristics_cpe_vendors(self, cpe_dataset: CPEDataset):
        raise NotImplementedError('Not meant to be implemented')

    @abstractmethod
    def compute_heuristics_cpe_match(self, cpe_dataset: CPEDataset):
        raise NotImplementedError('Not meant to be implemented')

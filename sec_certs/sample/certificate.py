import copy
import itertools
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Generic, Type, TypeVar, Union

from sec_certs.dataset.cve import CVEDataset
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONDecoder

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="Certificate")


class Certificate(Generic[T], ABC, ComplexSerializableType):
    heuristics: Any

    def __init__(self, *args, **kwargs):
        pass

    def __repr__(self) -> str:
        return str(self.to_dict())

    def __str__(self) -> str:
        return "Not implemented"

    @property
    @abstractmethod
    def dgst(self):
        raise NotImplementedError("Not meant to be implemented")

    @property
    @abstractmethod
    def label_studio_title(self):
        raise NotImplementedError("Not meant to be implemented")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Certificate):
            return False
        return self.dgst == other.dgst

    def to_dict(self) -> Dict[str, Any]:
        return {
            **{"dgst": self.dgst},
            **{key: val for key, val in copy.deepcopy(self.__dict__).items() if key in self.serialized_attributes},
        }

    @classmethod
    def from_dict(cls: Type[T], dct: dict) -> T:
        dct.pop("dgst")
        return cls(**dct)

    @classmethod
    def from_json(cls: Type[T], input_path: Union[Path, str]) -> T:
        with Path(input_path).open("r") as handle:
            return json.load(handle, cls=CustomJSONDecoder)

    @abstractmethod
    def compute_heuristics_version(self) -> None:
        raise NotImplementedError("Not meant to be implemented")

    @abstractmethod
    def compute_heuristics_cpe_match(self, cpe_classifier: CPEClassifier) -> None:
        raise NotImplementedError("Not meant to be implemented")

    def compute_heuristics_related_cves(self, cve_dataset: CVEDataset) -> None:
        if self.heuristics.cpe_matches:
            related_cves = [cve_dataset.get_cve_ids_for_cpe_uri(x) for x in self.heuristics.cpe_matches]
            related_cves = list(filter(lambda x: x is not None, related_cves))
            if related_cves:
                self.heuristics.related_cves = set(
                    itertools.chain.from_iterable([x for x in related_cves if x is not None])
                )
        else:
            self.heuristics.related_cves = None

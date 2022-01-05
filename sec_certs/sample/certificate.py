import copy
import itertools
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional, Type, TypeVar, Union

from sec_certs.dataset.cve import CVEDataset
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONDecoder, CustomJSONEncoder

logger = logging.getLogger(__name__)


class Certificate(ABC, ComplexSerializableType):
    T = TypeVar("T", bound="Certificate")

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
            return NotImplemented
        return self.dgst == other.dgst

    def to_dict(self):
        return {
            **{"dgst": self.dgst},
            **{key: val for key, val in copy.deepcopy(self.__dict__).items() if key in self.serialized_attributes},
        }

    @classmethod
    def from_dict(cls: Type[T], dct: dict) -> T:
        dct.pop("dgst")
        return cls(**dct)

    def to_json(self, output_path: Optional[Union[str, Path]] = None):
        if output_path is None:
            raise RuntimeError(
                f"You tried to serialize an object ({type(self)}) that does not have implicit json path. Please provide json_path."
            )
        with Path(output_path).open("w") as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)

    @classmethod
    def from_json(cls, input_path: Union[Path, str]):
        with Path(input_path).open("r") as handle:
            return json.load(handle, cls=CustomJSONDecoder)

    @abstractmethod
    def compute_heuristics_version(self):
        raise NotImplementedError("Not meant to be implemented")

    @abstractmethod
    def compute_heuristics_cpe_vendors(self, cpe_classifier: CPEClassifier):
        raise NotImplementedError("Not meant to be implemented")

    @abstractmethod
    def compute_heuristics_cpe_match(self, cpe_classifier: CPEClassifier):
        raise NotImplementedError("Not meant to be implemented")

    def compute_heuristics_related_cves(self, cve_dataset: CVEDataset):
        if self.heuristics.cpe_matches:
            related_cves = [cve_dataset.get_cve_ids_for_cpe_uri(x) for x in self.heuristics.cpe_matches]
            related_cves = list(filter(lambda x: x is not None, related_cves))
            if related_cves:
                self.heuristics.related_cves = set(
                    itertools.chain.from_iterable([x for x in related_cves if x is not None])
                )
        else:
            self.heuristics.related_cves = None

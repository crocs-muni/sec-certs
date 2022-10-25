import copy
import json
import logging
from abc import ABC, abstractmethod
from collections import ChainMap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generic, Optional, Set, Type, TypeVar, Union

import sec_certs.utils.extract
from sec_certs.cert_rules import PANDAS_KEYWORDS_CATEGORIES
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONDecoder

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="Certificate")
H = TypeVar("H", bound="Heuristics")


@dataclass
class References(ComplexSerializableType):
    directly_referenced_by: Optional[Set[str]] = field(default=None)
    indirectly_referenced_by: Optional[Set[str]] = field(default=None)
    directly_referencing: Optional[Set[str]] = field(default=None)
    indirectly_referencing: Optional[Set[str]] = field(default=None)


class Heuristics:
    cpe_matches: Optional[Set[str]]
    related_cves: Optional[Set[str]]


class Certificate(Generic[T, H], ABC, ComplexSerializableType):
    manufacturer: Optional[str]
    name: Optional[str]
    heuristics: H

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

    @property
    def keywords_df_data(self) -> Dict[str, float]:
        """
        Returns dictionary of keywords divided by categories, used to generate dataframe.
        """
        return dict(
            ChainMap(
                *[
                    sec_certs.utils.extract.get_sums_for_rules_subset(self._get_keyword_data_input(), cat)
                    for cat in PANDAS_KEYWORDS_CATEGORIES
                ]
            )
        )

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
    def from_dict(cls: Type[T], dct: Dict) -> T:
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
    def _get_keyword_data_input(self) -> Optional[Dict]:
        raise NotImplementedError("Not meant to be implemented")

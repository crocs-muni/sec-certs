from __future__ import annotations

import copy
import logging
from abc import ABC, abstractmethod
from collections import ChainMap
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import sec_certs.utils.extract
from sec_certs.cert_rules import PANDAS_KEYWORDS_CATEGORIES
from sec_certs.serialization.json import ComplexSerializableType

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="Certificate")
H = TypeVar("H", bound="Heuristics")
P = TypeVar("P", bound="PdfData")


@dataclass
class References(ComplexSerializableType):
    directly_referenced_by: set[str] | None = field(default=None)
    indirectly_referenced_by: set[str] | None = field(default=None)
    directly_referencing: set[str] | None = field(default=None)
    indirectly_referencing: set[str] | None = field(default=None)

    def __bool__(self):
        return any(getattr(self, x) for x in vars(self))


class Heuristics:
    cpe_matches: set[str] | None
    related_cves: set[str] | None


class PdfData:
    def get_keywords_df_data(self, var: str) -> dict[str, float]:
        data_dct = getattr(self, var)
        return dict(
            ChainMap(
                *[
                    sec_certs.utils.extract.get_sums_for_rules_subset(data_dct, cat)
                    for cat in PANDAS_KEYWORDS_CATEGORIES
                ]
            )
        )


class Certificate(Generic[T, H, P], ABC, ComplexSerializableType):
    manufacturer: str | None
    name: str | None
    pdf_data: P
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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Certificate):
            return False
        return self.dgst == other.dgst

    def to_dict(self) -> dict[str, Any]:
        return {
            **{"dgst": self.dgst},
            **{key: val for key, val in copy.deepcopy(self.__dict__).items() if key in self.serialized_attributes},
        }

    @classmethod
    def from_dict(cls: type[T], dct: dict) -> T:
        dct.pop("dgst")
        return cls(**dct)

    @abstractmethod
    def compute_heuristics_version(self) -> None:
        raise NotImplementedError("Not meant to be implemented")

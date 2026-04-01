from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, ClassVar

from sec_certs import constants
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType


@dataclass(eq=True, frozen=True)
class FIPSAlgorithm(PandasSerializableType, ComplexSerializableType):
    """
    Data structure for algorithm of `FIPSCertificate`
    """

    alg_number: str
    algorithm_type: str
    vendor: str
    implementation_name: str
    validation_date: date
    product_id: str | None = None
    description: str | None = None
    version: str | None = None
    product_type: str | None = None
    capability_environment_pairs: tuple[tuple[str, str | None], ...] | None = None

    pandas_columns: ClassVar[list[str]] = [
        "dgst",
        "alg_number",
        "algorithm_type",
        "vendor",
        "implementation_name",
        "validation_date",
        "product_id",
        "description",
        "version",
        "product_type",
        "capability_environment_pairs",
    ]

    @property
    def pandas_tuple(self) -> tuple:
        return (
            self.dgst,
            self.alg_number,
            self.algorithm_type,
            self.vendor,
            self.implementation_name,
            self.validation_date,
            self.product_id,
            self.description,
            self.version,
            self.product_type,
            self.capability_environment_pairs,
        )

    @property
    def dgst(self) -> str:
        return f"{self.algorithm_type} {self.alg_number}"

    @property
    def page_url(self) -> str:
        return constants.FIPS_ALG_URL.format(self.algorithm_type, self.alg_number)

    @classmethod
    def from_dict(cls, dct: dict[str, Any]) -> FIPSAlgorithm:
        new_dct = dct.copy()
        if isinstance(new_dct.get("capability_environment_pairs"), list):
            new_dct["capability_environment_pairs"] = tuple(tuple(x) for x in new_dct["capability_environment_pairs"])
        if isinstance(new_dct.get("validation_date"), str):
            new_dct["validation_date"] = cls.parse_date(new_dct["validation_date"])
        return cls(**new_dct)

    @staticmethod
    def parse_date(date_str: str) -> date:
        try:
            return date.fromisoformat(date_str)
        except ValueError:
            return datetime.strptime(date_str, "%m/%d/%Y").date()

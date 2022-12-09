from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import ClassVar

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

    pandas_columns: ClassVar[list[str]] = [
        "dgst",
        "alg_number",
        "algorithm_type",
        "vendor",
        "implementation_name",
        "validation_date",
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
        )

    @property
    def dgst(self) -> str:
        return f"{self.algorithm_type}{self.alg_number}"

    @property
    def page_url(self) -> str:
        return constants.FIPS_ALG_URL.format(self.algorithm_type, self.alg_number)

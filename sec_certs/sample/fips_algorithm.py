from dataclasses import dataclass, field
from functools import total_ordering
from typing import Optional

from sec_certs import constants
from sec_certs.serialization.json import ComplexSerializableType


@dataclass(eq=True, frozen=True)
@total_ordering
class FIPSAlgorithm(ComplexSerializableType):
    """
    Data structure for algorithm of `FIPSCertificate`
    """

    cert_id: str
    algorithm_type: Optional[str] = field(default=None)
    vendor: Optional[str] = field(default=None)
    implementation: Optional[str] = field(default=None)
    date: Optional[str] = field(default=None)

    @property
    def dgst(self) -> str:
        return f"{self.algorithm_type}{self.cert_id}"

    @property
    def page_url(self) -> str:
        return constants.FIPS_ALG_URL.format(self.algorithm_type, self.cert_id)

    def _compare_tuple(self):
        # This is necessary to not have errors with comparing str with None.
        return (
            self.cert_id,
            self.algorithm_type if self.algorithm_type else "",
            self.vendor if self.vendor else "",
            self.implementation if self.implementation else "",
            self.date if self.date else "",
        )

    def __lt__(self, other):
        if not isinstance(other, FIPSAlgorithm):
            raise ValueError("Cannot compare.")
        return self._compare_tuple() < other._compare_tuple()

    def __repr__(self) -> str:
        return f"FIPSAlgorithm({self.dgst})"

    def __str__(self) -> str:
        return f"{self.algorithm_type} algorithm {self.cert_id} created by {self.vendor}"

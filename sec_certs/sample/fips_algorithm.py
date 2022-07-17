from dataclasses import dataclass, field
from typing import Optional

from sec_certs import constants
from sec_certs.serialization.json import ComplexSerializableType


@dataclass(eq=True, order=True, frozen=True)
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
        return f"{self.algorithm_type}#{self.cert_id}"

    @property
    def page_url(self) -> str:
        return constants.FIPS_ALG_URL.format(self.algorithm_type, self.cert_id)

    def __repr__(self) -> str:
        return f"FIPSAlgorithm({self.dgst})"

    def __str__(self) -> str:
        return f"{self.algorithm_type} algorithm # {self.cert_id} created by {self.vendor}"

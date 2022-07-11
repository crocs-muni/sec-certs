from dataclasses import dataclass

from sec_certs.serialization.json import ComplexSerializableType


@dataclass(eq=True)
class FIPSAlgorithm(ComplexSerializableType):
    """
    Data structure for algorithm of `FIPSCertificate`
    """

    cert_id: str
    vendor: str
    implementation: str
    algorithm_type: str
    date: str

    @property
    def dgst(self) -> str:
        # certs in dataset are in format { id: [FIPSAlgorithm] }, there is only one type of algorithm
        # for each id
        # TODO: This is probably not a good digest.
        return self.algorithm_type

    def __repr__(self) -> str:
        return self.algorithm_type + " algorithm #" + self.cert_id + " created by " + self.vendor

    def __str__(self) -> str:
        return str(self.algorithm_type + " algorithm #" + self.cert_id + " created by " + self.vendor)

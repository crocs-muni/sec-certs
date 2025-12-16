from dataclasses import dataclass

"""
Table 8: Approved Algorithms
"""


@dataclass
class ApprovedAlgo:
    algorithm: str
    cavpCertName: str
    properties: str
    reference: str


"""
Table 9: Vendor Affirmed Algorithms
and
Table 10: Non-Approved, Allowed Algorithms
"""


@dataclass
class Algo:
    name: str
    algoPropList: str
    implName: str
    reference: str


"""
Table 11: Non-Approved, Allowed Algorithms with No Security Claimed
"""


@dataclass
class NonApprovedAllowedNSC:
    name: str
    caveat: str
    use: str


"""
Table 12: Non-Approved, Not Allowed Algorithms
"""


@dataclass
class NonApprovedNonAllowedAlgo:
    name: str
    use: str

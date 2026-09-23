from dataclasses import dataclass

from ..table import column

"""
Table 8: Approved Algorithms
"""


@dataclass(kw_only=True)
class ApprovedAlgo:
    algorithm: str = column("Algorithm")
    cavpCertName: str = column("CAVP Cert")
    properties: str = column("Properties")
    reference: str = column("Reference")


"""
Table 9: Vendor Affirmed Algorithms
and
Table 10: Non-Approved, Allowed Algorithms
"""


@dataclass(kw_only=True)
class Algo:
    name: str = column("Name")
    algoPropList: str = column("Properties")
    implName: str = column("Implementation")
    reference: str = column("Reference")


"""
Table 11: Non-Approved, Allowed Algorithms with No Security Claimed
"""


@dataclass(kw_only=True)
class NonApprovedAllowedNSC:
    name: str = column("Name")
    caveat: str = column("Caveat")
    use: str = column("Use and Function")


"""
Table 12: Non-Approved, Not Allowed Algorithms
"""


@dataclass(kw_only=True)
class NonApprovedNonAllowedAlgo:
    name: str = column("Name")
    use: str = column("Use and Function")

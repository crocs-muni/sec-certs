from dataclasses import dataclass

# Tables 5,6,7,8,9
# AlgoProp is actually a Key:Value pair, but for simplicity it is represented as a string


@dataclass
class ApprovedAlgo:
    algorithm: str
    cavpCertName: str
    properties: str
    reference: str


# Used for tables
@dataclass
class Algo:
    name: str
    algoPropList: str
    implName: str
    reference: str


@dataclass
class NonApprovedAllowedNSC:
    name: str
    caveat: str
    use: str


@dataclass
class NonApprovedNonAllowedAlgo:
    name: str
    use: str

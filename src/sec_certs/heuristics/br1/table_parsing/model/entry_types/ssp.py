from dataclasses import dataclass

"""
Table 27: Storage Areas
"""


@dataclass
class StorageArea:
    name: str
    description: str
    persistance: str


"""
Table 28: SSP Input-Output
"""


@dataclass
class SspIOMethod:
    name: str
    source: str
    dest: str
    format: str
    distribution: str
    entry: str
    sfiAlgo: str = ""


"""
Table 29: SSP Zeroization Methods
"""


@dataclass
class SspZeroization:
    method: str
    description: str
    rationale: str
    operatorId: str


"""
Table 30: SSP Information First
Table 31: SSP Information Second
This table consists of 2 parts
"""


@dataclass
class Ssp:
    name: str
    description: str
    size: str
    strength: str
    type: str
    generatedBy: str = ""
    usedBy: str = ""

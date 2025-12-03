from dataclasses import dataclass


# Tables 27-31
@dataclass
class StorageArea:
    name: str
    description: str
    persistance: str


@dataclass
class SspIOMethod:
    name: str
    source: str
    dest: str
    format: str
    distribution: str
    entry: str
    sfiAlgo: str = ""


@dataclass
class SspZeroization:
    method: str
    description: str
    rationale: str
    operatorId: str


# This table consists of a number of optional columns, total 14 columns
@dataclass
class Ssp:
    name: str
    description: str
    size: str
    strength: str
    type: str
    generatedBy: str = ""
    usedBy: str = ""

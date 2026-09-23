from dataclasses import dataclass

from ..table import column

"""
Table 27: Storage Areas
"""


@dataclass(kw_only=True)
class StorageArea:
    name: str = column("Storage Area Name")
    description: str = column("Description")
    persistance: str = column("Persistence Type")


"""
Table 28: SSP Input-Output
"""


@dataclass(kw_only=True)
class SspIOMethod:
    name: str = column("Name")
    source: str = column("From")
    dest: str = column("To")
    format: str = column("Format Type")
    distribution: str = column("Distribution Type")
    entry: str = column("Entry Type")
    sfiAlgo: str = column("SFI or Algorithm")


"""
Table 29: SSP Zeroization Methods
"""


@dataclass(kw_only=True)
class SspZeroization:
    method: str = column("Zeroization Method")
    description: str = column("Description")
    rationale: str = column("Rationale")
    operatorId: str = column("Operator Initiation")


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

from dataclasses import dataclass

"""
Table 19: Ports and Interfaces
"""


@dataclass
class PortInterface:
    physicalPort: str
    logicalInterface: str
    data: str

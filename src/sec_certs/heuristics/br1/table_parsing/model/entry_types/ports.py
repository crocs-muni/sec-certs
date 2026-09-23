from dataclasses import dataclass

from ..table import column

"""
Table 19: Ports and Interfaces
"""


@dataclass(kw_only=True)
class PortInterface:
    physicalPort: str = column("Physical Port")
    logicalInterface: str = column("Logical Interface(s)")
    data: str = column("Data That Passes")

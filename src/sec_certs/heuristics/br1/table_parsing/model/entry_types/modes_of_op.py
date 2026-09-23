from dataclasses import dataclass

from ..table import column

"""
Table 7: Modes List and Description
"""


@dataclass(kw_only=True)
class ModeOfOp:
    name: str = column("Mode Name")
    description: str = column("Description")
    type: str = column("Type")
    statusIndicator: str = column("Status Indicator")

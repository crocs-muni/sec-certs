from dataclasses import dataclass

"""
Table 7: Modes List and Description
"""


@dataclass
class ModeOfOp:
    name: str
    description: str
    type: str
    statusIndicator: str = ""

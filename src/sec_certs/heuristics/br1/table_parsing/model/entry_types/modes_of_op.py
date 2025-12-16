from dataclasses import dataclass


# Table 7
@dataclass
class ModeOfOp:
    name: str
    description: str
    type: str
    statusIndicator: str = ""

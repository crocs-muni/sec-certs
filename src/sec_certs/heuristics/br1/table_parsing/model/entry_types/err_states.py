from dataclasses import dataclass

"""
Table 36: Error States
"""


@dataclass
class ErrorState:
    name: str
    description: str
    conditions: str
    recoveryMethod: str
    indicator: str

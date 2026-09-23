from dataclasses import dataclass

from ..table import column

"""
Table 36: Error States
"""


@dataclass(kw_only=True)
class ErrorState:
    name: str = column("Name")
    description: str = column("Description")
    conditions: str = column("Conditions")
    recoveryMethod: str = column("Recovery Method")
    indicator: str = column("Indicator")

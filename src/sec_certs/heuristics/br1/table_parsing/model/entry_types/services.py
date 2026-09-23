from dataclasses import dataclass

from ..table import column

"""
Table 22: Approved Services
"""


@dataclass(kw_only=True)
class ApprovedService:
    name: str = column("Name")
    description: str = column("Description")
    indicator: str = column("Indicator")
    inputs: str = column("Inputs")
    outputs: str = column("Outputs")
    secFunImpl: str = column("Security Functions")
    rolesSspAccess: str = column("SSP Access")


"""
Table 23: Non-Approved Services
"""


@dataclass(kw_only=True)
class NonApprovedService:
    name: str = column("Name")
    description: str = column("Description")
    alg_accessed: str = column("Algorithms")
    role: str = column("Role")

from dataclasses import dataclass

"""
Table 22: Approved Services
"""


@dataclass
class ApprovedService:
    name: str
    description: str
    indicator: str
    inputs: str
    outputs: str
    secFunImpl: str
    roles: str
    rolesSspAccess: str = ""


"""
Table 23: Non-Approved Services
"""


class NonApprovedService:
    name: str
    description: str
    alg_accessed: str
    role: str

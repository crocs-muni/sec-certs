from dataclasses import dataclass

# Tables 22-23, nested tables, for now will be skipped


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


class NonApprovedService:
    name: str
    description: str
    alg_accessed: str
    role: str

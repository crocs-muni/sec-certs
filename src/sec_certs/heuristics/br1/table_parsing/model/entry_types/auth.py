from dataclasses import dataclass

"""
Table 20: Authentication Methods
"""


@dataclass
class AuthMethod:
    name: str
    description: str
    mechanism: str
    strength: str
    perMinute: str = ""


"""
Table 21: Roles
"""


@dataclass
class Role:
    name: str
    type: str
    operatorType: str
    authMethodList: str

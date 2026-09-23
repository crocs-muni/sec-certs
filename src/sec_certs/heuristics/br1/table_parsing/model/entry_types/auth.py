from dataclasses import dataclass

from ..table import column

"""
Table 20: Authentication Methods
"""


@dataclass(kw_only=True)
class AuthMethod:
    name: str = column("Method Name")
    description: str = column("Description")
    mechanism: str = column("Security Mechanism")
    strength: str = column("Strength Each Attempt")
    perMinute: str = column("Strength per Minute")


"""
Table 21: Roles
"""


@dataclass(kw_only=True)
class Role:
    name: str = column("Name")
    type: str = column("Type")
    operatorType: str = column("Operator Type")
    authMethodList: str = column("Authentication Methods")

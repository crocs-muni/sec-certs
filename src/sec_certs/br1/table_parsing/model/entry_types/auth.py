from dataclasses import dataclass


# Tables 20, 21
@dataclass
class AuthMethod:
    name: str
    description: str
    mechanism: str
    strength: str
    perMinute: str = ""


@dataclass
class Role:
    name: str
    type: str
    operatorType: str
    authMethodList: str

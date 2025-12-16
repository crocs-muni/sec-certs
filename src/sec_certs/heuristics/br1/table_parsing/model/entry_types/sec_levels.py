from dataclasses import dataclass


# Table 1
@dataclass
class SecurityLevel:
    section: str
    title: str
    level: str

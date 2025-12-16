from dataclasses import dataclass

"""
Table 1: Security Levels
"""


@dataclass
class SecurityLevel:
    section: str
    title: str
    level: str

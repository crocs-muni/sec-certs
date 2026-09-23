from dataclasses import dataclass

from ..table import column

"""
Table 1: Security Levels
"""


@dataclass(kw_only=True)
class SecurityLevel:
    section: str = column("Section")
    title: str = column("Title")
    level: str = column("Security Level")

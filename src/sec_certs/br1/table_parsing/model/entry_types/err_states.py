from dataclasses import dataclass

# Table 36


@dataclass
class ErrorState:
    name: str
    description: str
    conditions: str
    recoveryMethod: str
    indicator: str

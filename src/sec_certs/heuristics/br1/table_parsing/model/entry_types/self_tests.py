from dataclasses import dataclass

# Tables 32 - 35

"""
Table 32: Pre-Operational Self-Tests
"""


@dataclass
class SelfTest:
    algorithmOrTest: str
    testProps: str
    testMethod: str
    type: str
    indicator: str
    details: str


"""
Table 33: Conditional Self-Tests
"""


@dataclass
class CondSelfTest:
    algorithmOrTest: str
    testProps: str
    testMethod: str
    type: str
    indicator: str
    details: str
    condition: str
    coverage: str  # optional
    coverageNotes: str  # optional


"""
Table 34: Pre-Operational Periodic Information
"""


@dataclass
class PeriodicSelfTest:
    algorithmOrTest: str
    testMethod: str
    type: str
    period: str
    periodicMethod: str


"""
Table 35: Conditional Periodic Information
"""


@dataclass
class PeriodicCondSelfTest:
    algorithmOrTest: str
    testMethod: str
    type: str
    period: str
    periodicMethod: str

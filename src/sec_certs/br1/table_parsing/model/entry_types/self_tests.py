from dataclasses import dataclass

# Tables 32 - 35


@dataclass
class SelfTest:
    algorithmOrTest: str
    testProps: str
    testMethod: str
    type: str
    indicator: str
    details: str


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


@dataclass
class PeriodicSelfTest:
    algorithmOrTest: str
    testMethod: str
    type: str
    period: str
    periodicMethod: str


@dataclass
class PeriodicCondSelfTest:
    algorithmOrTest: str
    testMethod: str
    type: str
    period: str
    periodicMethod: str

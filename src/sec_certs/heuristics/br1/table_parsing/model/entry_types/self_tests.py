from dataclasses import dataclass

from ..table import column

# Tables 32 - 33

"""
Table 32: Pre-Operational Self-Tests
"""


@dataclass(kw_only=True)
class SelfTest:
    algorithmOrTest: str = column("Algorithm or Test")
    testProps: str = column("Test Properties")
    testMethod: str = column("Test Method")
    type: str = column("Test Type")
    indicator: str = column("Indicator")
    details: str = column("Details")


"""
Table 33: Conditional Self-Tests
"""


@dataclass(kw_only=True)
class CondSelfTest:
    algorithmOrTest: str = column("Algorithm or Test")
    testProps: str = column("Test Properties")
    testMethod: str = column("Test Method")
    type: str = column("Test Type")
    indicator: str = column("Indicator")
    details: str = column("Details")
    condition: str = column("Conditions")

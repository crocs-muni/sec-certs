from dataclasses import dataclass

from ..table import column

"""
Table 24: Mechanisms and Actions Required
"""


@dataclass(kw_only=True)
class PhSecMechanism:
    mechanism: str = column("Mechanism")
    inspectFreq: str = column("Inspection Frequency")
    inspectGuidance: str = column("Inspection Guidance")

from dataclasses import dataclass

"""
Table 24: Mechanisms and Actions Required
"""


@dataclass
class PhSecMechanism:
    mechanism: str
    inspectFreq: str
    type: str
    inspectGuidance: str

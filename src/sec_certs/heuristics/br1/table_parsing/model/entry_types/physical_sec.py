from dataclasses import dataclass

# Tables 24-26
# Table 25,26 are cross tabulations - for now will be skipped


@dataclass
class PhSecMechanism:
    mechanism: str
    inspectFreq: str
    type: str
    inspectGuidance: str

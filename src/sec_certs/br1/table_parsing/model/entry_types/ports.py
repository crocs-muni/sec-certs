from dataclasses import dataclass


# Table 19
@dataclass
class PortInterface:
    physicalPort: str
    logicalInterface: str
    data: str

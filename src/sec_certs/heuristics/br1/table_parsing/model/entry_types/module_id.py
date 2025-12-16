from dataclasses import dataclass

"""
Table 2: Tested Module Identification – Hardware
"""


@dataclass
class TestedHw:
    modelPartNum: str
    hwVersion: str
    processors: str
    features: str = ""


"""
Table 3: Tested Module Identification – Software/Firmware/Hybrid (Executable Code Sets)
"""


@dataclass
class TestedSwFwHy:
    packageFileName: str
    swFwVersion: str
    features: str  # optional
    integrityTest: str


"""
Table 4: Tested Module Identification – Hybrid Disjoint Hardware
"""


@dataclass
class TestedHyHw:
    modelPartNum: str
    hwVersion: str
    fwVersion: str = ""
    processors: str = ""
    features: str = ""


"""
Table 5: Tested Operational Environments - Software, Firmware, Hybrid
"""


@dataclass
class TestedOpEnvSwFwHy:
    operatingSystem: str
    hardwarePlatform: str
    processors: str
    paa_pai: str
    hypervisorHostOs: str  # optional
    version: str


"""
Table 6: Vendor Affirmed Operational Environments - Software, Firmware, Hybrid
"""


@dataclass
class OpEnvSwFwHyVA:
    operatingSystem: str
    hardwarePlatform: str

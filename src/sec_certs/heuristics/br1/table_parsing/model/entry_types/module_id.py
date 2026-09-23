from dataclasses import dataclass

from ..table import column

"""
Table 2: Tested Module Identification – Hardware
"""


@dataclass(kw_only=True)
class TestedHw:
    modelPartNum: str = column("Model and/or Part Number")
    hwVersion: str = column("Hardware Version")
    fwVersion: str = column("Firmware Version")
    processors: str = column("Processors")
    features: str = column("Features")


"""
Table 3: Tested Module Identification – Software/Firmware/Hybrid (Executable Code Sets)
"""


@dataclass(kw_only=True)
class TestedSwFwHy:
    packageFileName: str = column("Package or File Name")
    swFwVersion: str = column("Software/Firmware Version")
    features: str = column("Features")
    integrityTest: str = column("Integrity Test")


"""
Table 4: Tested Module Identification – Hybrid Disjoint Hardware
"""


@dataclass(kw_only=True)
class TestedHyHw:
    modelPartNum: str = column("Model and/or Part Number")
    hwVersion: str = column("Hardware Version")
    fwVersion: str = column("Firmware Version")
    processors: str = column("Processors")
    features: str = column("Features")


"""
Table 5: Tested Operational Environments - Software, Firmware, Hybrid
"""


@dataclass(kw_only=True)
class TestedOpEnvSwFwHy:
    operatingSystem: str = column("Operating System")
    hardwarePlatform: str = column("Hardware Platform")
    processors: str = column("Processors")
    paa_pai: str = column("PAA/PAI")
    hypervisorHostOs: str = column("Hypervisor or Host OS")
    version: str = column("Version(s)")


"""
Table 6: Vendor Affirmed Operational Environments - Software, Firmware, Hybrid
"""


@dataclass(kw_only=True)
class OpEnvSwFwHyVA:
    operatingSystem: str = column("Operating System")
    hardwarePlatform: str = column("Hardware Platform")

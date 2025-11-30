from dataclasses import dataclass, field

from .entry_types.algorithms import (
    Algo,
    ApprovedAlgo,
    NonApprovedAllowedNSC,
    NonApprovedNonAllowedAlgo,
)
from .entry_types.auth import AuthMethod, Role
from .entry_types.err_states import ErrorState
from .entry_types.modes_of_op import ModeOfOp
from .entry_types.module_id import (
    OpEnvSwFwHyVA,
    TestedHw,
    TestedHyHw,
    TestedOpEnvSwFwHy,
    TestedSwFwHy,
)
from .entry_types.physical_sec import PhSecMechanism
from .entry_types.ports import PortInterface
from .entry_types.sec_levels import SecurityLevel
from .entry_types.self_tests import CondSelfTest, SelfTest
from .entry_types.services import ApprovedService, NonApprovedService
from .entry_types.ssp import SspIOMethod, SspZeroization, StorageArea
from .table import BR1Table


@dataclass
class BR1TablesClass:
    # Security Levels
    security_levels: BR1Table[SecurityLevel] = field(default_factory=lambda: BR1Table("", 1, 2, SecurityLevel))

    # Tested Module Identification
    tested_module_id_hw: BR1Table[TestedHw] = field(
        default_factory=lambda: BR1Table("Tested Module Identification - Hardware", 2, 2, TestedHw)
    )
    tested_module_id_sw_fw_hy: BR1Table[TestedSwFwHy] = field(
        default_factory=lambda: BR1Table(
            "Tested Module Identification – Software, Firmware, Hybrid",
            2,
            2,
            TestedSwFwHy,
        )
    )
    tested_module_id_hw_hy: BR1Table[TestedHyHw] = field(
        default_factory=lambda: BR1Table("Tested Module Identification – Hybrid Disjoint Hardware", 2, 2, TestedHyHw)
    )
    tested_op_env_sw_fw_hy: BR1Table[TestedOpEnvSwFwHy] = field(
        default_factory=lambda: BR1Table(
            "Tested Operational Environments - Software, Firmware, Hybrid",
            2,
            2,
            TestedOpEnvSwFwHy,
        )
    )
    vendor_affirmed_op_env_sw_fw_hy: BR1Table[OpEnvSwFwHyVA] = field(
        default_factory=lambda: BR1Table(
            "Vendor-Affirmed Operational Environments - Software, Firmware, Hybrid",
            2,
            2,
            OpEnvSwFwHyVA,
        )
    )

    # Modes of Operation
    modes_of_operation: BR1Table[ModeOfOp] = field(default_factory=lambda: BR1Table("", 2, 4, ModeOfOp))

    # Algorithms
    approved_algorithms: BR1Table[ApprovedAlgo] = field(
        default_factory=lambda: BR1Table("Approved Algorithms", 2, 5, ApprovedAlgo)
    )
    vendor_affirmed_algos: BR1Table[Algo] = field(
        default_factory=lambda: BR1Table("Vendor-Affirmed Algorithms", 2, 5, Algo)
    )
    non_approved_allowed_algos: BR1Table[Algo] = field(
        default_factory=lambda: BR1Table("Non-Approved, Allowed Algorithms", 2, 5, Algo)
    )
    non_approved_allowed_NSC: BR1Table[NonApprovedAllowedNSC] = field(
        default_factory=lambda: BR1Table(
            "Non-Approved, Allowed Algorithms with No Security Claimed",
            2,
            5,
            NonApprovedAllowedNSC,
        )
    )
    non_approved_not_allowed: BR1Table[NonApprovedNonAllowedAlgo] = field(
        default_factory=lambda: BR1Table("Non-Approved, Not Allowed Algorithms", 2, 5, NonApprovedNonAllowedAlgo)
    )

    # Ports and Interfaces
    ports_interfaces: BR1Table[PortInterface] = field(default_factory=lambda: BR1Table("", 3, 1, PortInterface))

    # Authentication Methods
    authentication_methods: BR1Table[AuthMethod] = field(default_factory=lambda: BR1Table("", 4, 1, AuthMethod))
    roles: BR1Table[Role] = field(default_factory=lambda: BR1Table("", 4, 2, Role))

    # Services
    approved_services: BR1Table[ApprovedService] = field(default_factory=lambda: BR1Table("", 4, 3, ApprovedService))
    non_approved_services: BR1Table[NonApprovedService] = field(
        default_factory=lambda: BR1Table("", 4, 4, NonApprovedService)
    )

    # Physical Security
    mechanisms_actions: BR1Table[PhSecMechanism] = field(default_factory=lambda: BR1Table("", 7, 1, PhSecMechanism))

    # SSPs
    storage_areas: BR1Table[StorageArea] = field(default_factory=lambda: BR1Table("", 9, 1, StorageArea))

    ssp_io_methods: BR1Table[SspIOMethod] = field(default_factory=lambda: BR1Table("", 9, 2, SspIOMethod))

    ssp_zeroization_methods: BR1Table[SspZeroization] = field(
        default_factory=lambda: BR1Table("", 9, 3, SspZeroization)
    )
    # Self Tests
    self_tests: BR1Table[SelfTest] = field(default_factory=lambda: BR1Table("", 10, 1, SelfTest))
    cond_self_tests: BR1Table[CondSelfTest] = field(default_factory=lambda: BR1Table("", 10, 2, CondSelfTest))

    # Error States
    error_states: BR1Table[ErrorState] = field(default_factory=lambda: BR1Table("", 10, 4, ErrorState))

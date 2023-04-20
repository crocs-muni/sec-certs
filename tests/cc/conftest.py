from datetime import date

import pytest

from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.protection_profile import ProtectionProfile


@pytest.fixture(scope="module")
def cert_one() -> CCCertificate:
    return CCCertificate(
        "active",
        "Access Control Devices and Systems",
        "NetIQ Identity Manager 4.7",
        "NetIQ Corporation",
        "SE",
        {"ALC_FLR.2", "EAL3+"},
        date(2020, 6, 15),
        date(2025, 6, 15),
        "https://www.commoncriteriaportal.org/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf",
        "https://www.commoncriteriaportal.org/files/epfiles/ST%20-%20NetIQ%20Identity%20Manager%204.7.pdf",
        "https://www.commoncriteriaportal.org/files/epfiles/Certifikat%20CCRA%20-%20NetIQ%20Identity%20Manager%204.7_signed.pdf",
        "https://www.netiq.com/",
        set(),
        set(),
        None,
        None,
        None,
    )


@pytest.fixture(scope="module")
def cert_two() -> CCCertificate:
    pp = ProtectionProfile("sample_pp", None, pp_link="https://sample.pp")
    update = CCCertificate.MaintenanceReport(
        date(1900, 1, 1), "Sample maintenance", "https://maintenance.up", "https://maintenance.up"
    )

    return CCCertificate(
        "archived",
        "Sample category",
        "Sample certificate name",
        "Sample manufacturer",
        "Sample scheme",
        {"Sample security level"},
        date(1900, 1, 2),
        date(1900, 1, 3),
        "https://path.to/report/link",
        "https://path.to/st/link",
        "https://path.to/cert/link",
        "https://path.to/manufacturer/web",
        {pp},
        {update},
        None,
        None,
        None,
    )

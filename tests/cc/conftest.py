from collections.abc import Generator
from datetime import date
from importlib import resources
from pathlib import Path

import pytest
import tests.data.cc.analysis
import tests.data.cc.dataset
import tests.data.protection_profiles

from sec_certs.dataset.cc import CCDataset
from sec_certs.dataset.protection_profile import ProtectionProfileDataset
from sec_certs.sample.cc import CCCertificate


@pytest.fixture(scope="module")
def pp_data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.protection_profiles, "") as path:
        yield path


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.cc.dataset, "") as path:
        yield path


@pytest.fixture(scope="module")
def analysis_data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.cc.analysis, "") as path:
        yield path


@pytest.fixture
def toy_dataset() -> CCDataset:
    with resources.path(tests.data.cc.dataset, "toy_dataset.json") as path:
        return CCDataset.from_json(path)


@pytest.fixture
def toy_pp_dataset() -> ProtectionProfileDataset:
    with resources.path(tests.data.protection_profiles, "dataset.json") as path:
        return ProtectionProfileDataset.from_json(path)


@pytest.fixture
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
        "https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf",
        "https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/ST%20-%20NetIQ%20Identity%20Manager%204.7.pdf",
        "https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/Certifikat%20CCRA%20-%20NetIQ%20Identity%20Manager%204.7_signed.pdf",
        "https://www.netiq.com/",
        None,
        set(),
        None,
        None,
        None,
    )


@pytest.fixture(scope="module")
def cert_two() -> CCCertificate:
    update = CCCertificate.MaintenanceReport(
        date(1900, 1, 1), "Sample maintenance", "https://maintenance.up", "https://maintenance.up"
    )

    return CCCertificate(
        "archived",
        "Access Control Devices and Systems",
        "Sample certificate name",
        "Sample manufacturer",
        "DE",
        {"Sample security level"},
        date(1900, 1, 2),
        date(1900, 1, 3),
        "https://path.to/report/link",
        "https://path.to/st/link",
        "https://path.to/cert/link",
        "https://path.to/manufacturer/web",
        {"https://sample.pp"},
        {update},
        None,
        None,
        None,
    )

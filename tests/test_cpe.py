from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import tests.data.cc.analysis.auxiliary_datasets
from sec_certs import constants
from sec_certs.dataset import CPEDataset, CVEDataset
from sec_certs.sample import CPE, CPEConfiguration
from sec_certs.serialization.json import SerializationError


@pytest.fixture(scope="module")
def cpe_dset_path() -> Path:
    return Path(tests.data.cc.analysis.auxiliary_datasets.__path__[0]) / "cpe_dataset.json"


@pytest.fixture(scope="module")
def cve_dset_with_cpe_configs_path() -> Path:
    return Path(tests.data.cc.analysis.auxiliary_datasets.__path__[0]) / "cve_dset_with_cpe_configs.json"


@pytest.fixture(scope="module")
def cpe_dset(cpe_dset_path: Path) -> CPEDataset:
    return CPEDataset.from_json(cpe_dset_path)


@pytest.fixture(scope="module")
def cve_dset_with_cpe_configs(cve_dset_with_cpe_configs_path: Path) -> CVEDataset:
    return CVEDataset.from_json(cve_dset_with_cpe_configs_path)


@pytest.fixture(scope="module")
def cpe_dict() -> dict[str, Any]:
    return {
        "uri": "cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*",
        "title": None,
        "start_version": None,
        "end_version": None,
    }


@pytest.mark.slow
@pytest.mark.monitor_test
@pytest.mark.xfail(reason="May fail due to errors with NIST server.")
@pytest.mark.skip(reason="Too much memory consumed.")
def test_cpe_dset_from_web(tmp_path: Path):
    dset = CPEDataset.from_web(tmp_path)
    assert dset is not None
    assert "cpe:2.3:o:infineon:trusted_platform_firmware:6.40:*:*:*:*:*:*:*" in dset.cpes


def test_cpe_dset_from_json(cpe_dset_path: Path, cpe_dset: CPEDataset):
    assert CPEDataset.from_json(cpe_dset_path) == cpe_dset


def test_cpe_dset_vendor_lookup_dict(cpe_dset: CPEDataset):
    assert cpe_dset.vendors == {"ibm", "tracker-software", "semperplugins"}


def test_cpe_dset_vendor_to_version_lookup_dict(cpe_dset: CPEDataset):
    assert cpe_dset.vendor_to_versions == {
        "ibm": {"8.2.2", "2.6.0.1"},
        "semperplugins": {"1.3.6.4"},
        "tracker-software": {"6.0.320.0"},
    }


def test_cpe_dset_vendor_version_to_cpe_lookup_dict(cpe_dset: CPEDataset):
    assert cpe_dset.vendor_version_to_cpe == {
        ("ibm", "8.2.2"): {
            CPE(
                "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*",
                "IBM Security Access Manager For Enterprise Single Sign-On 8.2.2",
            )
        },
        ("ibm", "2.6.0.1"): {
            CPE(
                "cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*",
                "IBM Security Key Lifecycle Manager 2.6.0.1",
            )
        },
        ("semperplugins", "1.3.6.4"): {
            CPE(
                "cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*",
                "Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress",
            )
        },
        ("tracker-software", "6.0.320.0"): {
            CPE(
                "cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*",
                "Tracker Software PDF-XChange Lite Printer 6.0.320.0",
            )
        },
    }


def test_cpe_parsing():
    potentially_problematic_cpes = {
        'cpe:2.3:a:bayashi:dopvstar\\::0091:*:*:*:*:*:*:*"': ("bayashi", "dopvstar:", "0091"),
        "cpe:2.3:a:moundlabs:\\:\\:mound\\:\\::2.1.6:*:*:*:*:*:*:*": ("moundlabs", "::mound::", "2.1.6"),
        "cpe:2.3:a:lemonldap-ng:lemonldap\\:\\::*:*:*:*:*:*:*:*": (
            "lemonldap-ng",
            "lemonldap::",
            constants.CPE_VERSION_NA,
        ),
        "cpe:2.3:o:cisco:nx-os:5.0\\\\\\(3\\\\\\)u5\\\\\\(1g\\\\\\):*:*:*:*:*:*:*": (
            "cisco",
            "nx-os",
            "5.0\\(3\\)u5\\(1g\\)",
        ),
        "cpe:2.3:a:\\@thi.ng\\/egf_project:\\@thi.ng\\/egf:-:*:*:*:*:node.js:*:*": (
            "@thi.ng/egf project",
            "@thi.ng/egf",
            "-",
        ),
        "cpe:2.3:a:oracle:communications_diameter_signaling_router_idih\\:::*:*:*:*:*:*:*": (
            "oracle",
            "communications diameter signaling router idih:",
            constants.CPE_VERSION_NA,
        ),
    }
    for uri, tpl in potentially_problematic_cpes.items():
        cpe = CPE(uri)
        assert cpe.vendor == tpl[0]
        assert cpe.item_name == tpl[1]
        assert cpe.version == tpl[2]


def test_cpe_from_to_dict(cpe_dict):
    cpe = CPE.from_dict(cpe_dict)
    ret = cpe.to_dict()
    assert cpe_dict == ret
    other_cpe = CPE.from_dict(ret)
    assert cpe == other_cpe


def test_to_pandas(cpe_dset: CPEDataset):
    df = cpe_dset.to_pandas()
    assert df.shape == (len(cpe_dset), len(CPE.pandas_columns) - 1)
    assert df.index.name == "uri"
    assert set(df.columns) == set(CPE.pandas_columns) - {"uri"}


def test_serialization_missing_path():
    dummy_dset = CPEDataset(False, {})
    with pytest.raises(SerializationError):
        dummy_dset.to_json()


def test_single_platform_config_cpe(cve_dset_with_cpe_configs: CVEDataset):
    tested_cpe_config = cve_dset_with_cpe_configs["CVE-2010-2325"].vulnerable_cpe_configurations
    cpe_set = {
        "cpe:2.3:a:ibm:websphere_application_server:7.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.3:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.4:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.5:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.6:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.7:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.8:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:7.0.0.9:*:*:*:*:*:*:*",
        "cpe:2.3:a:ibm:websphere_application_server:*:*:*:*:*:*:*:*",
    }
    cpe_config = CPEConfiguration(
        platform="cpe:2.3:o:ibm:zos:*:*:*:*:*:*:*:*",
        cpes=cpe_set,
    )
    assert cpe_config in tested_cpe_config


def test_multiple_platform_config_cpe(cve_dset_with_cpe_configs: CVEDataset):
    tested_cpe_configs = cve_dset_with_cpe_configs["CVE-2003-0070"].vulnerable_cpe_configurations
    cpe_set = {
        "cpe:2.3:a:nalin_dahyabhai:vte:0.11.21:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.12.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.14.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.15.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.16.14:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.17.4:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.20.5:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.22.5:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.24.3:*:*:*:*:*:*:*",
        "cpe:2.3:a:nalin_dahyabhai:vte:0.25.1:*:*:*:*:*:*:*",
    }
    cpe_configs = [
        CPEConfiguration(
            platform="cpe:2.3:a:gnome:gnome-terminal:2.0:*:*:*:*:*:*:*",
            cpes=cpe_set,
        ),
        CPEConfiguration(
            platform="cpe:2.3:a:gnome:gnome-terminal:2.2:*:*:*:*:*:*:*",
            cpes=cpe_set,
        ),
    ]

    for cpe_config in cpe_configs:
        assert cpe_config in tested_cpe_configs


def test_no_cpe_configuration(cve_dset_with_cpe_configs: CVEDataset):
    tested_cpe_configs = cve_dset_with_cpe_configs["CVE-2003-0001"].vulnerable_cpe_configurations
    assert tested_cpe_configs == []

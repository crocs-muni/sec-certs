from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from dateutil.parser import isoparse

import tests.data.fips.certificate
import tests.data.fips.dataset
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.sample.cpe import CPE, CPEConfiguration
from sec_certs.sample.cve import CVE
from sec_certs.sample.fips import FIPSCertificate


@pytest.fixture(scope="module")
def alg_dset_path() -> Path:
    return Path(tests.data.fips.dataset.__path__[0]) / "alg_dataset.json"


@pytest.fixture(scope="module")
def alg_dset(alg_dset_path: Path) -> FIPSAlgorithmDataset:
    return FIPSAlgorithmDataset.from_json(alg_dset_path)


@pytest.fixture(scope="module")
def alg_dict() -> dict[str, Any]:
    return {
        "alg_number": "2902",
        "algorithm_type": "AES",
        "vendor": "Hewlett-Packard Development Company, L.P.",
        "implementation_name": "HP Secure Encryption Engine v1.0",
        "validation_date": "7/10/2014",
    }


@pytest.fixture(scope="module")
def cert_data_dir() -> Path:
    return Path(tests.data.fips.certificate.__path__[0])


@pytest.fixture
def certificate(tmp_path_factory) -> FIPSCertificate:
    tmp_dir = tmp_path_factory.mktemp("dset")
    dset_json_path = Path(tests.data.fips.dataset.__path__[0]) / "toy_dataset.json"
    data_dir_path = dset_json_path.parent
    shutil.copytree(data_dir_path, tmp_dir, dirs_exist_ok=True)
    fips_dset = FIPSDataset.from_json(tmp_dir / "toy_dataset.json")

    crt = fips_dset["184097a88a9b4ad9"]
    fips_dset.certs = {crt.dgst: crt}
    fips_dset.download_all_artifacts()
    fips_dset.convert_all_pdfs()

    return crt


@pytest.fixture(scope="module")
def dataset_data_dir() -> Path:
    return Path(tests.data.fips.dataset.__path__[0])


@pytest.fixture(scope="module")
def toy_dataset(dataset_data_dir: Path) -> FIPSDataset:
    return FIPSDataset.from_json(dataset_data_dir / "toy_dataset.json")


@pytest.fixture(scope="module")
def vulnerable_cpe() -> CPE:
    return CPE("cpe:2.3:o:redhat:enterprise_linux:7.1:*:*:*:*:*:*:*", "Red Hat Enterprise Linux 7.1")


@pytest.fixture(scope="module")
def some_random_cpe() -> CPE:
    return CPE(
        "cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*",
        "IBM Security Key Lifecycle Manager 2.6.0.1",
    )


@pytest.fixture(scope="module")
def cve(vulnerable_cpe: CPE) -> CVE:
    return CVE(
        "CVE-1234-123456",
        [vulnerable_cpe],
        [],
        CVE.Impact(10, "HIGH", 10, 10),
        isoparse("2021-05-26T04:15Z"),
        {"CWE-200"},
    )


@pytest.fixture(scope="module")
def some_other_cve(some_random_cpe: CPE) -> CVE:
    return CVE(
        "CVE-2019-4513",
        [some_random_cpe],
        [],
        CVE.Impact(8.2, "HIGH", 3.9, 4.2),
        isoparse("2000-05-26T04:15Z"),
        {"CVE-611"},
    )


@pytest.fixture(scope="module")
def ibm_cpe_configuration() -> CPEConfiguration:
    return CPEConfiguration(
        CPE("cpe:2.3:o:ibm:zos:*:*:*:*:*:*:*:*"),
        [
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.1:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.2:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.3:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.4:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.5:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.6:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.7:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.8:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.9:*:*:*:*:*:*:*"),
            CPE("cpe:2.3:a:ibm:websphere_application_server:*:*:*:*:*:*:*:*"),
        ],
    )


@pytest.fixture(scope="module")
def cpes_ibm_websphere_app_with_platform() -> set[CPE]:
    return {
        CPE("cpe:2.3:o:ibm:zos:*:*:*:*:*:*:*:*", "IBM zOS"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:*:*:*:*:*:*:*:*", "IBM WebSphere Application Server"),
    }


@pytest.fixture(scope="module")
def ibm_xss_cve(ibm_cpe_configuration: CPEConfiguration) -> CVE:
    return CVE(
        "CVE-2010-2325",
        [],
        [ibm_cpe_configuration],
        CVE.Impact(4.3, "MEDIUM", 2.9, 8.6),
        isoparse("2000-06-18T04:15Z"),
        {"CWE-79"},
    )


@pytest.fixture(scope="module")
def cpe_dataset(
    vulnerable_cpe: CPE, some_random_cpe: CPE, cpes_ibm_websphere_app_with_platform: set[CPE]
) -> CPEDataset:
    cpes = {
        vulnerable_cpe,
        some_random_cpe,
        CPE(
            "cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*",
            "Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress",
        ),
        CPE(
            "cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*",
            "Tracker Software PDF-XChange Lite Printer 6.0.320.0",
        ),
        *cpes_ibm_websphere_app_with_platform,
    }

    return CPEDataset(False, {x.uri: x for x in cpes})


@pytest.fixture(scope="module")
def cve_dataset(cve: CVE, some_other_cve: CVE, ibm_xss_cve: CVE) -> CVEDataset:
    cves = {cve, some_other_cve, ibm_xss_cve}
    cve_dset = CVEDataset({x.cve_id: x for x in cves})
    cve_dset.build_lookup_dict(use_nist_mapping=False)
    return cve_dset


@pytest.fixture(scope="module")
def processed_dataset(
    toy_dataset: FIPSDataset, cpe_dataset: CPEDataset, cve_dataset: CVEDataset, tmp_path_factory
) -> FIPSDataset:
    tmp_dir = tmp_path_factory.mktemp("fips_dset")
    toy_dataset.copy_dataset(tmp_dir)

    tested_certs = [
        toy_dataset["3095"],
        toy_dataset["3093"],
        toy_dataset["3197"],
        toy_dataset["2441"],
    ]
    toy_dataset.certs = {x.dgst: x for x in tested_certs}

    toy_dataset.download_all_artifacts()
    toy_dataset.convert_all_pdfs()
    toy_dataset.extract_data()
    toy_dataset._compute_references(keep_unknowns=True)

    toy_dataset.auxiliary_datasets.cpe_dset = cpe_dataset
    toy_dataset.auxiliary_datasets.cve_dset = cve_dataset
    toy_dataset.compute_cpe_heuristics()
    toy_dataset.compute_related_cves()
    toy_dataset._compute_transitive_vulnerabilities()

    return toy_dataset

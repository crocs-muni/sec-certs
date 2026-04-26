import json
from collections.abc import Generator
from dataclasses import asdict
from datetime import date, timedelta
from importlib.resources import as_file, files
from pathlib import Path

import pytest
import tests.data.eucc

from sec_certs.sample.eucc import EUCCCertificate


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        (
            "Alice Smith a [dot] smith organization [dot] com ( a[dot]smith[at]organization[dot]com ) tel +123456789",
            "Alice Smith a.smith@organization.com tel +123456789",
        ),
        ("%20support [dot] team generic [dot] org ( support[dot]team[at]generic[dot]org )", "support.team@generic.org"),
        (
            "John Smith Doe j [dot] smith corporate [dot] net ( j[dot]smith[at]corporate[dot]net )",
            "John Smith Doe j.smith@corporate.net",
        ),
        ("Generic contact info 987654", "Generic contact info 987654"),
        ("--- Admin . %20 office [at] domain ( office[at]domain[dot]com )", "Admin office@domain.com"),
        (
            "Phone +49 (0)228 99 9582-0 - Fax +49 (0)228 9582-5477 - Infoline +49 (0)228 99 9582-111",
            "Phone +49 (0)228 99 9582-0 - Fax +49 (0)228 9582-5477 - Infoline +49 (0)228 99 9582-111",
        ),
    ],
)
def test_deobfuscate_contact(input_text, expected_output):
    result = EUCCCertificate.EnisaMetadata._deobfuscate_contact(input_text)
    assert result == expected_output


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        (
            "EAL4 augmented with ALC_FLR.1",
            {"EAL4": ["ALC_FLR.1"]},
        ),
        (
            "EAL2",
            {"EAL2": []},
        ),
        (
            "EAL5 augmented with ALC_FLR.2, AVA_VAN.5",
            {"EAL5": ["ALC_FLR.2", "AVA_VAN.5"]},
        ),
        (
            "EAL1 augmented with ALC_FLR.2 and ASE_SPD.1",
            {"EAL1": ["ALC_FLR.2", "ASE_SPD.1"]},
        ),
        (
            "Global Assurance: EAL 5 augmented with ADV_IMP.2, ADV_INT.3, ADV_TDS.5, ALC_CMC.5, ALC_DVS.2, "
            "ALC_FLR.3, ALC_TAT.3, ATE_FUN.2, ATE_COV.3, AVA_VAN.5 sub-TSF assurance level EAL6 augmented with ALC_FLR.3",
            {
                "EAL5": [
                    "ADV_IMP.2",
                    "ADV_INT.3",
                    "ADV_TDS.5",
                    "ALC_CMC.5",
                    "ALC_DVS.2",
                    "ALC_FLR.3",
                    "ALC_TAT.3",
                    "ATE_FUN.2",
                    "ATE_COV.3",
                    "AVA_VAN.5",
                ],
                "EAL6": ["ALC_FLR.3"],
            },
        ),
    ],
)
def test_parse_package(input_text, expected_output):
    result = EUCCCertificate.EnisaMetadata._parse_package(input_text)
    assert result == expected_output


@pytest.mark.parametrize(
    "cert_id, expected_output",
    [
        ("EUCC-ANSSI-2025-3-2", "FR"),
        ("EUCC-ANSSI-2025-3-1", "FR"),
        ("EUCC-3095-2025-07-01", "ES"),
        ("EUCC-3110-2025-08-2500052-01", "NL"),
        ("EUCC-3090-2025-10-0003", "FR"),
        ("EUCC-3090-2026-14", "FR"),
    ],
)
def test_get_scheme_from_cert_id(cert_id, expected_output):
    result = EUCCCertificate._get_scheme_from_cert_id(cert_id)
    assert result == expected_output


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        ("2023-01-01", date(2023, 1, 1)),
        ("02/04/2025", date(2025, 2, 4)),
        ("", None),
        (None, None),
        ("not a date string", None),
    ],
)
def test_get_not_valid_before(input_text, expected_output):
    result = EUCCCertificate._get_not_valid_before(input_text)
    assert result == expected_output


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        ("2024-01-01", date(2029, 1, 1)),
        ("2020/12/31", date(2025, 12, 31)),
        ("2024/02/29", date(2029, 2, 28)),
        ("2023/02/28", date(2028, 2, 28)),
        ("", None),
        (None, None),
        ("this is not a date", None),
        ("2024-13-45", None),
    ],
)
def test_get_not_valid_after(input_text, expected_output):
    result = EUCCCertificate._get_not_valid_after(input_text)
    assert result == expected_output


@pytest.mark.parametrize(
    "input_date, expected_output",
    [
        (date.today() + timedelta(days=1), "active"),
        (date.today() + timedelta(days=365), "active"),
        (date.today(), "archived"),
        (date.today() - timedelta(days=1), "archived"),
        (date.today() - timedelta(days=1000), "archived"),
        (None, None),
    ],
)
def test_get_status(input_date, expected_output):
    result = EUCCCertificate._get_status(input_date)
    assert result == expected_output


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        (
            "https://semiconductor.samsung.com/security-solution/nfc/part-number/s3nsen6/",
            "https://semiconductor.samsung.com/security-solution/nfc/part-number/s3nsen6/",
        ),
        ("Visit https://example.com/.", "https://example.com/."),
    ],
)
def test_extract_holder_website(input_text, expected_output):
    result = EUCCCertificate._extract_holder_website(input_text)
    assert result == expected_output


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        ("EAL4", "EAL4"),
        ("EAL4 augmented with ALC_FLR.1", "EAL4"),
        ("EAL5 augmented with ALC_FLR.2, AVA_VAN.5", "EAL5"),
        (
            "EAL5 Augmenté (ADV_IMP.2, ADV_INT.3, ADV_TDS.5, ALC_CMC.5, ALC_DVS.2, ALC_TAT.3, ASE_TSS.2, ATE_COV.3, "
            "ATE_FUN.2, AVA_VAN.5) EAL6 Augmenté (ASE_TSS.2)",
            "EAL5",
        ),
        ("EAL12", "EAL12"),
        ("No security level present", ""),
        ("", ""),
        (None, ""),
        ("eal4", ""),
    ],
)
def test_extract_first_eal(input_text, expected_output):
    result = EUCCCertificate._extract_first_eal(input_text)
    assert result == expected_output


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with as_file(files(tests.data.eucc)) as path:
        yield path


def load_scraped_metadata(data_dir: Path) -> dict:
    with Path.open(data_dir / "scraped_metadata.json", "r", encoding="utf-8") as f:
        return json.load(f)


def load_scraped_links(data_dir: Path) -> dict:
    with Path.open(data_dir / "scraped_links.json", "r", encoding="utf-8") as f:
        return json.load(f)


def load_processed_enisa_metadata(data_dir: Path) -> dict:
    with Path.open(data_dir / "processed_other_metadata.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_from_metadata_dict(data_dir):
    metadata = load_scraped_metadata(data_dir)
    links = load_scraped_links(data_dir)
    expected_enisa_metadata = load_processed_enisa_metadata(data_dir)

    cert = EUCCCertificate._from_metadata_dict(metadata["certificate_id"], metadata, links)

    actual_fields = {
        "category": cert.category,
        "name": cert.name,
        "status": cert.status,
        "manufacturer": cert.manufacturer,
        "security_level": cert.security_level,
        "not_valid_before": cert.not_valid_before,
        "not_valid_after": cert.not_valid_after,
        "report_link": cert.report_link,
        "st_link": cert.st_link,
        "cert_link": cert.cert_link,
        "manufacturer_web": cert.manufacturer_web,
    }

    expected_fields = {
        "category": "SMARTCARD CONTROLLER",
        "name": (
            "Infineon Security Controller IFX_CCI_00000Fh, IFX_CCI_000010h, IFX_CCI_000026h, "
            "IFX_CCI_000027h, IFX_CCI_000028h, IFX_CCI_000029h, IFX_CCI_00002Ah, "
            "IFX_CCI_00002Bh, IFX_CCI_00002Ch in the design step G12"
        ),
        "status": "active",
        "manufacturer": "Infineon Technologies AG",
        "security_level": {"EAL6"},
        "not_valid_before": date(2025, 12, 19),
        "not_valid_after": date(2030, 12, 19),
        "report_link": (
            "https://certification.enisa.europa.eu/document/download/"
            "39c71b1a-27f0-49d9-bd39-ac950ba8795c_en?"
            "filename=EUCC-3087-2025-12-0001%20Certificate%20Report.pdf"
        ),
        "st_link": (
            "https://certification.enisa.europa.eu/document/download/"
            "cd6b4c5a-4f26-452d-9ced-b7eb0683ef7c_en?"
            "filename=EUCC-3087-2025-12-0001%20Security.pdf"
        ),
        "cert_link": (
            "https://certification.enisa.europa.eu/document/download/"
            "110c73bb-359a-40af-9e59-612f085a0fc9_en?"
            "filename=EUCC-3087-2025-12-0001%20Certificate.pdf"
        ),
        "manufacturer_web": "https://www.infineon.com/product-information/cybersecurity-information",
    }

    assert actual_fields == expected_fields
    assert asdict(cert.other_metadata) == expected_enisa_metadata

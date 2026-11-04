import importlib
import locale
from collections.abc import Generator
from importlib.resources import as_file, files
from pathlib import Path

import pytest
import tests.data.cc.frontpage

from sec_certs import constants
from sec_certs.utils.frontpage import BSIFrontpageParser, CanadaFrontpageParser, NSCIBFrontpageParser
from sec_certs.utils.frontpage import canada as canada_module
from sec_certs.utils.frontpage.nscib import _organization_of


@pytest.fixture(scope="module")
def frontpage_dir() -> Generator[Path, None, None]:
    with as_file(files(tests.data.cc.frontpage)) as path:
        yield path


NSCIB_TRUSTCB_EXPECTED = {
    constants.TAG_CERT_ID: "NSCIB-CC-2400046-01-CR",
    constants.TAG_CERT_ITEM: (
        "Cisco Secure Firewall Threat Defense (FTD) 7.4 with Secure Firewall Management Center (FMC) 7.4 "
        "and Secure Client 5.1"
    ),
    constants.TAG_DEVELOPER: "Cisco Systems, Inc",
    constants.TAG_SPONSOR: "Cisco Systems, Inc",
    constants.TAG_CERT_LAB: "SGS Brightsight B.V",
    constants.TAG_EVAL_FACILITY: "SGS Brightsight B.V",
    constants.TAG_REPORT_VERSION: "1",
    constants.TAG_PROJECT_NUMBER: "NSCIB-2400046-01",
    constants.TAG_AUTHOR: "Kjartan Jæger Kvassnes",
    constants.TAG_REPORT_DATE: "23 March 2025",
}

NSCIB_TUV_EXPECTED = {
    constants.TAG_CERT_ID: "NSCIB-CC-234008-CR",
    constants.TAG_CERT_ITEM: "TrustWare 3.0 (v3.0.5",
    constants.TAG_DEVELOPER: "Samsung Electronics Co., Ltd",
    constants.TAG_SPONSOR: "Samsung Electronics Co., Ltd",
    constants.TAG_CERT_LAB: "Brightsight",
    constants.TAG_EVAL_FACILITY: "Brightsight",
    constants.TAG_REPORT_VERSION: "1",
    constants.TAG_PROJECT_NUMBER: "234008",
    constants.TAG_AUTHOR: "Denise Cater",
    constants.TAG_REPORT_DATE: "9 October 2019",
}


@pytest.fixture(scope="module")
def nscib_parser() -> NSCIBFrontpageParser:
    return NSCIBFrontpageParser()


@pytest.mark.parametrize(
    ("name", "expected"),
    [("nscib_report_trustcb", NSCIB_TRUSTCB_EXPECTED), ("nscib_report_tuv", NSCIB_TUV_EXPECTED)],
)
@pytest.mark.parametrize("converter", ["pdftotext", "docling"])
def test_nscib_text(
    nscib_parser: NSCIBFrontpageParser, frontpage_dir: Path, name: str, expected: dict[str, str], converter: str
):
    items = nscib_parser.parse(frontpage_dir / converter / f"{name}.txt")

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "text"
    assert items == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [("nscib_report_trustcb", NSCIB_TRUSTCB_EXPECTED), ("nscib_report_tuv", NSCIB_TUV_EXPECTED)],
)
def test_nscib_structured(nscib_parser: NSCIBFrontpageParser, frontpage_dir: Path, name: str, expected: dict[str, str]):
    items = nscib_parser.parse(frontpage_dir / "docling" / f"{name}.txt", frontpage_dir / "docling" / f"{name}.json")

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "structured"
    assert items == expected


def test_nscib_converters_agree_on_hyphenated_project_number(nscib_parser: NSCIBFrontpageParser, frontpage_dir: Path):
    pdftotext = nscib_parser.parse(frontpage_dir / "pdftotext" / "nscib_report_trustcb.txt")
    docling = nscib_parser.parse(frontpage_dir / "docling" / "nscib_report_trustcb.txt")

    assert pdftotext[constants.TAG_PROJECT_NUMBER] == "NSCIB-2400046-01"
    assert docling[constants.TAG_PROJECT_NUMBER] == "NSCIB-2400046-01"


@pytest.mark.parametrize(
    ("name", "cert_id", "facility", "author", "report_date"),
    [
        ("nscib_report_tuv_2020", "NSCIB-CC-0176780-CR", "Brightsight", "Wouter Slegers", "20 August 2020"),
        ("nscib_report_tuv_2022", "NSCIB-CC-0392006-CR", "SGS Brightsight B.V", "Andy Brown", "31 August 2022"),
    ],
)
def test_nscib_further_templates(
    nscib_parser: NSCIBFrontpageParser,
    frontpage_dir: Path,
    name: str,
    cert_id: str,
    facility: str,
    author: str,
    report_date: str,
):
    items = nscib_parser.parse(frontpage_dir / "pdftotext" / f"{name}.txt")

    assert items[constants.TAG_CERT_ID] == cert_id
    assert items[constants.TAG_CERT_LAB] == facility
    assert items[constants.TAG_AUTHOR] == author
    assert items[constants.TAG_REPORT_DATE] == report_date


def test_nscib_cert_lab_has_no_leading_whitespace(nscib_parser: NSCIBFrontpageParser, frontpage_dir: Path):
    for name in ("nscib_report_trustcb", "nscib_report_tuv"):
        cert_lab = nscib_parser.parse(frontpage_dir / "pdftotext" / f"{name}.txt")[constants.TAG_CERT_LAB]
        assert cert_lab == cert_lab.strip()
        assert cert_lab.split(" ")[0].upper()


def test_nscib_ignores_letterhead_labels(nscib_parser: NSCIBFrontpageParser, frontpage_dir: Path):
    items = nscib_parser.parse(frontpage_dir / "pdftotext" / "nscib_report_tuv.txt")

    assert "Westervoortsedijk" not in items[constants.TAG_CERT_ITEM]
    assert "NL815820380B01" not in str(items)


def test_nscib_colon_in_certified_item_is_not_a_label(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "colon.txt"
    report.write_text(
        "\n".join(
            [
                "Certification Report",
                "Acme SecureCore: Crypto Edition",
                "v2.1 (build 42)",
                "Sponsor and developer: Acme Systems, Inc.",
                "1 Acme Way",
                "Report number: NSCIB-CC-2400099-01-CR",
                "Date: 1 January 2025",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    items = nscib_parser.parse(report)

    assert items[constants.TAG_CERT_ITEM] == "Acme SecureCore: Crypto Edition v2.1 (build 42"
    assert items[constants.TAG_DEVELOPER] == "Acme Systems, Inc"
    assert items[constants.TAG_CERT_ID] == "NSCIB-CC-2400099-01-CR"


@pytest.mark.parametrize(
    ("merged", "expected"),
    [
        ("AKD d.o.o. Savska cesta 31, 10 000 Zagreb, Republic of Croatia", "AKD d.o.o."),
        ("AKD D.O.O. Savska cesta 31, 10 000 Zagreb", "AKD D.O.O."),
        ("Cisco Systems, Inc. 170 West Tasman Drive 95134 San Jose, CA USA", "Cisco Systems, Inc."),
        ("SGS Brightsight B.V. Brassersplein 2 2612 CT Delft The Netherlands", "SGS Brightsight B.V."),
        ("Entrust Minneapolis1187 Park Place Shakopee, MN 55379 USA", "Entrust"),
        ("Brightsight", "Brightsight"),
    ],
)
def test_nscib_organization_trimmed_off_merged_address(merged: str, expected: str):
    assert _organization_of(merged) == expected


def test_nscib_soft_hyphen_in_prose_is_dropped(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "hyphenated.txt"
    report.write_text(
        "Certification Report\nAcme Secure\u00adCore\nReport number: NSCIB-CC-2400099-01-CR\n",
        encoding="utf-8",
    )

    assert nscib_parser.parse(report)[constants.TAG_CERT_ITEM] == "Acme SecureCore"


def test_nscib_unbalanced_parenthesis_is_still_trimmed(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "unbalanced.txt"
    report.write_text(
        "Certification Report\nAcme SecureCore v1.0)\nReport number: NSCIB-CC-2400099-01-CR\n",
        encoding="utf-8",
    )

    assert nscib_parser.parse(report)[constants.TAG_CERT_ITEM] == "Acme SecureCore v1.0"


def test_nscib_address_trimmed_when_label_and_value_share_a_block(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "merged_label.txt"
    report.write_text(
        "\n".join(
            [
                "Certification Report",
                "Acme SecureCore",
                "Sponsor: Veridos GmbH, Identity Solutions Prinzregentenstr. 161 1677 Munchen Germany",
                "Report number: NSCIB-CC-2300088-01-CR2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert nscib_parser.parse(report)[constants.TAG_SPONSOR] == "Veridos GmbH"


def test_nscib_spaced_dash_in_certified_item_is_kept(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "dash.txt"
    report.write_text(
        "Certification Report\nAcme SecureCore - Crypto Edition\nReport number: NSCIB-CC-2400099-01-CR\n",
        encoding="utf-8",
    )

    items = nscib_parser.parse(report)

    assert items[constants.TAG_CERT_ITEM] == "Acme SecureCore - Crypto Edition"


def test_nscib_fields_survive_a_missing_cert_id(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "no_id.txt"
    report.write_text(
        "Certification Report\nAcme SecureCore\nEvaluation facility: Riscure B.V.\nDate: 1 January 2025\n",
        encoding="utf-8",
    )

    items = nscib_parser.parse(report)

    assert constants.TAG_CERT_ID not in items
    assert items[constants.TAG_CERT_LAB] == "Riscure B.V"
    assert items[constants.TAG_REPORT_DATE] == "1 January 2025"
    assert items[constants.TAG_CERT_ITEM] == "Acme SecureCore"


def test_nscib_scheme_prefixed_title_is_recognized(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "eucc_title.txt"
    report.write_text(
        "\n".join(
            [
                "EUCC Certification Report",
                "ZTE OTN Solution v1.10",
                "Sponsor and developer: ZTE Corporation",
                "Report number: EUCC-3110-2026-2500102-01",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    items = nscib_parser.parse(report)

    assert items[constants.TAG_CERT_ITEM] == "ZTE OTN Solution v1.10"
    assert items[constants.TAG_DEVELOPER] == "ZTE Corporation"


def test_nscib_reference_line_is_not_a_title(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "reference_line.txt"
    report.write_text(
        "\n".join(
            [
                "TNO CERTIFICATION",
                "NSCIB-CC-05-6609 Certification Report",
                "Laan van Westenenk 501 P.O. Box 541 7300 AM Apeldoorn",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert nscib_parser.parse(report) == {}


def test_nscib_non_report_yields_nothing(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    not_a_report = tmp_path / "empty.txt"
    not_a_report.write_text("Lorem ipsum dolor sit amet.\n", encoding="utf-8")

    assert nscib_parser.parse(not_a_report) == {}


@pytest.fixture(scope="module")
def canada_parser() -> CanadaFrontpageParser:
    return CanadaFrontpageParser()


CANADA_HSL_EXPECTED = {
    constants.TAG_CERT_ID: "544-EWA",
    constants.TAG_CERT_LAB: "CANADA",
    constants.TAG_CERT_ITEM: (
        "High Sec Labs SK21PH-4, SK41PH-4, DK22PH-4, DK42PH-4, SK81PH-4, DK82PH-4, SX42PH-4, SX82PH-4 "
        "Firmware Version 44404-E7E7 Peripheral Sharing Devices"
    ),
    constants.TAG_REPORT_DATE: "20 November 2023",
}

CANADA_THYCOTIC_EXPECTED = {
    constants.TAG_CERT_ID: "383-4-445",
    constants.TAG_CERT_LAB: "CANADA",
    constants.TAG_CERT_ITEM: "Thycotic Secret Server Government Edition v10.0",
    constants.TAG_REPORT_VERSION: "1.1",
    constants.TAG_REPORT_DATE: "23 October 2018",
}

CANADA_MCAFEE_HERCULES_EXPECTED = {
    constants.TAG_CERT_ID: "383-4-88-CR",
    constants.TAG_CERT_LAB: "CANADA",
    constants.TAG_CERT_ITEM: "McAfee® Hercules® Policy Auditor v4.5 and McAfee® Hercules® Remediation Manager v4.5",
    constants.TAG_REPORT_VERSION: "1.1",
    constants.TAG_REPORT_DATE: "11 April 2008",
}

CANADA_NETAPP_EXPECTED = {
    constants.TAG_CERT_ID: "383-4-263-CR",
    constants.TAG_CERT_LAB: "CANADA",
    constants.TAG_CERT_ITEM: "NetApp Clustered Data ONTAP® 8.2.1",
    constants.TAG_REPORT_VERSION: "1.0",
    constants.TAG_REPORT_DATE: "5 January 2015",
}

CANADA_REPORTS = [
    ("canada_report_hsl", CANADA_HSL_EXPECTED),
    ("canada_report_thycotic", CANADA_THYCOTIC_EXPECTED),
    ("canada_report_mcafee_hercules", CANADA_MCAFEE_HERCULES_EXPECTED),
    ("canada_report_netapp", CANADA_NETAPP_EXPECTED),
]


@pytest.mark.parametrize(("name", "expected"), CANADA_REPORTS)
def test_canada_text(canada_parser: CanadaFrontpageParser, frontpage_dir: Path, name: str, expected: dict[str, str]):
    items = canada_parser.parse(frontpage_dir / "pdftotext" / f"{name}.txt")

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "text"
    assert items == expected


@pytest.mark.parametrize(("name", "expected"), CANADA_REPORTS)
def test_canada_structured(
    canada_parser: CanadaFrontpageParser, frontpage_dir: Path, name: str, expected: dict[str, str]
):
    items = canada_parser.parse(frontpage_dir / "docling" / f"{name}.txt", frontpage_dir / "docling" / f"{name}.json")

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "structured"
    assert items == expected


def test_canada_further_template(canada_parser: CanadaFrontpageParser, frontpage_dir: Path):
    items = canada_parser.parse(frontpage_dir / "pdftotext" / "canada_report_mcafee.txt")

    assert items[constants.TAG_CERT_ID] == "383-4-396"
    assert items[constants.TAG_CERT_LAB] == "CANADA"
    assert items[constants.TAG_CERT_ITEM] == (
        "McAfee Threat Intelligence Exchange 2.0.0 and Data Exchange Layer 3.0.0 with ePolicy Orchestrator 5.3.2"
    )
    assert items[constants.TAG_REPORT_VERSION] == "1.0"
    assert items[constants.TAG_REPORT_DATE] == "30 November 2016"


CANADA_DELL_EXPECTED = {
    constants.TAG_CERT_ID: "383-4-480",
    constants.TAG_CERT_LAB: "CANADA",
    constants.TAG_CERT_ITEM: "Dell EMC™ Isilon with OneFS v8.2.0.0",
    constants.TAG_DEVELOPER: "Dell EMC",
    constants.TAG_REPORT_VERSION: "1.0",
    constants.TAG_REPORT_DATE: "31 January 2020",
}


def test_canada_structured_developer(canada_parser: CanadaFrontpageParser, frontpage_dir: Path):
    items = canada_parser.parse(
        frontpage_dir / "docling" / "canada_report_dell.txt", frontpage_dir / "docling" / "canada_report_dell.json"
    )

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "structured"
    assert items == CANADA_DELL_EXPECTED


def test_canada_text_developer(canada_parser: CanadaFrontpageParser, frontpage_dir: Path):
    items = canada_parser.parse(frontpage_dir / "pdftotext" / "canada_report_dell.txt")

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "text"
    assert items == CANADA_DELL_EXPECTED


def test_canada_text_developer_under_wrapped_product_name(canada_parser: CanadaFrontpageParser):
    text = (
        "COMMON CRITERIA CERTIFICATION REPORT\nMarket Central SecureSwitch® Fiber Optic\nSwitch Models: A, B\n"
        "Market Central, Inc.\n25 June 2020\n383-4-506\nV1.0\n"
    )

    items = canada_parser.parse_text(text.replace("\n", " "), text)

    assert items[constants.TAG_DEVELOPER] == "Market Central, Inc"
    assert items[constants.TAG_CERT_ITEM] == "Market Central SecureSwitch® Fiber Optic Switch Models: A, B"


def test_canada_text_wrapped_product_name_starting_like_it_is_not_a_developer(canada_parser: CanadaFrontpageParser):
    text = (
        "COMMON CRITERIA CERTIFICATION REPORT\nMcAfee Threat Intelligence Exchange 2.0.0 and\n"
        "McAfee Data Exchange Layer\n30 November 2016\n383-4-396\n"
    )

    items = canada_parser.parse_text(text.replace("\n", " "), text)

    assert constants.TAG_DEVELOPER not in items
    assert items[constants.TAG_CERT_ITEM] == (
        "McAfee Threat Intelligence Exchange 2.0.0 and McAfee Data Exchange Layer"
    )


def test_canada_report_version_ignores_product_version(canada_parser: CanadaFrontpageParser):
    text = "COMMON CRITERIA CERTIFICATION REPORT\nFortiManager 6.2\n7 November 2022\n573-LSS\n"

    items = canada_parser.parse_text(text.replace("\n", " "), text)

    assert items[constants.TAG_CERT_ITEM] == "FortiManager 6.2"
    assert constants.TAG_REPORT_VERSION not in items


def _docling_document(blocks: list[str]) -> dict:
    return {"texts": [{"text": block} for block in blocks]}


def test_canada_title_keeps_all_caps_product_words(canada_parser: CanadaFrontpageParser):
    text = "COMMON CRITERIA CERTIFICATION REPORT\nIBM Security QRadar 7.4\n31 January 2020\n383-4-480\n"

    items = canada_parser.parse_text(text.replace("\n", " "), text)

    assert items[constants.TAG_CERT_ITEM] == "IBM Security QRadar 7.4"
    assert items[constants.TAG_REPORT_DATE] == "31 January 2020"


def test_canada_structured_wrapped_product_name_is_not_a_developer(canada_parser: CanadaFrontpageParser):
    items = canada_parser.parse_structured(
        _docling_document(
            [
                "COMMON CRITERIA CERTIFICATION REPORT",
                "High Sec Labs SK21PH-4, SK41PH-4",
                "Firmware Version 44404-E7E7 Peripheral Sharing Devices",
                "20 November 2023",
                "544-EWA",
            ]
        )
    )

    assert constants.TAG_DEVELOPER not in items
    assert items[constants.TAG_CERT_ITEM] == (
        "High Sec Labs SK21PH-4, SK41PH-4 Firmware Version 44404-E7E7 Peripheral Sharing Devices"
    )


def test_canada_structured_developer_by_legal_form(canada_parser: CanadaFrontpageParser):
    items = canada_parser.parse_structured(
        _docling_document(
            ["COMMON CRITERIA CERTIFICATION REPORT", "FortiGate 7.0", "Fortinet, Inc.", "31 January 2020", "383-4-480"]
        )
    )

    assert items[constants.TAG_DEVELOPER] == "Fortinet, Inc"
    assert items[constants.TAG_CERT_ITEM] == "FortiGate 7.0"


def test_canada_structured_legacy_issued_by_is_not_a_developer(canada_parser: CanadaFrontpageParser):
    items = canada_parser.parse_structured(
        _docling_document(
            [
                "Certification Report",
                "NetApp Clustered Data ONTAP® 8.2.1",
                "Issued by:",
                "Communications Security Establishment Certification Body Document number : 383-4-263-CR",
            ]
        )
    )

    assert constants.TAG_DEVELOPER not in items
    assert items[constants.TAG_CERT_ITEM] == "NetApp Clustered Data ONTAP® 8.2.1"


def test_canada_date_parsing_ignores_process_locale():
    try:
        locale.setlocale(locale.LC_ALL, "cs_CZ.UTF-8")
    except locale.Error:
        pytest.skip("cs_CZ.UTF-8 locale not installed")

    try:
        text = "COMMON CRITERIA CERTIFICATION REPORT\nThycotic Secret Server v10.0\n23 October 2018\n383-4-445\n"
        items = importlib.reload(canada_module).CanadaFrontpageParser().parse_text(text.replace("\n", " "), text)
    finally:
        locale.setlocale(locale.LC_ALL, "C")
        importlib.reload(canada_module)

    assert items[constants.TAG_REPORT_DATE] == "23 October 2018"
    assert items[constants.TAG_CERT_ITEM] == "Thycotic Secret Server v10.0"


def test_canada_docling_markdown_lacks_frontpage_content(canada_parser: CanadaFrontpageParser, frontpage_dir: Path):
    items = canada_parser.parse(frontpage_dir / "docling" / "canada_report_hsl.txt")

    assert items == {}


def test_canada_non_report_yields_nothing(canada_parser: CanadaFrontpageParser, tmp_path: Path):
    not_a_report = tmp_path / "empty.txt"
    not_a_report.write_text("Lorem ipsum dolor sit amet.\n", encoding="utf-8")

    assert canada_parser.parse(not_a_report) == {}


@pytest.fixture(scope="module")
def bsi_parser() -> BSIFrontpageParser:
    return BSIFrontpageParser()


BSI_EUCC_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-0904-V3-2026",
    constants.TAG_EUCC_CERT_ID: "EUCC-3087-2026-0012",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: "TCOS FlexCert Version 2.0 Release 2/SLC52",
    constants.TAG_DEVELOPER: "Deutsche Telekom Security GmbH",
}

BSI_1999_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-0153-1999",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: "Philips Smart Card Controller P8WE5032V0B",
    constants.TAG_DEVELOPER: "Philips Semiconductors Hamburg Unternehmensbereich der Philips GmbH Business Line Identification",
}

BSI_2003_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-0225-2003",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: (
        "IBM LPAR for POWER 4 for the IBM pSeries Firmware Releases: 3R031021 (p630), 3K031021 (p650) "
        "and 3H031021 (p690"
    ),
    constants.TAG_DEVELOPER: "IBM Corporation",
}

BSI_2020_DE_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-1063-2020",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: "c-secure-ident, Version 2.0",
    constants.TAG_DEVELOPER: "c-trace GmbH",
}

BSI_2020_SPONSOR_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-0831-V2-2020",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: "SMGW, Version 1.1",
    constants.TAG_DEVELOPER: "OpenLimit SignCubes GmbH",
    constants.TAG_SPONSOR: "Power Plus Communications AG",
}

BSI_MAINTENANCE_2008_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-0386-2006-MA-04",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: "ZKA SECCOS Sig v1.5.3",
    constants.TAG_DEVELOPER: "Sagem Orga GmbH",
}

BSI_MAINTENANCE_2022_DE_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-0862-V2-2021-MA-02",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: "POLYAS CORE, Version 2.5.4",
    constants.TAG_DEVELOPER: "Polyas GmbH",
}

BSI_REASSESSMENT_2023_EXPECTED = {
    constants.TAG_CERT_ID: "BSI-DSZ-CC-1188-2023-RA-02",
    constants.TAG_CERT_LAB: "BSI",
    constants.TAG_CERT_ITEM: "TCOS ID Version 3.0 Release 1/P71",
    constants.TAG_DEVELOPER: "Deutsche Telekom Security GmbH",
}

# A protection profile report: no BSI-DSZ id and no product, only the EUCC id
BSI_EUCC_PP_EXPECTED = {
    constants.TAG_CERT_ID: "EUCC-3087-2026-0006",
    constants.TAG_EUCC_CERT_ID: "EUCC-3087-2026-0006",
    constants.TAG_CERT_LAB: "BSI",
}

BSI_REPORTS = [
    ("bsi_eucc_report", BSI_EUCC_EXPECTED),
    ("bsi_report_1999", BSI_1999_EXPECTED),
    ("bsi_report_2003", BSI_2003_EXPECTED),
    ("bsi_report_2020_de", BSI_2020_DE_EXPECTED),
    ("bsi_report_2020_sponsor", BSI_2020_SPONSOR_EXPECTED),
    ("bsi_maintenance_2008", BSI_MAINTENANCE_2008_EXPECTED),
    ("bsi_maintenance_2022_de", BSI_MAINTENANCE_2022_DE_EXPECTED),
    ("bsi_reassessment_2023", BSI_REASSESSMENT_2023_EXPECTED),
    ("bsi_eucc_pp_report", BSI_EUCC_PP_EXPECTED),
]


@pytest.mark.parametrize(("name", "expected"), BSI_REPORTS)
def test_bsi_text(bsi_parser: BSIFrontpageParser, frontpage_dir: Path, name: str, expected: dict[str, str]):
    items = bsi_parser.parse(frontpage_dir / "pdftotext" / f"{name}.txt")

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "text"
    assert items == expected


@pytest.mark.parametrize(("name", "expected"), BSI_REPORTS)
def test_bsi_structured(bsi_parser: BSIFrontpageParser, frontpage_dir: Path, name: str, expected: dict[str, str]):
    items = bsi_parser.parse(frontpage_dir / "docling" / f"{name}.txt", frontpage_dir / "docling" / f"{name}.json")

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "structured"
    assert items == expected


def test_bsi_report_without_title(bsi_parser: BSIFrontpageParser, frontpage_dir: Path):
    items = bsi_parser.parse(frontpage_dir / "pdftotext" / "bsi_certificate_page.txt")

    assert items == {
        constants.TAG_CERT_ID: "BSI-DSZ-CC-1248-2026",
        constants.TAG_CERT_LAB: "BSI",
        constants.TAG_CERT_ITEM: "SUSE Linux Enterprise Server 15 SP4",
        constants.TAG_DEVELOPER: "SUSE Software Solutions Germany GmbH",
        constants.TAG_PARSE_STRATEGY: "text",
    }


def test_bsi_two_digit_version_in_administration_id(bsi_parser: BSIFrontpageParser):
    document = _docling_document(
        [
            "EUCC-3087-2026-04-0005 Administration ID BSI-DSZ-CC-0827-V11-2026",
            "for",
            "Infineon Technologies Security Controller M9900 A22",
            "from",
            "Infineon Technologies AG",
        ]
    )

    items = bsi_parser.parse_structured(document)

    assert items[constants.TAG_CERT_ID] == "BSI-DSZ-CC-0827-V11-2026"
    assert items[constants.TAG_EUCC_CERT_ID] == "EUCC-3087-2026-04-0005"


def test_bsi_merged_heading_keeps_der_inside_developer(bsi_parser: BSIFrontpageParser):
    document = _docling_document(
        [
            "BSI-DSZ-CC-0153-1999 for Philips Smart Card Controller P8WE5032V0B from Philips Semiconductors "
            "Hamburg Unternehmensbereich der Philips GmbH"
        ]
    )

    items = bsi_parser.parse_structured(document)

    assert items[constants.TAG_CERT_ITEM] == "Philips Smart Card Controller P8WE5032V0B"
    assert items[constants.TAG_DEVELOPER] == "Philips Semiconductors Hamburg Unternehmensbereich der Philips GmbH"


@pytest.mark.parametrize(
    "blocks",
    [
        ["BSI-DSZ-CC-0886-2013", "for", "TCOS Passport Version 2.1", "from T-Systems International GmbH"],
        ["BSI-DSZ-CC-0886-2013", "zu", "TCOS Passport Version 2.1", "der T-Systems International GmbH"],
        ["BSI-DSZ-CC-0886-2013", "for TCOS Passport Version 2.1 from", "T-Systems International GmbH"],
        ["BSI-DSZ-CC-0886-2013", "TCOS Passport", "for Version 2.1", "from T-Systems International GmbH"],
        ["TCOS Passport", "BSI-DSZ-CC-0886-2013 for Version 2.1 from T-Systems International GmbH"],
    ],
    ids=["glued-from", "glued-der", "glued-for-and-trailing-from", "for-inside-product", "product-above-id"],
)
def test_bsi_structured_reordered_by_docling(bsi_parser: BSIFrontpageParser, blocks: list[str]):
    items = bsi_parser.parse_structured(_docling_document(blocks))

    assert items[constants.TAG_CERT_ITEM] == "TCOS Passport Version 2.1"
    assert items[constants.TAG_DEVELOPER] == "T-Systems International GmbH"


def test_bsi_developer_stops_at_letterhead(bsi_parser: BSIFrontpageParser):
    document = _docling_document(
        [
            "BSI-DSZ-CC-1248-2026",
            "for",
            "SUSE Linux Enterprise Server 15 SP4",
            "from",
            "SUSE Software Solutions Germany GmbH",
            "BSI - Bundesamt für Sicherheit in der Informationstechnik, Postfach 20 03 63, D-53133 Bonn",
            "Certification Report V1.0 CC-Zert-327 V5.53",
        ]
    )

    items = bsi_parser.parse_structured(document)

    assert items[constants.TAG_DEVELOPER] == "SUSE Software Solutions Germany GmbH"


def test_bsi_report_without_cert_id_yields_only_the_lab(bsi_parser: BSIFrontpageParser, frontpage_dir: Path):
    # The portal files some ANSSI reports under DE
    items = bsi_parser.parse(frontpage_dir / "pdftotext" / "anssi_report_2012_fr.txt")

    assert items == {constants.TAG_CERT_LAB: "BSI", constants.TAG_PARSE_STRATEGY: "text"}

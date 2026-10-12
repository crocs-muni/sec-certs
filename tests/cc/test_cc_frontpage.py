from collections.abc import Generator
from importlib.resources import as_file, files
from pathlib import Path

import pytest
import tests.data.cc.frontpage

from sec_certs import constants
from sec_certs.utils.frontpage import CanadaFrontpageParser, NSCIBFrontpageParser


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
    """Docling breaks ``NSCIB-2400046-01`` after the hyphen; the break must not reach the value."""
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
        # No legal form to anchor on, and the house number is glued to the city name.
        ("Entrust Minneapolis1187 Park Place Shakopee, MN 55379 USA", "Entrust"),
        ("Brightsight", "Brightsight"),
    ],
)
def test_nscib_organisation_trimmed_off_merged_address(nscib_parser: NSCIBFrontpageParser, merged: str, expected: str):
    assert nscib_parser._organisation_of(merged) == expected


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
    """Docling sometimes merges the label, the organization and its address into one block."""
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
    """EUCC-era reports title the frontpage "EUCC Certification Report"."""
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
    """
    The older template carries a reference line that ends with the title anchor
    ("NSCIB-CC-05-6609 Certification Report"). Taking it for the title makes the letterhead
    that follows it the product name, so only a plain word may prefix the anchor.
    """
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
    constants.TAG_REPORT_DATE: "23 October 2018",
}

CANADA_MCAFEE_HERCULES_EXPECTED = {
    constants.TAG_CERT_ID: "383-4-88-CR",
    constants.TAG_CERT_LAB: "CANADA",
    constants.TAG_CERT_ITEM: "McAfee® Hercules® Policy Auditor v4.5 and McAfee® Hercules® Remediation Manager v4.5",
    constants.TAG_REPORT_DATE: "11 April 2008",
}

CANADA_NETAPP_EXPECTED = {
    constants.TAG_CERT_ID: "383-4-263-CR",
    constants.TAG_CERT_LAB: "CANADA",
    constants.TAG_CERT_ITEM: "NetApp Clustered Data ONTAP® 8.2.1",
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
    """The same fields must come out of pdftotext plain text and Docling JSON alike."""
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
    """
    A third, older report template where the certification id and date swap places relative to the
    other two fixtures (id before date here, after it in canada_report_thycotic) -- guards that the
    product-name cut point checks both, not just whichever came first in the other samples.
    """
    items = canada_parser.parse(frontpage_dir / "pdftotext" / "canada_report_mcafee.txt")

    assert items[constants.TAG_CERT_ID] == "383-4-396"
    assert items[constants.TAG_CERT_LAB] == "CANADA"
    assert items[constants.TAG_CERT_ITEM] == (
        "McAfee Threat Intelligence Exchange 2.0.0 and Data Exchange Layer 3.0.0 with ePolicy Orchestrator 5.3.2"
    )
    assert items[constants.TAG_REPORT_DATE] == "30 November 2016"


def test_canada_structured_developer(canada_parser: CanadaFrontpageParser, frontpage_dir: Path):
    items = canada_parser.parse(
        frontpage_dir / "docling" / "canada_report_dell.txt", frontpage_dir / "docling" / "canada_report_dell.json"
    )

    assert items.pop(constants.TAG_PARSE_STRATEGY) == "structured"
    assert items == {
        constants.TAG_CERT_ID: "383-4-480",
        constants.TAG_CERT_LAB: "CANADA",
        constants.TAG_CERT_ITEM: "Dell EMC™ Isilon with OneFS v8.2.0.0",
        constants.TAG_DEVELOPER: "Dell EMC",
        constants.TAG_REPORT_DATE: "31 January 2020",
    }


def test_canada_text_keeps_developer_in_cert_item(canada_parser: CanadaFrontpageParser, frontpage_dir: Path):
    """Known limitation: pdftotext can't tell the developer line from a wrapped product name."""
    items = canada_parser.parse(frontpage_dir / "pdftotext" / "canada_report_dell.txt")

    assert items[constants.TAG_CERT_ITEM] == "Dell EMC™ Isilon with OneFS v8.2.0.0 Dell EMC"
    assert constants.TAG_DEVELOPER not in items


def test_canada_docling_markdown_lacks_frontpage_content(canada_parser: CanadaFrontpageParser, frontpage_dir: Path):
    """
    Documents a real converter limitation rather than papering over it.

    Docling's markdown export drops the frontpage banner (certification id, product name) for
    this scheme's report layout entirely -- it isn't reachable from `save_as_markdown` output, only
    from the full serialized JSON document. Since `DoclingConverter.convert` always writes both
    files, this only affects the text-only fallback path, not real extraction.
    """
    items = canada_parser.parse(frontpage_dir / "docling" / "canada_report_hsl.txt")

    assert items == {}


def test_canada_non_report_yields_nothing(canada_parser: CanadaFrontpageParser, tmp_path: Path):
    not_a_report = tmp_path / "empty.txt"
    not_a_report.write_text("Lorem ipsum dolor sit amet.\n", encoding="utf-8")

    assert canada_parser.parse(not_a_report) == {}

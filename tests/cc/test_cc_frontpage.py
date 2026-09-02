from collections.abc import Generator
from importlib.resources import as_file, files
from pathlib import Path

import pytest
import tests.data.cc.frontpage

from sec_certs import constants
from sec_certs.utils.frontpage import NSCIBFrontpageParser


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
    ],
)
def test_nscib_organisation_trimmed_off_merged_address(nscib_parser: NSCIBFrontpageParser, merged: str, expected: str):
    assert nscib_parser._organisation_of(merged) == expected


def test_nscib_spaced_dash_in_certified_item_is_kept(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    report = tmp_path / "dash.txt"
    report.write_text(
        "Certification Report\nAcme SecureCore - Crypto Edition\nReport number: NSCIB-CC-2400099-01-CR\n",
        encoding="utf-8",
    )

    items = nscib_parser.parse(report)

    assert items[constants.TAG_CERT_ITEM] == "Acme SecureCore - Crypto Edition"


def test_nscib_non_report_yields_nothing(nscib_parser: NSCIBFrontpageParser, tmp_path: Path):
    not_a_report = tmp_path / "empty.txt"
    not_a_report.write_text("Lorem ipsum dolor sit amet.\n", encoding="utf-8")

    assert nscib_parser.parse(not_a_report) == {}

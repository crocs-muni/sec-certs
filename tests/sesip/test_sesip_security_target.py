"""Tests of reading from a SESIP Security Target: keywords, template sections and claimed SFRs"""

import json
from importlib.resources import files
from pathlib import Path

import pytest
import tests.data.sesip.security_target
import tests.data.sesip.sts_json

from sec_certs.cert_rules import sesip_rules
from sec_certs.converter import has_docling
from sec_certs.document.base import BlockKind, DocumentBlock, DocumentView
from sec_certs.document.plaintext import PlainTextView
from sec_certs.sample.sesip import SESIPCertificate, _st_claimed_sfrs, _st_sections
from sec_certs.utils.extract import extract_keywords

STS_JSON = files(tests.data.sesip.sts_json)
KEYWORDS = json.loads((files(tests.data.sesip.security_target) / "keywords.json").read_text(encoding="utf-8"))
REAL_STS = json.loads((STS_JSON / "expected.json").read_text(encoding="utf-8"))
docling_only = pytest.mark.skipif(not has_docling, reason="docling is not installed")


class FakeView(DocumentView):
    """A document made of headings and paragraphs"""

    def __init__(self, *blocks: tuple[str, str]):
        self.blocks = [DocumentBlock(BlockKind(kind), text) for kind, text in blocks]

    @property
    def artifact_path(self) -> Path:
        return Path("fake")

    def get_full_text(self, layers=None) -> str:
        return "\n".join(block.text for block in self.blocks)

    def iter_blocks(self, layers=None):
        yield from self.blocks


def H(text: str) -> tuple[str, str]:
    return "heading", text


def T(text: str) -> tuple[str, str]:
    return "text", text


def keywords(tmp_path, text: str) -> dict | None:
    (tmp_path / "st.txt").write_text(text)
    return extract_keywords(PlainTextView(tmp_path / "st.txt"), sesip_rules)


def claimed(*blocks) -> set[str] | None:
    view = FakeView(*blocks)
    return _st_claimed_sfrs(view, _st_sections(view))


@pytest.mark.parametrize("case", KEYWORDS["groups"], ids=[case["group"] for case in KEYWORDS["groups"]])
def test_keyword_groups_added_for_sesip(tmp_path, case):
    found = keywords(tmp_path, case["text"])[case["group"]]
    assert {sub: sorted(found.get(sub, {})) for sub in case["expect"]} == case["expect"], case.get("why")


@pytest.mark.parametrize("case", KEYWORDS["sfr_names"], ids=[case["text"][:40] for case in KEYWORDS["sfr_names"]])
def test_sfr_names(tmp_path, case):
    found = keywords(tmp_path, case["text"])["sesip_sfr"]
    assert sorted(sfr for category in found.values() for sfr in category) == case["expect"], case.get("why")


def test_sections_are_found_by_name_not_by_number():
    old = _st_sections(FakeView(H("1.2 Platform references"), H("3.2 Security functional requirements (SFRs)")))
    new = _st_sections(
        FakeView(
            H("1.2 SESIP Profile Reference"), H("1.3 Platform Reference"), H("D.4.2 Security Functional Requirements")
        )
    )
    assert old == {
        "platform_reference": "1.2 Platform references",
        "sfr": "3.2 Security functional requirements (SFRs)",
    }
    assert (
        new["platform_reference"] == "1.3 Platform Reference" and new["sfr"] == "D.4.2 Security Functional Requirements"
    )
    assert _st_sections(FakeView(T("4 Mapping and sufficiency rationales"))) == {
        "rationales": "4 Mapping and sufficiency rationales"
    }
    noise = FakeView(
        T("The security objectives are listed below."), H("1 " + "Introduction " * 10), H("NXP Semiconductors")
    )
    assert _st_sections(noise) is None


def test_first_heading_wins_but_sfrs_are_taken_inside_the_requirements():
    headings = [H("3.3 Security Functional Requirements"), H("3.3.1 Base SP Security Functional Requirements")]
    assert _st_sections(FakeView(*headings))["sfr"] == "3.3 Security Functional Requirements"
    # five real STs repeat the heading
    overview = [H("1.4 Base SP Security Functional Requirements"), H("3 Security Requirements and Implementation")]
    assert _st_sections(FakeView(*overview, *headings))["sfr"] == "3.3 Security Functional Requirements"


@pytest.mark.parametrize(
    "heading, key",
    [
        ("1.2 SESIP Profile Reference", "profile_reference"),
        ("1.2 Protection Profile reference and conformance claims", "profile_reference"),
        ("1.2 Profile and conformance claims", "profile_reference"),
        ("1.2 Conformance claims", "profile_reference"),
        ("1.3.1 RED conformance claim", None),  # the radio directive, two real STs
        ("1.3 Other conformance claims", None),
        ("1.1 ST reference", "st_reference"),
        ("5.1 Test reference", None),
    ],
)
def test_reference_headings(heading, key):
    assert _st_sections(FakeView(H(heading))) == ({key: heading} if key else None)


def test_claimed_sfrs_are_the_headings_of_the_sfr_section():
    assert claimed(
        H("3 Security Requirements and Implementation"),
        H("3.2 Security Functional Requirements"),
        H("3.2.1 Verification  of  Platform Identity"),  # docling keeps double spaces
        T("1. Primary boot"),  # item of list does not end the section
        H("3.2.2 Secure Initialization of Platform"),
        H("3.3 Optional Security Functional Requirements"),
        H("3.3.1 Secure Debugging"),
        H("4 Mapping and Sufficiency Rationales"),
        H("4.1 Cryptographic Operation"),
    ) == {"verification_of_platform_identity", "secure_initialization_of_platform", "secure_debugging"}
    assert claimed(H("3.2 Security Functional Requirements"), H("3.2.1 Secure Debugging"), H("3.3 Flaw Reporting")) == {
        "secure_debugging"
    }
    unnumbered = [H("Mapping and sufficiency rationales"), H("3.2.2 Cryptographic Operation")]
    assert claimed(H("3.2 Security Functional Requirements"), H("3.2.1 Secure Debugging"), *unnumbered) == {
        "secure_debugging"
    }
    assert claimed(H("1 Introduction")) is None
    assert claimed(H("3.2 Security Functional Requirements"), H("4 Mapping and Sufficiency Rationales")) is None


def test_sibling_chapters_with_sfrs_stay_in_the_section():
    # SESIP-2300165-01, -2400006-01, -2500167-01 split the SFRs into chapters 3.2 to 3.7
    assert claimed(
        H("3 Security requirements and implementation"),
        H("3.2 Base PP Security Functional Requirements"),
        H("3.2.1 Secure Debugging"),
        H("3.5 Optional Security Functional Requirement"),
        H("3.5.1 Secure External Storage"),
        H("3.6 Product Life Cycle"),
        H("3.6.1 Field Return of Platform"),
        H("4 Mapping and sufficiency rationales"),
    ) == {"secure_debugging", "secure_external_storage", "field_return_of_platform"}
    # sibling chapter without SFRs ends it
    sfr = [H("3.2 Security Functional Requirements"), H("3.2.1 Secure Debugging")]
    assert claimed(*sfr, H("3.3 TOE Summary"), H("3.3.1 Design")) == {"secure_debugging"}
    assert claimed(*sfr, H("5 TOE Summary Specification"), H("5.1 Cryptographic Operation")) == {"secure_debugging"}
    assert claimed(*sfr, H("3.3 Product Life Cycle")) == {"secure_debugging"}


def test_sfr_with_a_non_conformance_rationale_is_not_claimed():
    assert claimed(
        H("3.2 Security Functional Requirements"),
        H("3.2.1 Secure Update of Platform"),
        T("The platform can be updated to a newer version in the field."),
        H("Nonconformance rationale:"),
        T("The platform does not include any firmware component."),
        H("3.2.2 Cryptographic Operation"),
        H("Conformance rationale:"),
        H("3.2.3 Secure Debugging"),
        T("Non-conformance rationale"),
    ) == {"cryptographic_operation"}


@pytest.mark.docling
@docling_only
@pytest.mark.parametrize("cert_id", sorted(REAL_STS))
def test_real_security_targets(cert_id):
    from sec_certs.document.docling import DoclingView

    view, expected = DoclingView(STS_JSON / f"{cert_id}.json"), REAL_STS[cert_id]
    sections = _st_sections(view)
    assert {"st_reference", "platform_reference", "guidance", "sar", "flaw_reporting", "rationales"} < set(sections)
    assert ("profile_reference" in sections) is expected["has_profile_reference"], "optional, shifts the numbering"
    assert sections["sfr"] == expected["sfr"]
    assert sorted(_st_claimed_sfrs(view, sections)) == expected["claimed"]


def st_cert(tmp_path) -> SESIPCertificate:
    cert = SESIPCertificate(SESIPCertificate.IndexData(cert_id="SESIP-2500125-01", product="P"))
    cert.set_local_paths(tmp_path / "cert", tmp_path / "st")
    cert.state.st.download_ok = cert.state.st.convert_ok = cert.state.st.extract_ok = True
    cert.pdf_data.st_sections, cert.pdf_data.st_claimed_sfrs = {"stale": "x"}, {"stale"}
    return cert


def test_certificate_gets_sections_and_claimed_sfrs(tmp_path, monkeypatch):
    view = FakeView(H("3.2 Security Functional Requirements"), H("3.2.1 Secure Debugging"))
    monkeypatch.setattr("sec_certs.sample.sesip.get_view", lambda doc: view)
    cert = SESIPCertificate.extract_st_sections(st_cert(tmp_path))
    assert cert.pdf_data.st_sections == {"sfr": "3.2 Security Functional Requirements"}
    assert cert.pdf_data.st_claimed_sfrs == {"secure_debugging"} and cert.state.st.extract_ok is True
    untouched = st_cert(tmp_path)
    untouched.state.st.convert_ok = False
    assert SESIPCertificate.extract_st_sections(untouched).pdf_data.st_sections == {"stale": "x"}


@pytest.mark.parametrize("error", [FileNotFoundError("no json"), ValueError("no path"), IndexError("broken table")])
def test_any_error_fails_only_this_security_target(tmp_path, monkeypatch, caplog, error):
    def broken(doc):
        raise error

    monkeypatch.setattr("sec_certs.sample.sesip.get_view", broken)
    cert = SESIPCertificate.extract_st_sections(st_cert(tmp_path))
    assert cert.pdf_data.st_sections is None and cert.pdf_data.st_claimed_sfrs is None
    assert cert.state.st.extract_ok is False and "failed to read the sections" in caplog.text

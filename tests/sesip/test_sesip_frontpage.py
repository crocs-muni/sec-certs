"""Tests of the SESIP certificate frontpage parser"""

import json
from importlib.resources import files

import pytest
import tests.data.sesip.frontpage

from sec_certs.configuration import config
from sec_certs.sample.sesip import SESIPCertificate
from sec_certs.utils.frontpage import parse_sesip_frontpage

FRONTPAGE = files(tests.data.sesip.frontpage)
EXPECTED = json.loads((FRONTPAGE / "expected.json").read_text(encoding="utf-8"))
PHRASES = json.loads((FRONTPAGE / "phrases.json").read_text(encoding="utf-8"))
TEMPLATE = (
    "Certificate ID SESIP-2400006-01 Product TrustCB B.V. declares that Foo Chip of Bar B.V. complies to the "
    "requirements described in Standard GP_FST_070, Public Release v1.2 ... Summarised: SESIP2 with Physical Attacker "
    "Resistance As evaluated by: Riscure B.V. Under scheme: SESIP As described in TrustCB Scheme Procedures v2.3 "
    "Validity Date of issue: 2024-04-02 Date of expiry: 2026-03-28"
)
PARSED = {
    "cert_id": "SESIP-2400006-01",
    "assurance_level": "SESIP2",
    "issue_date": "2024-04-02",
    "expiry_date": "2026-03-28",
    "cert_item": "Foo Chip",
    "developer": "Bar B.V.",
    "cert_lab": "Riscure B.V.",
    "augmentations": "Physical Attacker Resistance",
    "sesip_profile": None,
    "st_reference": None,
    "standard": "GP_FST_070 v1.2",
    "scheme_version": "v2.3",
}


def test_template_certificate():
    assert parse_sesip_frontpage(TEMPLATE) == PARSED


@pytest.mark.parametrize("text", ["", "Lorem ipsum dolor sit amet", "Product Foo Sponsor Bar B.V. Facility Riscure"])
def test_text_without_the_phrases_gives_all_none(text):
    assert parse_sesip_frontpage(text) == dict.fromkeys(PARSED)


@pytest.mark.parametrize("fixture", sorted(EXPECTED))
def test_real_certificates(fixture):
    parsed = parse_sesip_frontpage((FRONTPAGE / f"{fixture}.txt").read_text(encoding="utf-8"))
    assert {key: parsed[key] for key in EXPECTED[fixture]} == EXPECTED[fixture]


@pytest.mark.parametrize("case", PHRASES, ids=[" ".join(case["expect"]) for case in PHRASES])
def test_phrases(case):
    parsed = parse_sesip_frontpage(case["text"])
    assert {key: parsed[key] for key in case["expect"]} == case["expect"], case.get("why")


def test_markdown_table_from_docling_txt():
    text = """| Certificate ID SESIP-2400006-01 | TrustCB B.V. declares that |
|----------------------------------|----------------------------|
| Product          | Foo Chip |
|                  | of |
| Sponsor          | Bar B.V. |
|                  | complies to |
| Evaluation Facility | As evaluated by: Riscure B.V. |"""
    parsed = parse_sesip_frontpage(text)
    assert all(parsed[key] == PARSED[key] for key in ("cert_id", "cert_item", "developer", "cert_lab"))


def test_certificate_gets_its_frontpage(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "pdf_converter", "pdftotext")
    cert = SESIPCertificate(SESIPCertificate.IndexData(cert_id="SESIP-2400006-01", product="Foo"))
    cert.set_local_paths(tmp_path / "cert", tmp_path / "st")
    cert.state.cert.txt_path.parent.mkdir(parents=True)
    cert.state.cert.txt_path.write_text(TEMPLATE)
    cert.state.cert.download_ok = cert.state.cert.convert_ok = cert.state.cert.extract_ok = True
    assert SESIPCertificate.extract_cert_frontpage(cert).pdf_data.cert_frontpage == PARSED
    cert.state.cert.txt_path.write_bytes(b"\xff\xfe\x00garbage")
    SESIPCertificate.extract_cert_frontpage(cert)
    assert cert.pdf_data.cert_frontpage == dict.fromkeys(PARSED), "unreadable text is not a failure"
    assert cert.state.cert.extract_ok is True
    cert.state.cert.txt_path.unlink()
    SESIPCertificate.extract_cert_frontpage(cert)
    assert cert.pdf_data.cert_frontpage is None and cert.state.cert.extract_ok is False

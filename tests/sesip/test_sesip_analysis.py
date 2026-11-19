"""Tests of the SESIP heuristics: lab, status, certificate versions, SESIP profiles and PSA levels
profile_versions.json holds every profile text of the certificates
"""

import json
import re
from datetime import date, timedelta
from importlib.resources import files
from pathlib import Path

import pytest
import tests.data.sesip.analysis

from sec_certs.dataset.sesip import SESIPDataset
from sec_certs.sample import sesip
from sec_certs.sample.sesip import SESIP_PROFILES, SESIPCertificate, SESIPProfile

KNOWN_TEXTS = json.loads((files(tests.data.sesip.analysis) / "profile_versions.json").read_text(encoding="utf-8"))
KNOWN_TEXTS |= json.loads((files(tests.data.sesip.analysis) / "profile_variants.json").read_text(encoding="utf-8"))
MCU, PSA2, PSA3 = "Secure MCUs and MPUs", "PSA Certified Level 2", "PSA Certified Level 3"
ROT3, ISE4 = "PSA Certified RoT Component Level 3", "PSA Certified Level 4 iSE/SE"
ISE3 = "PSA Certified Level 3 iSE/SE + RoT Component"
PSA_SCOPES = ("psa_whole", "rot_component", "ise_se_or_rot_component")


def make_cert(frontpage: dict | None = None, **index) -> SESIPCertificate:
    cert = SESIPCertificate(SESIPCertificate.IndexData(**{"cert_id": "SESIP-2400001-01", "product": "P"} | index))
    cert.pdf_data.cert_frontpage = frontpage
    return cert


def profiles_in(text: str | None) -> dict[str, str | None] | None:
    """family -> 'version release' of the profiles found in the frontpage text"""
    cert = make_cert({"sesip_profile": text})
    cert.heuristics.sesip_profiles = {SESIPProfile("stale")}
    cert.compute_heuristics_sesip_profiles()
    if cert.heuristics.sesip_profiles is None:
        return None
    return {p.family: " ".join(x for x in (p.version, p.release) if x) or None for p in cert.heuristics.sesip_profiles}


@pytest.mark.parametrize(
    "evaluator, frontpage_lab, expected",
    [
        ("SGS Brightsight B.V.", None, ["SGS Brightsight"]),
        ("Keysight-Riscure B.V.", None, ["Keysight-Riscure"]),  # new owner, kept apart from Riscure
        ("SGS Brightsight", "Riscure B.V. located in Delft", ["SGS Brightsight"]),  # the table wins
        (None, "Brightsight B.V.", ["Brightsight"]),
        (None, None, None),
    ],
)
def test_cert_lab(evaluator, frontpage_lab, expected):
    cert = make_cert({"cert_lab": frontpage_lab}, evaluator=evaluator)
    cert.heuristics.cert_lab = ["stale"]
    cert.compute_heuristics_cert_lab()
    assert cert.heuristics.cert_lab == expected


TOMORROW, TODAY = ((date.today() + timedelta(days=days)).isoformat() for days in (1, 0))


@pytest.mark.parametrize(
    "product, table_status, expiry, expected",
    [
        ("P", None, TOMORROW, "active"),
        ("P", "Issued", TODAY, "archived"),  # same rule as EUCC
        ("P", "TERMINATED", TOMORROW, "terminated"),
        ("Withdrawn (2022-01-18)", None, TOMORROW, "withdrawn"),
        ("P", None, None, None),
        ("P", None, "2026-13-45", None),
    ],
)
def test_status(product, table_status, expiry, expected):
    cert = make_cert({"expiry_date": expiry}, product=product, status=table_status)
    cert.heuristics.status = "stale"
    cert.compute_heuristics_status()
    assert cert.heuristics.status == expected


def test_certificate_versions():
    dataset = SESIPDataset()
    for cert_id in ("SESIP-2300031-03", "SESIP-2300031-01", "SESIP-2300031-02", "SESIP-2200040-01.1", "SESIP-XYZ"):
        cert = make_cert(cert_id=cert_id)
        dataset.certs[cert.dgst] = cert
    dataset._compute_cert_versions()
    links = {c.cert_id: (c.heuristics.prev_certificates, c.heuristics.next_certificates) for c in dataset}
    assert links["SESIP-2300031-02"] == (["SESIP-2300031-01"], ["SESIP-2300031-03"])
    assert links["SESIP-2300031-03"] == (["SESIP-2300031-01", "SESIP-2300031-02"], [])
    assert links["SESIP-2200040-01.1"] == links["SESIP-XYZ"] == ([], []), "a reissue .1 is not a version"


@pytest.mark.parametrize("text", sorted(KNOWN_TEXTS))
def test_profiles_of_every_known_text(text):
    assert profiles_in(text) == (KNOWN_TEXTS[text] or None)


@pytest.mark.parametrize(
    "text, expected, logged",
    [
        (None, None, False),
        ("Nos SESIP!", None, True),  # OCR of the certification mark
        (
            f"SESIP Profile for {MCU} version 1.0 SESIP Profile for PSA Certified RoT Component Level v1.0",
            {MCU: "1.0"},
            True,
        ),
        (f"SESIP Profile for {MCU} version 1.0 SESIP Profile for {PSA3} V1.0", {MCU: "1.0", PSA3: "1.0"}, False),
    ],
)
def test_unknown_profile_is_logged(caplog, text, expected, logged):
    assert profiles_in(text) == expected
    assert ("unknown SESIP profile" in caplog.text) is logged


def test_profile_catalog_is_well_formed():
    raw = json.loads((Path(sesip.__file__).parent.parent / "sesip_profiles.json").read_text(encoding="utf-8"))
    assert [p["family"] for p in raw] == list(SESIP_PROFILES), "no family twice"
    for entry in raw:
        assert set(entry) == {"family", "pattern", "issuer", "doc_ids", "url", "psa_level", "psa_scope"}
        assert entry["issuer"] in ("GlobalPlatform", "PSA Certified", None)
        assert all(re.fullmatch(r"GP[A-Z]?_[A-Z]{3}_\d{3}|JSADEN\d{3}", doc_id) for doc_id in entry["doc_ids"])
        assert entry["url"] is None or entry["url"].startswith("https://")
        assert (entry["psa_level"] in (2, 3, 4)) is ("PSA" in entry["family"])
        assert entry["psa_scope"] in ((None,) if entry["psa_level"] is None else PSA_SCOPES)


@pytest.mark.parametrize(
    "families, expected",
    [
        ([PSA2], {"psa_whole": 2}),
        ([ROT3], {"rot_component": 3}),  # a building block
        ([MCU, PSA3, ISE3], {"psa_whole": 3, "ise_se_or_rot_component": 3}),  # a chip and its enclave
        ([PSA3, PSA2, ISE4], {"psa_whole": 2, "ise_se_or_rot_component": 4}),  # the lowest, as with EAL
        (["Family renamed since"], None),
        ([], None),
    ],
)
def test_psa_profile_levels(families, expected):
    cert = make_cert()
    cert.heuristics.sesip_profiles = {SESIPProfile(family) for family in families} or None
    cert.heuristics.psa_profile_levels = {"stale": 1}
    cert.compute_heuristics_psa_profile_levels()
    assert cert.heuristics.psa_profile_levels == expected


def test_heuristics_from_an_older_json_load():
    old = {"status": "active", "psa_profile_level": 3, "psa_rot_component_profile_level": None}
    assert SESIPCertificate.Heuristics.from_dict(old) == SESIPCertificate.Heuristics(status="active")


def test_heuristics_on_the_dataset_survive_json(dset):
    first = next(iter(dset))
    first.pdf_data.cert_frontpage = {"sesip_profile": f"Profile for {MCU} v1.0 Profile for {PSA3} v1.0 REL 02"}
    dset.compute_heuristics()
    assert any(c.heuristics.cert_lab for c in dset)
    assert {c.heuristics.status for c in dset} <= {"active", "archived", "withdrawn", "terminated", None}
    assert first.heuristics.sesip_profiles == {SESIPProfile(MCU, "1.0"), SESIPProfile(PSA3, "1.0", "REL 02")}
    assert first.heuristics.psa_profile_levels == {"psa_whole": 3}
    restored = SESIPDataset.from_json(dset.json_path)
    assert all(restored[c.dgst].heuristics == c.heuristics for c in dset)

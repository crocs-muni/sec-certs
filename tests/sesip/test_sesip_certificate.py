"""Tests of SESIP certificate: index row, identity, download, conversion, PDF metadata, JSON"""

import json
from datetime import date

import pytest
import requests
from tests.sesip.conftest import PDF, FakeConverter, write_pdf

from sec_certs.sample.sesip import SESIPCertificate, SESIPProfile
from sec_certs.serialization.json import CustomJSONDecoder, CustomJSONEncoder

ROW = {"product": "Foo", "cert_id": "SESIP-2600030-01", "cert_link": "https://x/c.pdf", "st_link": "https://x/s.pdf"}


def make_cert(tmp_path, **row) -> SESIPCertificate:
    cert = SESIPCertificate.from_index_row(ROW | row)
    cert.set_local_paths(tmp_path / "cert", tmp_path / "st")
    return cert


def test_index_row_becomes_typed_fields(caplog):
    cert = SESIPCertificate.from_index_row(ROW | {"issue_date": "2027-07-26", "status": "", "new_column": "x"})
    assert cert.cert_id == "SESIP-2600030-01" and cert.name == "Foo"
    assert cert.index_data.issue_date == date(2027, 7, 26)
    assert cert.index_data.status is None, "an empty cell is None"
    assert not hasattr(cert.index_data, "new_column")
    assert SESIPCertificate.IndexData.from_dict({"cert_id": "X", "product": "P", "removed_field": 1}).product == "P"
    assert SESIPCertificate.from_index_row(ROW | {"issue_date": "2019-0i-27"}).index_data.issue_date is None
    assert "issue_date" in caplog.text, "a malformed date is logged, not fatal"


def test_dgst_depends_only_on_the_cert_id():
    cert = SESIPCertificate.from_index_row(ROW)
    assert len(cert.dgst) == 16 and set(cert.dgst) <= set("0123456789abcdef")
    assert cert.dgst == SESIPCertificate.from_index_row(ROW | {"product": "Bar", "cert_link": "https://x/new"}).dgst
    assert cert.dgst != SESIPCertificate.from_index_row(ROW | {"cert_id": "SESIP-2600030-02"}).dgst


def test_json_roundtrip_keeps_dates_flags_and_sets():
    cert = SESIPCertificate.from_index_row(ROW | {"issue_date": "2027-07-26"})
    cert.state.cert.download_ok, cert.state.cert.source_hash = True, "deadbeef"
    cert.pdf_data.cert_metadata = {"pdf_hyperlinks": {"https://trustcb.com/"}}
    cert.pdf_data.st_claimed_sfrs = {"secure_debugging", "cryptographic_operation"}
    cert.heuristics.sesip_profiles = {SESIPProfile("Secure MCUs and MPUs", "1.0"), SESIPProfile("ECN")}
    dumped = json.dumps(cert, cls=CustomJSONEncoder)
    back = json.loads(dumped, cls=CustomJSONDecoder)
    assert json.loads(dumped)["dgst"] == cert.dgst
    assert back.index_data == cert.index_data and back.index_data.issue_date == date(2027, 7, 26)
    assert (back.state.cert.download_ok, back.state.cert.source_hash, back.state.st.download_ok) == (
        True,
        "deadbeef",
        False,
    )
    assert back.pdf_data == cert.pdf_data and back.heuristics == cert.heuristics
    assert SESIPCertificate.PdfData.from_dict({}).st_claimed_sfrs is None, "an older JSON still loads"


def test_both_documents_are_downloaded(tmp_path, portal):
    cert = SESIPCertificate.download_artifacts(make_cert(tmp_path))
    assert cert.state.cert.download_ok and cert.state.st.download_ok
    assert cert.state.cert.source_path.read_bytes() == PDF and cert.state.cert.source_hash
    assert portal[1] == [ROW["cert_link"], ROW["st_link"]]


@pytest.mark.parametrize("link, calls", [("", 0), ("https://x/shared.pdf", 1)])
def test_missing_or_shared_link_gives_no_separate_st(tmp_path, portal, link, calls):
    # withheld certificates = one file is also cert and also ST
    cert = SESIPCertificate.download_artifacts(make_cert(tmp_path, cert_link=link, st_link=link))
    assert len(portal[1]) == calls
    assert cert.has_separate_st is False and cert.state.st.download_ok is False
    assert cert.state.cert.download_ok is bool(link)


def test_failed_redownload_keeps_the_hash_and_the_conversion(tmp_path, portal):
    codes, _ = portal
    cert = SESIPCertificate.download_artifacts(make_cert(tmp_path))
    good_hash, cert.state.cert.convert_ok = cert.state.cert.source_hash, True
    codes[ROW["cert_link"]] = requests.codes.not_found
    SESIPCertificate.download_artifacts(cert)
    assert cert.state.cert.download_ok is False and cert.state.cert.source_hash == good_hash
    codes.clear()
    SESIPCertificate.download_artifacts(cert, fresh=False)
    assert cert.state.cert.download_ok and cert.state.cert.convert_ok, "the same file is not converted again"


def test_conversion_sets_hashes_and_resets_extraction(tmp_path):
    cert = make_cert(tmp_path)
    for doc, body in ((cert.state.cert, PDF), (cert.state.st, b"%PDF FAIL")):
        doc.source_path.parent.mkdir(parents=True)
        doc.source_path.write_bytes(body)
        doc.download_ok = doc.extract_ok = True
    SESIPCertificate.convert_documents(cert, FakeConverter())
    assert cert.state.cert.convert_ok and cert.state.cert.txt_hash and cert.state.cert.json_hash
    assert cert.state.cert.extract_ok is False, "new text, the old extracted data no longer belong to it"
    assert cert.state.st.convert_ok is False and cert.state.st.txt_hash is None


def test_pdf_metadata_and_a_broken_pdf(tmp_path):
    cert = make_cert(tmp_path)
    write_pdf(cert.state.cert.source_path, "Certificate")
    cert.state.st.source_path.parent.mkdir(parents=True)
    cert.state.st.source_path.write_bytes(b"%PDF-1.7\ntruncated")
    for doc in (cert.state.cert, cert.state.st):
        doc.download_ok = doc.convert_ok = doc.extract_ok = True
    cert.pdf_data.st_metadata = {"stale": 1}
    SESIPCertificate.extract_documents_metadata(cert)
    assert cert.pdf_data.cert_metadata["/Title"] == "Certificate"
    assert cert.pdf_data.cert_metadata["pdf_number_of_pages"] == 1
    assert (cert.state.cert.extract_ok, cert.state.st.extract_ok) == (True, False)
    assert cert.pdf_data.st_metadata is None, "a failed document drops its old value"

"""Tests of SESIPDataset: TrustCB table, download, conversion, extraction and JSON"""

import logging
import re
import shutil
from dataclasses import fields
from importlib.resources import files

import pytest
import requests
import tests.data.sesip.sts_json
from tests.sesip.conftest import INDEX_TABLE, FakeConverter

from sec_certs.configuration import config
from sec_certs.constants import SESIP_INDEX_URL
from sec_certs.converter import has_docling
from sec_certs.dataset.sesip import SESIPDataset
from sec_certs.sample.sesip import SESIPCertificate

PAGE = INDEX_TABLE.read_text(encoding="utf-8")
NXP, WITHHELD, TERMINATED, WITHDRAWN = "SESIP-2600030-01", "SESIP-2600048-01", "SESIP-2100003-01", "SESIP-2000021-01"


def test_index_table_is_parsed_into_rows():
    rows = SESIPDataset._parse_index_table(PAGE)
    ids = [row["cert_id"] for row in rows]
    assert len(rows) == len(set(ids)) == 8
    assert all(set(row) == {f.name for f in fields(SESIPCertificate.IndexData)} for row in rows)
    assert all(re.fullmatch(r"SESIP-\d{7}-\d{2}(\.\d+)?", cert_id) for cert_id in ids)
    assert "SESIP-2200040-01.1" in ids, "an amended certificate keeps its dotted suffix"
    rows = dict(zip(ids, rows))
    assert rows[NXP]["developer"] == "NXP Semiconductors GmbH", "<br> inside a cell is a space"
    assert rows[NXP]["cert_link"] == "https://trustcb.com/download/?wpdmdl=6710", "href, not the button text"
    assert rows[WITHHELD]["product"] == "Details withheld"
    assert rows[WITHHELD]["cert_link"] == rows[WITHHELD]["st_link"]
    assert rows[TERMINATED]["status"] == "TERMINATED"
    assert rows[TERMINATED]["cert_link"] == "", "a policy page is not a certificate link"
    assert rows[WITHDRAWN]["status"] == "" and rows[WITHDRAWN]["product"].startswith("Withdrawn")


@pytest.mark.parametrize(
    "page, error",
    [
        (PAGE.replace(">Compliance<", ">Assurance<"), "Compliance"),
        ("<html><body>no table here</body></html>", "no wpDataTable"),
    ],
)
def test_changed_page_is_rejected(page, error):
    with pytest.raises(ValueError, match=error):
        SESIPDataset._parse_index_table(page)


def test_bad_rows_are_skipped_not_fatal(dset):
    with_summary = PAGE.replace("<tbody>", "<tbody><tr><td colspan=10>Total: 9</td></tr>", 1)
    assert len(SESIPDataset._parse_index_table(with_summary)) == 8
    dset.index_path.write_text(PAGE.replace(f">{NXP}<", "><", 1), encoding="utf-8")
    dset.get_certs_from_web(to_download=False)
    assert len(dset) == 7, "a row without cert_id is dropped"


def test_layout_and_lookup(dset, tmp_path):
    cert = dset[NXP]
    assert dset[NXP.lower()] is cert and dset[cert.dgst] is cert
    assert cert.state.st.source_path == tmp_path / "certs" / "st" / "pdf" / f"{cert.dgst}.pdf"
    assert dset.index_path == tmp_path / "web" / "sesip_certificates.html"
    assert SESIPDataset().cert_dir is None
    with pytest.raises(KeyError, match="SESIP-0000000-00"):
        dset["SESIP-0000000-00"]


def test_index_is_downloaded_and_results_are_carried_over(tmp_path, portal):
    dataset = SESIPDataset(root_dir=tmp_path)
    with pytest.raises(ValueError, match="No index"):
        dataset.get_certs_from_web(to_download=False)
    dataset.get_certs_from_web()
    assert len(dataset) == 8 and dataset.state.meta_sources_parsed
    dataset[NXP].pdf_data.cert_metadata = {"marker": "kept"}
    dataset.get_certs_from_web(carry_processing_results=True, keep_metadata=False)
    assert dataset[NXP].pdf_data.cert_metadata == {"marker": "kept"}
    assert not dataset.web_dir.exists()
    portal[0][SESIP_INDEX_URL] = requests.codes.service_unavailable
    with pytest.raises(ValueError, match="Could not download"):
        dataset.get_certs_from_web()


def test_download_all_artifacts(dset, portal):
    _, calls = portal
    dset.download_all_artifacts()
    assert sorted(c.cert_id for c in dset if not c.state.cert.download_ok) == sorted([WITHDRAWN, TERMINATED])
    assert calls.count(dset[WITHHELD].index_data.cert_link) == 1, "a shared link is fetched once"
    assert dset[WITHHELD].state.st.download_ok is False
    assert dset[NXP].state.cert.source_path.exists() and dset.state.artifacts_downloaded
    assert SESIPDataset.from_json(dset.json_path)[NXP].state.cert.download_ok is True
    calls.clear()
    dset.download_all_artifacts(fresh=False)
    assert len(calls) <= 1, "only what failed is tried again"


def test_convert_all_pdfs(converted):
    for cert in converted:
        cert.state.cert.convert_ok = cert.state.st.convert_ok = False
    converted[NXP].state.st.source_path.write_bytes(b"%PDF-1.7\nFAIL\n")
    converted.state.pdfs_converted = False
    converted.convert_all_pdfs(FakeConverter)
    for cert in converted:
        assert cert.state.cert.convert_ok is cert.state.cert.download_ok
    nxp = converted[NXP]
    assert nxp.state.cert.txt_path.read_text().startswith("text of") and nxp.state.cert.txt_hash
    assert nxp.state.st.convert_ok is False and nxp.state.st.txt_hash is None
    assert converted[WITHHELD].state.st.convert_ok is False, "there is no separate ST"
    assert converted.state.pdfs_converted
    assert SESIPDataset.from_json(converted.json_path)[NXP].state.cert.convert_ok is True


def test_extract_data_fills_and_keeps_every_step(converted):
    converted.extract_data()
    for cert in converted:
        if cert.state.cert.convert_ok:
            assert cert.pdf_data.cert_metadata["/Title"] == f"cert {cert.cert_id}", "lost in a worker process?"
            assert cert.pdf_data.cert_frontpage["cert_id"] == cert.cert_id
            assert cert.state.cert.extract_ok is True
        else:
            assert cert.pdf_data.cert_metadata is None and cert.state.cert.extract_ok is False
        if cert.has_separate_st:
            assert cert.pdf_data.st_keywords["cc_sar"]["AVA"]["AVA_VAN.3"] == 1
            assert "secure_update_of_platform" in cert.pdf_data.st_keywords["sesip_sfr"]["lifecycle"]
        else:
            assert cert.pdf_data.st_keywords is None
    converted.to_json()
    restored = SESIPDataset.from_json(converted.json_path)
    assert all(restored[c.dgst].pdf_data == c.pdf_data for c in converted)


DAMAGE = {
    "broken ST pdf": ("st", lambda cert: cert.state.st.source_path.write_bytes(b"%PDF-1.7 truncated")),
    "missing ST text": ("st", lambda cert: cert.state.st.txt_path.unlink()),
    "ST without a path": ("st", lambda cert: setattr(cert.state.st, "txt_path", None)),
    "missing cert text": ("cert", lambda cert: cert.state.cert.txt_path.unlink()),
}


@pytest.mark.parametrize("damage", DAMAGE)
def test_one_broken_document_fails_alone(converted, damage):
    broken, action = DAMAGE[damage]
    converted[NXP].pdf_data.st_keywords = converted[NXP].pdf_data.cert_frontpage = {"stale": 1}
    action(converted[NXP])
    converted.extract_data()
    victim = converted[NXP]
    assert (victim.state.cert.extract_ok, victim.state.st.extract_ok) == (broken != "cert", broken != "st")
    assert victim.pdf_data.cert_frontpage != {"stale": 1} and victim.pdf_data.st_keywords != {"stale": 1}
    assert all(c.state.cert.extract_ok for c in converted if c.state.cert.convert_ok and c.cert_id != NXP)


def test_retry_pass_touches_only_failed_documents(converted, caplog):
    converted.extract_data()
    done, failed = [c for c in converted if c.has_separate_st][:2]
    done.pdf_data.cert_metadata = {"marker": "kept"}
    failed.state.st.extract_ok, failed.pdf_data.st_metadata = False, None
    converted.extract_data(fresh=False)
    assert converted[done.dgst].pdf_data.cert_metadata == {"marker": "kept"}
    assert converted[failed.dgst].pdf_data.st_metadata["/Title"] == f"st {failed.cert_id}"
    with caplog.at_level(logging.INFO):
        converted.extract_data(fresh=False)
    assert "No documents need extraction" in caplog.text
    with pytest.raises(ValueError, match="backed"):
        SESIPDataset().extract_data()


def test_pdftotext_skips_the_st_structure_and_drops_stale_values(converted, caplog):
    redone, kept = [c for c in converted if c.has_separate_st][:2]
    for cert in (redone, kept):
        cert.pdf_data.st_sections, cert.pdf_data.st_claimed_sfrs = {"stale": "x"}, {"stale"}
    kept.state.st.convert_ok = False
    converted.extract_data()
    assert "Skipping ST sections" in caplog.text
    assert (
        converted[redone.dgst].pdf_data.st_sections is None and converted[redone.dgst].pdf_data.st_claimed_sfrs is None
    )
    assert converted[kept.dgst].pdf_data.st_sections == {"stale": "x"}, "an ST that is not processed keeps its value"


@pytest.mark.docling
@pytest.mark.skipif(not has_docling, reason="docling is not installed")
def test_extract_data_reads_the_st_structure_with_docling(converted, monkeypatch):
    monkeypatch.setattr(config, "pdf_converter", "docling")
    for cert in converted:
        cert.state.cert.convert_ok = False
        cert.state.st.convert_ok = cert.cert_id == NXP
    st = converted[NXP].state.st
    st.json_path.parent.mkdir(parents=True)
    shutil.copy(files(tests.data.sesip.sts_json) / "SESIP-2500183-01.json", st.json_path)
    converted.extract_data()
    converted.to_json()
    pdf_data = SESIPDataset.from_json(converted.json_path)[NXP].pdf_data
    assert pdf_data.st_sections["sfr"] == "3.2 Security functional requirements (SFRs)"
    assert len(pdf_data.st_claimed_sfrs) == 8 and "secure_update_of_platform" not in pdf_data.st_claimed_sfrs
    assert "secure_update_of_platform" in pdf_data.st_keywords["sesip_sfr"]["lifecycle"], "mentioned, not claimed"

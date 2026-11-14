"""Shared fixtures of the SESIP tests."""

from importlib.resources import files
from pathlib import Path

import pytest
import requests
import tests.data.sesip.dataset
from pypdf import PdfWriter

from sec_certs.configuration import config
from sec_certs.constants import SESIP_INDEX_URL
from sec_certs.dataset.sesip import SESIPDataset

INDEX_TABLE = files(tests.data.sesip.dataset) / "index_table.html"
PDF = b"%PDF-1.7\nfake\n"
FRONTPAGE = "Certificate ID {} Validity Date of issue: 2024-04-02 Date of expiry: 2026-03-28"
ST_TEXT = "The platform uses AES with CBC mode. Secure Update of Platform. ALC_FLR.2, AVA_VAN.3."


@pytest.fixture(autouse=True)
def no_progress_bar_sleep(monkeypatch):
    monkeypatch.setattr("sec_certs.utils.parallel_processing.time.sleep", lambda _: None)


class FakeConverter:
    """Runs in another process, so the PDF content is its only input."""

    HAS_JSON_OUTPUT = True

    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path) -> bool:
        if b"FAIL" in pdf_path.read_bytes():
            return False
        txt_path.write_text(f"text of {pdf_path.name}")
        json_path.write_text("{}")
        return True


@pytest.fixture
def portal(monkeypatch) -> tuple[dict[str, int], list[str]]:
    """Fake TrustCB: codes[url] is the answer (200 if not set), calls records every request."""
    codes: dict[str, int] = {}
    calls: list[str] = []

    def download(url, output, *args, **kwargs):
        calls.append(url)
        if (code := codes.get(url, requests.codes.ok)) == requests.codes.ok:
            output.write_bytes(INDEX_TABLE.read_bytes() if url == SESIP_INDEX_URL else PDF)
        return code

    monkeypatch.setattr("sec_certs.utils.helpers.download_file", download)
    return codes, calls


@pytest.fixture
def dset(tmp_path) -> SESIPDataset:
    """The 8 certificates of the saved TrustCB table, nothing downloaded."""
    dataset = SESIPDataset(root_dir=tmp_path)
    dataset.web_dir.mkdir(parents=True)
    dataset.index_path.write_bytes(INDEX_TABLE.read_bytes())
    dataset.get_certs_from_web(to_download=False)
    return dataset


def write_pdf(path: Path, title: str) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.add_metadata({"/Title": title})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        writer.write(handle)


@pytest.fixture
def converted(dset, monkeypatch) -> SESIPDataset:
    """Every linked document has a PDF and its text, as after pdftotext."""
    monkeypatch.setattr(config, "pdf_converter", "pdftotext")
    for cert in dset:
        wanted = ((cert.state.cert, bool(cert.index_data.cert_link)), (cert.state.st, cert.has_separate_st))
        for doc, linked in wanted:
            if linked:
                write_pdf(doc.source_path, f"{'st' if doc is cert.state.st else 'cert'} {cert.cert_id}")
                doc.txt_path.parent.mkdir(parents=True, exist_ok=True)
                doc.txt_path.write_text(ST_TEXT if doc is cert.state.st else FRONTPAGE.format(cert.cert_id))
                doc.download_ok = doc.convert_ok = True
    dset.state.artifacts_downloaded = dset.state.pdfs_converted = True
    return dset

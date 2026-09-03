from __future__ import annotations

from typing import TYPE_CHECKING

from sec_certs.configuration import config

if TYPE_CHECKING:
    from sec_certs.document.base import DocumentView
    from sec_certs.sample.document_state import DocumentState


def get_view(state: DocumentState) -> DocumentView:
    if config.pdf_converter == "pdftotext":
        from sec_certs.document.plaintext import PlainTextView

        return PlainTextView(state.txt_path)

    if config.pdf_converter == "docling":
        try:
            from sec_certs.document.docling import DoclingView
        except ImportError as e:
            raise ImportError(
                "Attempting to use the Docling document view, but docling is not installed. "
                "Install it using 'uv sync --extra docling' or 'pip install -e .[docling]'"
            ) from e

        return DoclingView(state.json_path)

    raise ValueError(f"Unknown PDF converter configured: {config.pdf_converter}")

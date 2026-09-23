from __future__ import annotations

from typing import TYPE_CHECKING

from sec_certs.configuration import config
from sec_certs.converter import has_docling, has_pdftotext

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter


def get_converter_cls() -> type[PDFConverter]:
    if config.pdf_converter == "pdftotext":
        # This shouldn't happen since pdftotext is in default deps.
        if not has_pdftotext:
            raise ImportError("Attempting to use pdftotext converter, but pdftotext is not installed.")

        from sec_certs.converter import PdftotextConverter

        return PdftotextConverter

    if config.pdf_converter == "docling":
        if not has_docling:
            raise ImportError(
                "Attempting to use Docling converter, but docling is not installed. "
                "Install it using 'uv sync --extra docling' or 'pip install -e .[docling]'"
            )

        from sec_certs.converter import DoclingConverter

        return DoclingConverter

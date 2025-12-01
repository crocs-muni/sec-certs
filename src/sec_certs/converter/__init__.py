import logging

from sec_certs.converter.base import PDFConverter

logger = logging.getLogger(__name__)

__all__ = ["PDFConverter"]
has_pdftotext: bool = False
has_docling: bool = False

try:
    from sec_certs.converter.pdftotext import PdftotextConverter  # noqa: F401

    __all__.append("PdftotextConverter")
    has_pdftotext = True

except ImportError:
    pass

try:
    from sec_certs.converter.docling import DoclingConverter  # noqa: F401

    __all__.append("DoclingConverter")
    has_docling = True

except ImportError:
    pass


def __getattr__(name):
    if name == "DoclingConverter" and not has_docling:
        raise ImportError(
            "Attempting to use Docling converter, but docling is not installed. "
            "Install it using 'uv sync --extra docling' or 'pip install -e .[docling]'"
        )

    if name == "PdftotextConverter" and not has_pdftotext:
        raise ImportError("Attempting to use pdftotext converter, but pdftotext is not installed.")

    raise ImportError(f"cannot import name f{name!r} from {__name__!r}")

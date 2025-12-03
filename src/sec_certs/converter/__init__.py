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

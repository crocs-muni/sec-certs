from sec_certs.converter.base import PDFConverter

__all__ = ["PDFConverter"]
has_pdftotext: bool = False
has_docling: bool = False

try:
    from sec_certs.converter.pdftotext import PdftotextConverter

    __all__ = ["PdftotextConverter"]
    has_pdftotext = True
except ImportError:
    pass

try:
    from sec_certs.converter.docling import DoclingConverter

    __all__ = ["DoclingConverter"]
    has_docling = True
except ImportError:
    pass

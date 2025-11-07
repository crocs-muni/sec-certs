from .base import PDFConverter

__all__ = ["PDFConverter"]
has_pdftotext: bool = False
has_docling: bool = False

try:
    from .pdftotext import PdftotextConverter

    __all__ = ["PdftotextConverter"]
    has_pdftotext = True
except ImportError:
    pass

try:
    from .docling import DoclingConverter

    __all__ = ["DoclingConverter"]
    has_docling = True
except ImportError:
    pass

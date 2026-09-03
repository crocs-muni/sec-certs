from __future__ import annotations

import logging
from pathlib import Path

from sec_certs.constants import LINE_SEPARATOR
from sec_certs.document.base import DocumentLayer, DocumentView
from sec_certs.utils.extract import load_text_file

logger = logging.getLogger(__name__)


class PlainTextView(DocumentView):
    def __init__(self, txt_path: Path, line_separator: str = LINE_SEPARATOR):
        self.txt_path = txt_path
        self.line_separator = line_separator

    @property
    def artifact_path(self) -> Path:
        return self.txt_path

    def get_full_text(self, layers: set[DocumentLayer] | None = None) -> str:
        if layers is not None and layers != set(DocumentLayer):
            logger.info(
                f"{type(self).__name__} has no notion of layers, "
                f"returning the whole text of {self} regardless of the requested layers."
            )

        whole_text, _, _ = load_text_file(self.txt_path, -1, self.line_separator)
        return whole_text

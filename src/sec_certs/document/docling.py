from __future__ import annotations

import logging
import sys
from functools import cached_property
from pathlib import Path

from docling_core.transforms.serializer.markdown import MarkdownTableSerializer
from docling_core.transforms.serializer.plain_text import (
    PlainTextDocSerializer,
    PlainTextParams,
)
from docling_core.types.doc.common.content_layer import ContentLayer
from docling_core.types.doc.document import DoclingDocument
from typing_extensions import override

from sec_certs.document.base import DocumentLayer, DocumentView

logger = logging.getLogger(__name__)


class CustomTableSerializer(MarkdownTableSerializer):
    @override
    @staticmethod
    def _compact_table(table_text: str) -> str:
        lines = table_text.split("\n")
        compact_lines = []

        for i, line in enumerate(lines):
            if not line:
                continue

            parts = line.split("|")[1:-1]

            if i == 1:
                continue

            compact_parts = [part.strip() for part in parts]

            compact_lines.append(" ".join(compact_parts))

        return "\n".join(compact_lines)


class DoclingView(DocumentView):
    def __init__(self, json_path: Path):
        self.json_path = json_path

    @property
    def artifact_path(self) -> Path:
        return self.json_path

    @cached_property
    def doc(self) -> DoclingDocument:
        return DoclingDocument.load_from_json(self.json_path)

    def _translate_layers(self, layers: set[DocumentLayer]) -> set[ContentLayer]:
        return {ContentLayer(layer) for layer in layers}

    def get_full_text(self, layers: set[DocumentLayer] | None = None) -> str:
        if layers is None:
            layers = set(DocumentLayer)

        serializer = PlainTextDocSerializer(
            doc=self.doc,
            table_serializer=CustomTableSerializer(),
            params=PlainTextParams(
                layers=self._translate_layers(layers),
                pages=None,
                start_idx=0,
                stop_idx=sys.maxsize,
                page_break_placeholder=None,
                traverse_pictures=False,
                compact_tables=True,
            ),
        )
        return serializer.serialize().text

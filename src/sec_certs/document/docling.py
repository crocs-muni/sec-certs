from __future__ import annotations

import logging
import sys
from functools import cached_property
from pathlib import Path
from typing import ClassVar

from docling_core.transforms.serializer.markdown import MarkdownTableSerializer
from docling_core.transforms.serializer.plain_text import (
    PlainTextDocSerializer,
    PlainTextParams,
)
from docling_core.types.doc.common.content_layer import ContentLayer
from docling_core.types.doc.document import DoclingDocument, NodeItem, TableCell, TableItem
from docling_core.types.doc.items.table.table_data import RichTableCell
from docling_core.types.doc.labels import DocItemLabel
from typing_extensions import override

from sec_certs.document.base import DocumentLayer, DocumentTable, DocumentView
from sec_certs.document.stitch import PageSpan, TableFragment, stitch_fragments

logger = logging.getLogger(__name__)

"""Labels that never count as content separating two fragments of the same table."""
_NON_BLOCKING_LABELS = {
    DocItemLabel.CAPTION,
    DocItemLabel.PAGE_HEADER,
    DocItemLabel.PAGE_FOOTER,
    DocItemLabel.FOOTNOTE,
}


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
    supports_tables: ClassVar[bool] = True

    def __init__(self, json_path: Path):
        self.json_path = json_path

    @property
    def artifact_path(self) -> Path:
        return self.json_path

    @cached_property
    def doc(self) -> DoclingDocument:
        if not self.json_path.is_file():
            raise FileNotFoundError(f"No converted document at {self.json_path}")
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

    @override
    def get_tables(
        self,
        layers: set[DocumentLayer] | None = None,
        pages: set[int] | None = None,
        include_index: bool = False,
        stitch: bool = True,
    ) -> list[DocumentTable]:
        content_layers = self._translate_layers(layers if layers is not None else set(DocumentLayer))
        fragments: list[TableFragment] = []
        blockers: list[PageSpan] = []

        # Body is always walked, even when not requested, because blockers are only meaningful there: the
        # running header and footer of every page would otherwise sit in every gap and block all merges.
        for item, _ in self.doc.iterate_items(included_content_layers=content_layers | {ContentLayer.BODY}):
            if isinstance(item, TableItem) and item.content_layer in content_layers:
                is_index = item.label == DocItemLabel.DOCUMENT_INDEX
                if include_index or not is_index:
                    fragments.append(self._to_fragment(item, is_index))
                    continue
            if item.content_layer is ContentLayer.BODY and getattr(item, "label", None) not in _NON_BLOCKING_LABELS:
                blockers.extend(self._page_spans(item))

        tables = stitch_fragments(fragments, blockers) if stitch else [fragment.table for fragment in fragments]

        # Filtered after stitching, so that asking for one page of a table still yields the whole table.
        if pages is not None:
            tables = [table for table in tables if pages.intersection(table.pages)]
        return tables

    def _to_fragment(self, item: TableItem, is_index: bool) -> TableFragment:
        grid = item.data.grid
        n_header = self._count_header_rows(grid)
        spans = self._page_spans(item)
        table = DocumentTable(
            rows=self._cells(grid[n_header:]),
            header=self._cells(grid[:n_header]),
            caption=item.caption_text(self.doc).strip() or None,
            pages=tuple(sorted({span.page for span in spans})),
            is_index=is_index,
            layer=self._translate_layer_back(item.content_layer),
        )
        # A fragment is compared as a tail by where it starts and as a head by where it ends, which differ
        # when the backend reports provenance for more than one page.
        return TableFragment(
            table=table,
            span=min(spans, key=lambda s: (s.page, s.top)) if spans else None,
            last_span=max(spans, key=lambda s: (s.page, s.bottom)) if spans else None,
        )

    def _cells(self, rows: list[list[TableCell]]) -> tuple[tuple[str, ...], ...]:
        return tuple(tuple(self._cell_text(cell) for cell in row) for row in rows)

    def _cell_text(self, cell: TableCell) -> str:
        # A rich cell holds a reference to a document node rather than plain text; its own `text` may be
        # empty, and resolving it without the document yields a placeholder comment.
        if isinstance(cell, RichTableCell):
            resolved = cell.ref.resolve(self.doc)
            return getattr(resolved, "text", "") or cell.text
        return cell.text

    @staticmethod
    def _count_header_rows(grid: list[list[TableCell]]) -> int:
        """
        Leading rows that hold any header cell, matching how Docling itself splits header from body.

        Always leaves at least one body row: a fragment whose every row is flagged as a header is a
        misclassification, and treating it as header-only would hide its contents from every consumer.
        """
        n = 0
        for row in grid:
            if not any(cell.column_header for cell in row):
                break
            n += 1
        return min(n, max(len(grid) - 1, 0))

    @staticmethod
    def _translate_layer_back(layer: ContentLayer) -> DocumentLayer:
        try:
            return DocumentLayer(layer.value)
        except ValueError:
            # Docling knows layers we do not model, e.g. background or invisible content.
            return DocumentLayer.BODY

    def _page_spans(self, item: NodeItem) -> list[PageSpan]:
        spans = []
        for prov in getattr(item, "prov", None) or []:
            page = self.doc.pages.get(prov.page_no)
            height = page.size.height if page and page.size else None
            if not height:
                continue
            bbox = prov.bbox.to_top_left_origin(height)
            spans.append(PageSpan(page=prov.page_no, top=bbox.t / height, bottom=bbox.b / height))
        return spans

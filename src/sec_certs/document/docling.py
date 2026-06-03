from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from docling_core.types.doc.document import (
    ContentLayer,
    DoclingDocument,
    SectionHeaderItem,
    TableItem,
    TextItem,
)

from sec_certs.document.segment import DocumentSegment

_LAYERS = {ContentLayer.BODY, ContentLayer.FURNITURE}


def iter_docling_segments(doc: DoclingDocument) -> Iterator[DocumentSegment]:
    section_stack: list[tuple[int, str]] = []
    for item, _ in doc.iterate_items(included_content_layers=_LAYERS):
        if isinstance(item, SectionHeaderItem):
            while section_stack and section_stack[-1][0] >= item.level:
                section_stack.pop()

        section_path = tuple(t for _, t in section_stack)
        if isinstance(item, TableItem):
            for cell in item.data.table_cells:
                yield DocumentSegment(
                    text=cell.text,
                    label="table_cell",
                    section_path=section_path,
                    page=item.prov[0].page_no,
                    layer=str(item.content_layer),
                    table_id=item.self_ref,
                    table_coord=(cell.start_row_offset_idx, cell.start_col_offset_idx),
                )
        elif isinstance(item, TextItem):
            yield DocumentSegment(
                text=item.text,
                label=str(item.label),
                section_path=section_path,
                page=item.prov[0].page_no,
                layer=str(item.content_layer),
            )

        if isinstance(item, SectionHeaderItem):
            section_stack.append((item.level, item.text))


def iter_segments_from_json(path: Path) -> Iterator[DocumentSegment]:
    doc = DoclingDocument.load_from_json(path)
    yield from iter_docling_segments(doc)

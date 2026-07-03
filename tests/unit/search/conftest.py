from datetime import datetime

import pytest
from tantivy import Document, Index, Schema


def _add(doc: Document, field: str, value) -> None:
    if isinstance(value, datetime):
        doc.add_date(field, value)
    elif isinstance(value, bool):
        doc.add_boolean(field, value)
    elif isinstance(value, int):
        doc.add_integer(field, value)
    elif isinstance(value, float):
        doc.add_float(field, value)
    else:
        doc.add_text(field, value)


@pytest.fixture
def make_index():
    def _make(schema: Schema, docs: list[dict]) -> Index:
        index = Index(schema)
        writer = index.writer()
        for doc in docs:
            d = Document()
            for field, value in doc.items():
                if value is None:
                    continue
                if isinstance(value, (list, tuple)):
                    for item in value:
                        _add(d, field, item)
                else:
                    _add(d, field, value)
            writer.add_document(d)
        writer.commit()
        index.reload()
        return index

    return _make


@pytest.fixture
def hits():
    def _hits(index: Index, query, id_field: str = "dgst", limit: int = 20) -> set:
        searcher = index.searcher()
        result = searcher.search(query, limit=limit)
        return {searcher.doc(addr)[id_field][0] for _, addr in result.hits}

    return _hits

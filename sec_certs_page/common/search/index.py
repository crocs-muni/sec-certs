from pathlib import Path

from tantivy import Schema, Index
from flask import current_app


def get_index(schema: Schema, name: str) -> Index:
    index_path = Path(current_app.instance_path) / current_app.config["SEARCH_INDEX_PATH"] / name
    index_path.mkdir(exist_ok=True, parents=True)
    try:
        return Index(schema, str(index_path), reuse=True)
    except ValueError:
        try:
            return Index(schema, str(index_path), reuse=False)
        except ValueError as e:
            raise RuntimeError(f"Failed to create search index at {index_path}: {e}")

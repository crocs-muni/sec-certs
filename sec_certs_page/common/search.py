from pathlib import Path

from flask import current_app
from whoosh.fields import ID, STORED, TEXT, Schema
from whoosh.index import Index, create_in, open_dir

index_schema = Schema(
    dgst=ID(stored=True),  # The certificate dgst
    name=TEXT(stored=True),  # The certificate name
    type=STORED,  # The type of document (one of "report", "target")
    cert_schema=STORED,  # The certification scheme (one of "cc", "fips", maybe "pp" in the future)
    content=TEXT,  # The document content
)


def create_index() -> Index:
    index_path = Path(current_app.instance_path) / current_app.config["WHOOSH_INDEX_PATH"]
    index_path.mkdir(exist_ok=True, parents=True)
    return create_in(index_path, schema=index_schema)


def get_index() -> Index:
    index_path = Path(current_app.instance_path) / current_app.config["WHOOSH_INDEX_PATH"]
    return open_dir(index_path, schema=index_schema)

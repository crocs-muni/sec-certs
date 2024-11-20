from pathlib import Path

from flask import current_app
from whoosh.analysis import StandardAnalyzer
from whoosh.fields import ID, KEYWORD, TEXT, Schema
from whoosh.index import Index, create_in, open_dir

index_schema = Schema(
    dgst=ID(stored=True, unique=True),  # The certificate dgst
    name=TEXT(stored=True),  # The certificate name
    document_type=KEYWORD(stored=True, unique=True),  # The type of document (one of "report", "target")
    cert_schema=KEYWORD(
        stored=True, unique=True
    ),  # The certification scheme (one of "cc", "fips", maybe "pp" in the future)
    category=KEYWORD(stored=True),
    status=KEYWORD(stored=True),
    scheme=KEYWORD(stored=True),  # Only CC: The issuing scheme
    content=TEXT(analyzer=StandardAnalyzer(minsize=1)),  # The document content
)


def create_index() -> Index:
    index_path = Path(current_app.instance_path) / current_app.config["WHOOSH_INDEX_PATH"]
    index_path.mkdir(exist_ok=True, parents=True)
    return create_in(index_path, schema=index_schema)


def get_index() -> Index:
    index_path = Path(current_app.instance_path) / current_app.config["WHOOSH_INDEX_PATH"]
    return open_dir(index_path, schema=index_schema)

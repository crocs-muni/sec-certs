from pathlib import Path

from flask import current_app
from whoosh.fields import ID, KEYWORD, TEXT, Schema
from whoosh.index import Index, create_in, open_dir

from .analyzer import FancyAnalyzer

index_schema = Schema(
    # The certificate dgst
    dgst=ID(stored=True, unique=False),
    # The certificate name
    name=TEXT(stored=True, analyzer=FancyAnalyzer()),
    # The type of document (one of "report", "target" or "cert")
    document_type=KEYWORD(stored=True, unique=False),
    # The certificate ID
    cert_id=TEXT(stored=True, analyzer=FancyAnalyzer()),
    # The certification scheme (one of "cc", "fips", maybe "pp" in the future)
    cert_schema=KEYWORD(stored=True, unique=False),
    # The certificate category, mapped to a single letter, the mappings differ for CC and FIPS.
    category=KEYWORD(stored=True, unique=False),
    # The certificate status.
    status=KEYWORD(stored=True, unique=False),
    # Only CC: The issuing scheme
    scheme=KEYWORD(stored=True, unique=False),
    # The document content
    content=TEXT(analyzer=FancyAnalyzer()),
)


def create_index() -> Index:
    index_path = Path(current_app.instance_path) / current_app.config["WHOOSH_INDEX_PATH"]
    index_path.mkdir(exist_ok=True, parents=True)
    return create_in(index_path, schema=index_schema)


def get_index() -> Index:
    index_path = Path(current_app.instance_path) / current_app.config["WHOOSH_INDEX_PATH"]
    return open_dir(index_path, schema=index_schema)

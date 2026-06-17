import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from tantivy import Document, Index

from ... import mongo
from ..views import entry_file_path

logger = logging.getLogger(__name__)


class Indexer(ABC):  # pragma: no cover
    """
    Base class for reindexing Tantivy documents for a given certificate schema.

    The subclasses should specify the attributes.
    """

    dataset_path: Path
    cert_schema: str
    index: Index
    doc_types: list[str]

    @abstractmethod
    def create_document(self, dgst: str, cert: dict[str, Any], content: dict[str, str]) -> Document:
        """Create a Tantivy document for the given certificate and its body texts."""
        ...

    def reindex(self, to_reindex):
        logger.info(f"Reindexing {len(to_reindex)} {self.cert_schema} files.")
        updated = 0

        writer = self.index.writer()
        for i, dgst in enumerate(to_reindex):
            content = {}
            for doc_type in self.doc_types:
                fpath = entry_file_path(dgst, self.dataset_path, doc_type, "txt")
                doc_content = ""
                try:
                    with fpath.open("r") as f:
                        doc_content = f.read()
                except FileNotFoundError:
                    pass

                content[doc_type] = doc_content

            cert = mongo.db[self.cert_schema].find_one({"_id": dgst})
            writer.delete_documents_by_term("dgst", dgst)
            writer.add_document(self.create_document(dgst, cert, content))
            updated += 1
            if i % 100 == 0:
                logger.info(f"{i}: updated {updated}.")

        writer.commit()
        writer.wait_merging_threads()
        logger.info(f"Reindexed {updated} out of {len(to_reindex)} {self.cert_schema} files.")

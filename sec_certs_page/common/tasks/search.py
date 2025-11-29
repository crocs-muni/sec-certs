import logging
from abc import abstractmethod
from pathlib import Path
from typing import Any

from ... import mongo, whoosh_index
from ..views import entry_file_path

logger = logging.getLogger(__name__)


class Indexer:  # pragma: no cover
    """
    Base class for reindexing Whoosh documents for a given certificate schema.

    The subclasses should specify the attributes.
    """

    dataset_path: Path
    cert_schema: str

    @abstractmethod
    def create_document(self, dgst: str, document: str, cert: dict[str, Any], content: str):
        """Create a Whoosh document from the given parameters."""
        ...

    def reindex(self, to_reindex):
        logger.info(f"Reindexing {len(to_reindex)} {self.cert_schema} files.")
        updated = 0
        with whoosh_index.writer() as writer, writer.searcher() as searcher:
            for i, (dgst, document_type) in enumerate(to_reindex):
                fpath = entry_file_path(dgst, self.dataset_path, document_type, "txt")
                try:
                    with fpath.open("r") as f:
                        content = f.read()
                except FileNotFoundError:
                    continue
                cert = mongo.db[self.cert_schema].find_one({"_id": dgst})
                docid = searcher.document_number(dgst=dgst, document_type=document_type)
                if docid is not None:
                    writer.delete_document(docid)
                writer.add_document(**self.create_document(dgst, document_type, cert, content))
                updated += 1
                if i % 100 == 0:
                    logger.info(f"{i}: updated {updated}.")
        logger.info(f"Reindexed {updated} out of {len(to_reindex)} {self.cert_schema} files.")

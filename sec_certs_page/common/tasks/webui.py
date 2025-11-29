import logging
from pathlib import Path
from typing import Optional, Set, Tuple

from flask import current_app
from tqdm import tqdm

from ..ai.webui import (
    add_file_to_knowledge_base,
    get_file_metadata,
    get_knowledge_base,
    update_file_data_content,
    update_file_in_knowledge_base,
    upload_file,
)
from ..views import entry_file_path

logger = logging.getLogger(__name__)


class KBUpdater:  # pragma: no cover
    """
    WebUI Knowledge Base Updater

    The attributes should be set by the subclasses.
    """

    collection: str
    dataset_path: Path

    def _load_kb(self, kbid: str) -> dict[str, Tuple[str, int, Optional[str]]]:
        """
        Load a knowledge base file map.

        Returns a map of filename -> (file_id, updated_at, collection_name)

        :param kbid: Knowledge base ID
        :return: File map
        """
        if kbid is None:
            return {}
        kb = get_knowledge_base(kbid)
        fmap: dict[str, Tuple[str, int, Optional[str]]] = {}
        if not kb:
            return fmap
        for file in kb["files"]:
            id = file["id"]
            name = file["meta"]["name"]
            collection = file["meta"].get("collection_name")
            updated = file["updated_at"]
            fmap[name] = (id, updated, collection)
        return fmap

    def update(self, to_update: Set[Tuple[str, str, Optional[str]]]):
        coll = self.collection.upper()
        reports_kbid = current_app.config.get(f"WEBUI_COLLECTION_{coll}_REPORTS", None)
        targets_kbid = current_app.config.get(f"WEBUI_COLLECTION_{coll}_TARGETS", None)
        reports_fmap = self._load_kb(reports_kbid)
        targets_fmap = self._load_kb(targets_kbid)

        # Go through all files to update
        # The file_id may be None if we don't know it yet
        for digest, document, file_id in tqdm(to_update):
            # Determine which KB and fmap to use
            if document == "report":
                kb = reports_kbid
                fmap = reports_fmap
            elif document == "target":
                kb = targets_kbid
                fmap = targets_fmap
            else:
                raise ValueError(f"Unknown document type for KB update: {document}")

            # We have no knowledge base for this document type
            if kb is None:
                continue

            # Get file contents
            fpath = entry_file_path(digest, self.dataset_path, document, "txt")
            if not fpath.exists() or not fpath.is_file():
                # We have nothing to upload
                continue

            # Check if the file is empty
            stat = fpath.stat()
            if stat.st_size == 0:
                # We have nothing to upload
                continue

            # Check whether we have the file under some id
            name = f"{digest}.txt"
            if name in fmap:
                # First try to get updated_at from the fmap
                file_id, updated_at, collection_name = fmap[name]
            elif file_id is not None:
                # Then try to get it from the server
                meta = get_file_metadata(file_id)
                if meta is None:
                    logger.warning(f"Failed to get file metadata for KB update: {digest}, {fpath} -> {file_id}")
                    file_id = None
                    updated_at = None
                    collection_name = None
                else:
                    updated_at = meta["updated_at"]
                    collection_name = meta["meta"].get("collection_name")
            else:
                # We have no idea about this file
                updated_at = None
                collection_name = None

            if file_id is None:
                # Create a new file
                resp = upload_file(fpath)
                if resp is None:
                    logger.warning(f"Failed to upload file for KB update: {digest}, {fpath} -> {resp}")
                    continue
                # Add it to the kb
                resp = add_file_to_knowledge_base(kb, resp["id"])
                if resp is None:
                    logger.warning(f"Failed to add file to KB: {digest}, {fpath} -> {resp}")
                    continue
            else:
                # There is a file, check if we need to add it to the kb
                if collection_name is None:
                    resp = add_file_to_knowledge_base(kb, file_id)
                    if resp is None:
                        logger.warning(f"Failed to add existing file to KB: {digest}, {fpath} -> {resp}")
                        continue
                mtime = int(stat.st_mtime)
                # Check if the file is old
                if mtime <= updated_at:  # type: ignore
                    # Nothing to do
                    continue
                # Then update the file with new contents
                with fpath.open("rb") as f:
                    resp = update_file_data_content(file_id, f)
                if resp is None:
                    logger.warning(f"Failed to update file content for KB update: {digest}, {fpath} -> {resp}")
                    continue
                # Then trigger also kb update
                resp = update_file_in_knowledge_base(kb, file_id)
                if resp is None:
                    logger.warning(f"Failed to update file in KB: {digest}, {fpath} -> {resp}")
                    continue

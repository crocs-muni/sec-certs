from pathlib import Path

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


class KBUpdater:  # pragma: no cover
    collection: str
    dataset_path: Path

    def _load_kb(self, kbid):
        if kbid is None:
            return {}
        kb = get_knowledge_base(kbid)
        fmap = {}
        if not kb:
            return fmap
        for file in kb["files"]:
            id = file["id"]
            name = file["meta"]["name"]
            updated = file["updated_at"]
            fmap[name] = (id, updated)
        return fmap

    def update(self, to_update):
        coll = self.collection.upper()
        reports_kbid = current_app.config.get(f"WEBUI_COLLECTION_{coll}_REPORTS", None)
        targets_kbid = current_app.config.get(f"WEBUI_COLLECTION_{coll}_TARGETS", None)
        reports_fmap = self._load_kb(reports_kbid)
        targets_fmap = self._load_kb(targets_kbid)

        for digest, document, file_id in tqdm(to_update):
            if document == "report":
                kb = reports_kbid
                fmap = reports_fmap
            elif document == "target":
                kb = targets_kbid
                fmap = targets_fmap
            else:
                continue

            # We have no knowledge base for this document type
            if kb is None:
                continue
            # Get file contents
            fpath = entry_file_path(digest, self.dataset_path, document, "txt")
            if not fpath.exists() or not fpath.is_file():
                continue
            # Check if the file is empty
            stat = fpath.stat()
            if stat.st_size == 0:
                continue
            # Check whether we have the file under some id
            name = f"{digest}.txt"
            if name in fmap:
                file_id, updated_at = fmap[name]
            elif file_id is not None:
                meta = get_file_metadata(file_id)
                updated_at = meta["updated_at"]
            else:
                updated_at = None

            if file_id is None:
                # Create a new file
                resp = upload_file(fpath)
                # Add it to the kb
                resp = add_file_to_knowledge_base(kb, resp["id"])
            else:
                mtime = int(stat.st_mtime)
                # Check if the file is already in the KB
                if mtime <= updated_at:
                    continue
                # Then update the file with new contents
                with fpath.open("rb") as f:
                    resp = update_file_data_content(file_id, f)
                # Then trigger also kb update
                resp = update_file_in_knowledge_base(kb, file_id)

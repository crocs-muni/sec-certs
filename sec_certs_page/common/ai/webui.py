import json
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests
from flask import current_app

from ... import cache


def _get_headers():
    return {"Authorization": f"Bearer {current_app.config['WEBUI_KEY']}", "Content-Type": "application/json"}


def _resolve_url(url: str):
    return urljoin(current_app.config["WEBUI_URL"], url)


def get(url: str, query=None):
    """Send a GET request to the WebUI API."""
    response = requests.get(_resolve_url(url), headers=_get_headers(), params=query)
    return response


def post(url: str, data=None, files=None):
    """Send a POST request to the WebUI API."""
    headers = _get_headers()
    full_url = _resolve_url(url)
    if data is not None and files is not None:
        raise ValueError("Cannot send both data and files in the same request.")
    if files is not None:
        headers.pop("Content-Type", None)
        response = requests.post(full_url, headers=headers, files=files)
    elif data is not None:
        response = requests.post(full_url, headers=headers, json=data)
    else:
        response = requests.post(full_url, headers=headers)
    return response


def delete(url: str, query=None):
    """Send a DELETE request to the WebUI API."""
    response = requests.delete(_resolve_url(url), headers=_get_headers(), params=query)
    return response


def upload_file(file_path: str | Path, metadata=None):
    """
    Upload a file to the WebUI API.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L139>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/files.py#L68>'__

    :param file_path: Path to the file to upload.
    :param metadata: Optional metadata dictionary to include with the file.
    :return: Response from the API.
    """
    url = "v1/files/"
    with open(file_path, "rb") as file:
        if metadata is not None:
            data = {"metadata": json.dumps(metadata)}
        else:
            data = None
        response = post(url, files={"file": file}, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def list_files(content: bool = False):
    """
    List all files in the WebUI API.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L281>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/files.py#L68>'__

    :param content: Whether to include file content in the response.
    :return: List of files.
    """
    url = "v1/files/"
    response = get(url, query={"content": str(content).lower()})
    if response.status_code == 200:
        return response.json()
    else:
        return None


def find_file(fname: str, content: bool = False):
    """
    Find files by name in the WebUI API.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L301>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/files.py#L68>'__

    :param fname: Filename to search for (supports wildcards).
    :param content: Whether to include file content in the response.
    :return: List of files matching the filename.
    """
    url = "v1/files/search"
    response = get(url, query={"filename": fname, "content": str(content).lower()})
    if response.status_code == 200:
        return response.json()
    else:
        return None


@cache.memoize(timeout=3600)
def file_map() -> dict[str, list[str]]:
    """
    Get a mapping of filenames to file IDs in the WebUI API.

    .. note::
        This function is cached for 1 hour to improve performance.

    :return: Dictionary mapping filenames to lists of file IDs.
    """
    data = find_file("*.txt")
    result: dict[str, list[str]] = {}
    if not data:
        return result
    for file in data:
        name = file["filename"]
        id = file["id"]
        result.setdefault(name, []).append(id)
    return result


def files_for_hashid(hashid: str) -> list[str]:
    """Map a hashid to file IDs."""
    fmap = file_map()
    if f"{hashid}.txt" not in fmap:
        return []
    else:
        return fmap[f"{hashid}.txt"]


def files_for_knowledge_base(kb_id: str) -> list[dict[str, Any]]:
    """Get file IDs for a knowledge base."""
    data = get_knowledge_base(kb_id)
    if data and "files" in data:
        return data["files"]
    else:
        return []


@cache.memoize(timeout=3600)
def file_metadata(file_id: str) -> Optional[dict[str, Any]]:
    """Get metadata for a file without the actual data content."""
    data = get_file_metadata(file_id)
    if data:
        if "data" in data:
            del data["data"]
        return data
    else:
        return None


def file_name(file_id: str) -> Optional[str]:
    """Get the filename for a file ID."""
    meta = file_metadata(file_id)
    if meta and "filename" in meta:
        return meta["filename"]
    else:
        return None


def file_type(file_id: str, collection: str) -> str:
    """Determine the file type (report/target) for a given file ID and collection."""
    reports_kb = f"WEBUI_COLLECTION_{collection.upper()}_REPORTS"
    targets_kb = f"WEBUI_COLLECTION_{collection.upper()}_TARGETS"
    reports_kbid = current_app.config.get(reports_kb)
    targets_kbid = current_app.config.get(targets_kb)
    meta = file_metadata(file_id)
    if meta["meta"]["collection_name"] == reports_kbid:
        return "report"
    elif meta["meta"]["collection_name"] == targets_kbid:
        return "target"
    raise ValueError("Unknown file type.")


def get_file_metadata(file_id: str) -> Optional[dict[str, Any]]:
    """
    Get metadata for a file.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L370>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/files.py#L36>'__

    :param file_id: The ID of the file.
    :return: Metadata dictionary for the file.
    """
    url = f"v1/files/{file_id}"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_file_content(file_id: str) -> Optional[bytes]:
    """
    Get content for a file.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L528>'__

    :param file_id: The ID of the file.
    :return: Content of the file.
    """
    url = f"v1/files/{file_id}/content"
    response = get(url)
    if response.status_code == 200:
        return response.content
    else:
        return None


def get_file_data_content(file_id: str) -> Optional[dict[str, Any]]:
    """
    Get data content for a file.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L455>'__

    :param file_id: The ID of the file.
    :return: Data content of the file.
    """
    url = f"v1/files/{file_id}/data/content"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def update_file_data_content(file_id: str, file) -> Optional[dict[str, Any]]:
    """
    Upload new data content for a file.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L487>'__

    :param file_id: The ID of the file.
    :param file: File object to upload.
    :return: Response from the API.
    """

    url = f"v1/files/{file_id}/data/content/update"
    response = post(url, files={"file": file})
    if response.status_code == 200:
        return response.json()
    else:
        return None


def remove_file(file_id: str) -> bool:
    """
    Remove a file from the WebUI API.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py#L709>'__

    :param file_id: The ID of the file to remove.
    :return: Whether the removal was successful.
    """
    url = f"v1/files/{file_id}"
    response = delete(url)
    return response.status_code == 200


def get_knowledge_bases() -> Optional[list[dict[str, Any]]]:
    """
    Get a list of knowledge bases.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/knowledge.py#L91>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/knowledge.py#L92>'__

    :return: List of knowledge bases.
    """
    url = "v1/knowledge/list"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_knowledge_base(kb_id: str) -> Optional[dict[str, Any]]:
    """
    Get details of a knowledge base.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/knowledge.py#L268>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/knowledge.py#L88>'__

    :param kb_id: The ID of the knowledge base.
    :return: Details of the knowledge base.
    """
    url = f"v1/knowledge/{kb_id}"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def create_knowledge_base(name: str, description: Optional[str] = None) -> Optional[dict[str, Any]]:
    """
    Create a new knowledge base.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/knowledge.py#L143>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/knowledge.py#L88>'__

    :param name: Name of the knowledge base.
    :param description: Optional description of the knowledge base.
    :return: Details of the created knowledge base.
    """
    url = "v1/knowledge/create"
    data = {"name": name, "description": description}
    response = post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def add_file_to_knowledge_base(kb_id: str, file_id: str):
    """
    Add an existing file to a knowledge base.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/knowledge.py#L360>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/knowledge.py#L88>'__

    :param kb_id: The ID of the knowledge base.
    :param file_id: The ID of the file to add.
    :return: Details of the updated knowledge base.
    """

    url = f"v1/knowledge/{kb_id}/file/add"
    data = {"file_id": file_id}
    response = post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def update_file_in_knowledge_base(kb_id: str, file_id: str) -> Optional[dict[str, Any]]:
    """
    Update a file in a knowledge base.

    This endpoint reprocesses the file and updates its embeddings in the knowledge base.
    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/knowledge.py#L445>'__
    'Response schema <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/knowledge.py#L88>'__

    :param kb_id: The ID of the knowledge base.
    :param file_id: The ID of the file to update.
    :return: Details of the updated knowledge base.
    """
    url = f"v1/knowledge/{kb_id}/file/update"
    data = {"file_id": file_id}
    response = post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def delete_knowledge_base(kb_id: str) -> Optional[bool]:
    """
    Delete a knowledge base.

    'Endpoint <https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/knowledge.py#L611>'__

    :param kb_id: The ID of the knowledge base to delete.
    :return:
    """
    url = f"v1/knowledge/{kb_id}/delete"
    response = post(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def resolve_files(collection: str, hashid: str) -> list[str]:
    """
    Resolve which file types (report/target) are available for a given hashid.

    :param collection: Collection name (e.g., "cc", "fips", "pp").
    :param hashid: Hash ID of the entry.
    :return: List of file types available for the entry.
    """
    files = files_for_hashid(hashid)
    resp = []
    for file in files:
        try:
            resp.append(file_type(file, collection))
        except ValueError:
            # Just eat the error.
            # This means the file is not part of the known knowledge bases.
            # Which means the database may be inconsistent.
            continue
    return resp

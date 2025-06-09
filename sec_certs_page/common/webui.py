import json
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests
from flask import current_app, render_template_string

from .. import cache, mongo
from .objformats import cert_name


def get(url: str, query=None):
    headers = {"Authorization": f"Bearer {current_app.config['WEBUI_KEY']}", "Content-Type": "application/json"}
    response = requests.get(urljoin(current_app.config["WEBUI_URL"], url), headers=headers, params=query)
    return response


def post(url: str, data=None, files=None):
    headers = {"Authorization": f"Bearer {current_app.config['WEBUI_KEY']}", "Content-Type": "application/json"}
    if data is not None and files is not None:
        raise ValueError("Cannot send both data and files in the same request.")
    if files is not None:
        headers.pop("Content-Type", None)
        response = requests.post(urljoin(current_app.config["WEBUI_URL"], url), headers=headers, files=files)
    elif data is not None:
        response = requests.post(urljoin(current_app.config["WEBUI_URL"], url), headers=headers, json=data)
    else:
        response = requests.post(urljoin(current_app.config["WEBUI_URL"], url), headers=headers)
    return response


def upload_file(file_path: str | Path, metadata=None):
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
    url = "v1/files/"
    response = get(url, query={"content": str(content).lower()})
    if response.status_code == 200:
        return response.json()
    else:
        return None


def find_file(fname: str, content: bool = False):
    url = "v1/files/search"
    response = get(url, query={"filename": fname, "content": str(content).lower()})
    if response.status_code == 200:
        return response.json()
    else:
        return None


@cache.memoize(timeout=3600)
def files_for_hashid(hashid: str):
    data = find_file(f"{hashid}.txt")
    return list(map(lambda x: x["id"], data)) if data else []


@cache.memoize(timeout=3600)
def files_for_knowledge_base(kb_id: str):
    data = get_knowledge_base(kb_id)
    if data and "files" in data:
        return data["files"]
    else:
        return []


@cache.memoize(timeout=3600)
def file_metadata(file_id: str):
    data = get_file_metadata(file_id)
    if data:
        if "data" in data:
            del data["data"]
        return data
    else:
        return None


def file_name(file_id: str):
    meta = file_metadata(file_id)
    if meta and "filename" in meta:
        return meta["filename"]
    else:
        return None


def file_type(file_id: str, collection: str):
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


def get_file_metadata(file_id: str):
    url = f"v1/files/{file_id}"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_file_content(file_id: str):
    url = f"v1/files/{file_id}/content"
    response = get(url)
    if response.status_code == 200:
        return response.content
    else:
        return None


def get_file_data_content(file_id: str):
    url = f"v1/files/{file_id}/data/content"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def update_file_data_content(file_id: str, file):
    url = f"v1/files/{file_id}/data/content/update"
    response = post(url, files={"file": file})
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_knowledge_bases():
    url = "v1/knowledge/list"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_knowledge_base(kb_id: str):
    url = f"v1/knowledge/{kb_id}"
    response = get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def create_knowledge_base(name: str, description: Optional[str] = None):
    url = "v1/knowledge/create"
    data = {"name": name, "description": description}
    response = post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def add_file_to_knowledge_base(kb_id: str, file_id: str):
    url = f"v1/knowledge/{kb_id}/file/add"
    data = {"file_id": file_id}
    response = post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def update_file_in_knowledge_base(kb_id: str, file_id: str):
    url = f"v1/knowledge/{kb_id}/file/update"
    data = {"file_id": file_id}
    response = post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def delete_knowledge_base(kb_id: str):
    url = f"v1/knowledge/{kb_id}/delete"
    response = post(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def chat_with_model(queries, system_addition: str = "", kbs: Optional[list] = None, files: Optional[list] = None):
    url = "chat/completions"
    data = {
        "model": current_app.config["WEBUI_MODEL"],
        "messages": [
            {"role": "system", "content": current_app.config["WEBUI_SYSTEM_PROMPT"] + system_addition},
            *queries,
        ],
    }

    file_attr = None
    if kbs is not None:
        file_attr = [{"type": "collection", "id": kb} for kb in kbs]
    if files is not None:
        file_attr = [{"type": "file", "id": file} for file in files]
    if file_attr is not None:
        data["files"] = file_attr
    response = post(url, data)
    return response


def resolve_files(collection: str, hashid: str):
    files = files_for_hashid(hashid)
    resp = []
    for file in files:
        resp.append(file_type(file, collection))
    return resp


def chat_about(
    query: str,
    collection: str,
    hashid: Optional[str] = None,
    about: str = "entry",
):
    files: Optional[list[str]] = None
    kbs: Optional[list[str]] = None
    cert = None
    reports_kb = f"WEBUI_COLLECTION_{collection.upper()}_REPORTS"
    targets_kb = f"WEBUI_COLLECTION_{collection.upper()}_TARGETS"
    reports_kbid = current_app.config.get(reports_kb)
    targets_kbid = current_app.config.get(targets_kb)
    if reports_kbid or targets_kbid:
        kbs = []
        if reports_kbid:
            kbs.append(reports_kbid)
        if targets_kbid:
            kbs.append(targets_kbid)
    if hashid is not None:
        cert = mongo.db[collection].find_one({"_id": hashid})
        if not cert:
            raise ValueError("Invalid hashid.")
        else:
            files = files_for_hashid(hashid)

    if about == "entry":
        if files is None:
            raise ValueError("Missing 'hashid' for entry query.")
        kbs = None
        system_addition = render_template_string(
            current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_CERT", ""), cert_name=cert_name(cert)
        )
    elif about == "collection":
        if kbs is None:
            raise ValueError("Missing knowledge base for collection query.")
        system_addition = current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_ALL", "")
        files = None
    elif about == "both":
        if files is None:
            raise ValueError("Missing 'hashid' for both query.")
        if kbs is None:
            raise ValueError("Missing knowledge base for both query.")
        system_addition = render_template_string(
            current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_BOTH", ""), cert_name=cert_name(cert)
        )
    else:
        raise ValueError("Invalid 'about' value.")

    return chat_with_model(query, system_addition, kbs=kbs, files=files)

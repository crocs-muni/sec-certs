from typing import Optional

import requests
from flask import current_app, render_template_string

from ... import mongo
from ..objformats import cert_name
from ..views import entry_file_path
from .webui import files_for_hashid, post


def chat_with_model(
    model: str, queries, system_addition: str = "", kbs: Optional[list] = None, files: Optional[list] = None
):
    """
    Chat with the model using the WebUI API.

    :param model: Model name.
    :param queries: List of message dictionaries.
    :param system_addition: Additional system prompt content.
    :param kbs: List of knowledge base IDs to use.
    :param files: List of file IDs to use.
    :return: Response from the API.
    """
    url = "chat/completions"
    data = {
        "model": model,
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


def chat_rag(
    queries, model: str, collection: str, hashid: Optional[str] = None, about: str = "entry"
) -> requests.Response:
    """
    Chat with the model using RAG (Retrieval-Augmented Generation).

    :param queries: THe list of message dictionaries.
    :param model: Model name.
    :param collection: Collection name (e.g., "cc", "fips", "pp").
    :param hashid: Certificate hash ID.
    :param about: Whether to do RAG over the "entry" (certificate documents only),
                  the whole "collection" (but not any particular certificate), or "both".
                  For "entry" and "both", a valid hashid must be provided.
                  For "collection", no hashid is needed.
    :return:
    """
    files: Optional[list[str]] = None
    kbs: Optional[list[str]] = None
    cert = None
    if collection not in ("cc", "fips", "pp"):
        raise ValueError("Invalid collection specified.")
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
            raise ValueError("No files available for RAG.")
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
            raise ValueError("No files available for RAG.")
        if kbs is None:
            raise ValueError("Missing knowledge base for both query.")
        system_addition = render_template_string(
            current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_BOTH", ""), cert_name=cert_name(cert)
        )
    else:
        raise ValueError("Invalid 'about' value.")

    return chat_with_model(model, queries, system_addition, kbs=kbs, files=files)


def chat_full(queries, model: str, collection: str, hashid: str, document: str = "both") -> requests.Response:
    if document == "both":
        docs = ["report", "target"]
    elif document in ("report", "target"):
        docs = [document]
    else:
        raise ValueError("Invalid document type specified.")
    doc_map = {}
    for doc in docs:
        fpath = entry_file_path(hashid, current_app.config[f"DATASET_PATH_{collection.upper()}_DIR"], doc, "txt")
        if fpath.exists():
            with fpath.open() as file:
                doc_map[doc] = file.read()
    if not doc_map:
        raise ValueError("No documents found.")
    cert = mongo.db[collection].find_one({"_id": hashid})
    system_addition = render_template_string(
        current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_CERT_FULL"), cert_name=cert_name(cert), **doc_map
    )
    return chat_with_model(model, queries, system_addition)

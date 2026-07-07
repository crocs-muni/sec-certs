import requests
from flask import current_app, render_template_string

from ... import mongo
from ..objformats import cert_name
from ..views import entry_file_path
from .api import post


def chat_with_model(model: str, queries, system_addition: str = ""):
    """
    Chat with the model using the OpenAI API.

    :param model: Model name.
    :param queries: List of message dictionaries.
    :param system_addition: Additional system prompt content.
    :return: Response from the API.
    """
    url = "chat/completions"
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": current_app.config["LLM_SYSTEM_PROMPT"] + system_addition},
            *queries,
        ],
        "stream": True,
    }
    response = post(url, data, stream=True)
    return response


def chat_full(queries, model: str, collection: str, hashid: str, documents: set[str]) -> requests.Response:
    cert = mongo.db[collection].find_one({"_id": hashid})
    if not cert:
        raise ValueError("Invalid hashid.")
    doc_map = {}
    for doc in documents:
        fpath = entry_file_path(hashid, current_app.config[f"DATASET_PATH_{collection.upper()}_DIR"], doc, "txt")
        if fpath.exists():
            with fpath.open() as file:
                doc_map[doc] = file.read()
    system_addition = render_template_string(
        current_app.config.get(f"LLM_PROMPT_{collection.upper()}_CERT"), cert_name=cert_name(cert), **doc_map
    )
    if not doc_map:
        system_addition += current_app.config.get("LLM_PROMPT_NO_DOCS", "")
    return chat_with_model(model, queries, system_addition)

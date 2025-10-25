from functools import wraps

from flask import current_app, request, url_for
from markdown2 import markdown
from nh3 import nh3

from .. import mongo
from ..common.permissions import chat_permission
from ..common.views import accounting
from ..common.webui import chat_full, chat_rag, file_name, file_type, resolve_files
from . import chat


def chat_api(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_app.config["CHAT_ENABLED"]:
            return {"status": "error", "message": "Chat is not enabled."}, 403
        if not chat_permission.can():
            return {"status": "error", "message": "You are not authorized to use the chat."}, 403
        if not request.is_json:
            return {"status": "error", "message": "Request must be JSON."}, 400
        return func(*args, **kwargs)

    return wrapper


@chat.route("/files/", methods=["POST"])
@chat_api
def files():
    """Query which files are available for a given hashid."""
    data = request.get_json()
    if "hashid" not in data:
        return {"status": "error", "message": "Missing 'hashid' in request."}, 400
    if "collection" not in data:
        return {"status": "error", "message": "Missing 'collection' in request."}, 400
    hashid = data["hashid"]
    collection = data["collection"]
    if collection not in ("cc", "fips", "pp"):
        return {"status": "error", "message": "Invalid collection specified."}, 400
    cert = mongo.db[collection].find_one({"_id": hashid})
    if not cert:
        return {"status": "error", "message": "Invalid hashid."}, 404
    try:
        resp = resolve_files(collection, hashid)
    except ValueError as e:
        return {"status": "error", "message": str(e)}, 400
    return {"status": "ok", "files": resp}


@chat.route("/rag/", methods=["POST"])
@chat_api
@accounting("daily", 100, json=True)
def query_rag():
    """Chat with the model."""
    data = request.get_json()
    if "query" not in data:
        return {"status": "error", "message": "Missing 'query' in request."}, 400
    if "about" not in data:
        return {"status": "error", "message": "Missing 'about' in request."}, 400
    if "collection" not in data:
        return {"status": "error", "message": "Missing 'collection' in request."}, 400
    if "model" not in data:
        data["model"] = current_app.config["WEBUI_DEFAULT_MODEL"]

    query = []
    for message in data["query"]:
        if "role" not in message or "content" not in message:
            return {"status": "error", "message": "Invalid query format."}, 400
        if message["role"] not in ("user", "assistant"):
            return {"status": "error", "message": "Invalid role in query."}, 400
        query.append({"role": message["role"], "content": message["content"]})
    collection = data["collection"]
    if collection not in ("cc", "fips", "pp"):
        return {"status": "error", "message": "Invalid collection specified."}, 400
    model = data["model"]
    if model not in current_app.config["WEBUI_MODELS"]:
        return {"status": "error", "message": "Invalid model specified."}, 400

    about = data["about"]
    hashid = data.get("hashid", None)

    try:
        result = chat_rag(query, model, collection, hashid, about)
    except ValueError as e:
        return {"status": "error", "message": str(e)}, 400

    if result.status_code != 200:
        return {"status": "error", "message": "Chat request failed."}, result.status_code
    json = result.json()
    choices = json.get("choices", [])
    if not choices:
        return {"status": "error", "message": "No response from the model."}, 500
    choice = choices[0]
    if "message" not in choice or "content" not in choice["message"]:
        return {"status": "error", "message": "Invalid response format from the model."}, 500
    response = choice["message"]["content"]
    if not response:
        return {"status": "error", "message": "Empty response from the model."}, 500

    rendered = markdown(
        response,
        extras={"cuddled-lists": None, "code-friendly": None, "tables": None, "html-classes": {"table": "table"}},
    )

    def attribute_filter(tag, name, value):
        if tag == "table" and name == "class":
            return "table table-light"
        return None

    cleaned = nh3.clean(rendered, attributes={"table": {"class"}}, attribute_filter=attribute_filter).strip()

    sources = []
    if "sources" in json:
        for source in json["sources"]:
            file_id = source["source"]["id"]
            fname = file_name(file_id)
            ftype = file_type(file_id, collection)
            sources.append(
                {
                    "id": file_id,
                    "name": fname,
                    "type": ftype,
                    "url": url_for(f"{collection}.entry_{ftype}_txt", hashid=hashid),
                }
            )
        for i, source in enumerate(sources):
            tag = f"[{i + 1}]"
            if tag in cleaned:
                cleaned = cleaned.replace(
                    tag,
                    f'<a href="{source["url"]}" target="_blank" title="Model used document.">[{source["type"]}]</a>',
                )

    return {"status": "ok", "response": cleaned, "raw": response, "sources": sources}, 200


@chat.route("/full/", methods=["POST"])
@chat_api
@accounting("daily", 100, json=True)
def query_full():
    """Chat with the model."""
    data = request.get_json()
    if "query" not in data:
        return {"status": "error", "message": "Missing 'query' in request."}, 400
    if "context" not in data:
        return {"status": "error", "message": "Missing 'context' in request."}, 400
    if "collection" not in data:
        return {"status": "error", "message": "Missing 'collection' in request."}, 400
    if "hashid" not in data:
        return {"status": "error", "message": "Missing 'hashid' in request."}, 400
    if "model" not in data:
        data["model"] = current_app.config["WEBUI_DEFAULT_MODEL"]

    query = []
    for message in data["query"]:
        if "role" not in message or "content" not in message:
            return {"status": "error", "message": "Invalid query format."}, 400
        if message["role"] not in ("user", "assistant"):
            return {"status": "error", "message": "Invalid role in query."}, 400
        query.append({"role": message["role"], "content": message["content"]})
    collection = data["collection"]
    if collection not in ("cc", "fips", "pp"):
        return {"status": "error", "message": "Invalid collection specified."}, 400
    model = data["model"]
    if model not in current_app.config["WEBUI_MODELS"]:
        return {"status": "error", "message": "Invalid model specified."}, 400

    hashid = data["hashid"]
    context = data["context"]
    if context not in ("report", "target", "both"):
        return {"status": "error", "message": "Invalid context specified."}, 400

    try:
        result = chat_full(query, model, collection, hashid, context)
    except ValueError as e:
        return {"status": "error", "message": str(e)}, 400

    if result.status_code != 200:
        return {"status": "error", "message": "Chat request failed."}, result.status_code
    json = result.json()
    choices = json.get("choices", [])
    if not choices:
        return {"status": "error", "message": "No response from the model."}, 500
    choice = choices[0]
    if "message" not in choice or "content" not in choice["message"]:
        return {"status": "error", "message": "Invalid response format from the model."}, 500
    response = choice["message"]["content"]
    if not response:
        return {"status": "error", "message": "Empty response from the model."}, 500

    rendered = markdown(
        response,
        extras={"cuddled-lists": None, "code-friendly": None, "tables": None, "html-classes": {"table": "table"}},
    )

    def attribute_filter(tag, name, value):
        if tag == "table" and name == "class":
            return "table table-light"
        return None

    cleaned = nh3.clean(rendered, attributes={"table": {"class"}}, attribute_filter=attribute_filter).strip()

    return {"status": "ok", "response": cleaned, "raw": response, "sources": []}, 200

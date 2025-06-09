from flask import current_app, request, session, url_for
from markdown2 import markdown
from nh3 import nh3

from .. import mongo
from ..common.permissions import admin_permission
from ..common.views import captcha_required
from ..common.webui import chat_about, file_name, file_type, resolve_files
from . import chat


@chat.route("/authorize/", methods=["POST"])
@captcha_required(json=True)
def authorize():
    """Add "chat_authorized=True" to user's session."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    session["chat_authorized"] = True
    return {"status": "ok"}


@chat.route("/authorized/")
def authorized():
    """Check if the user is authorized to chat."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    return {"authorized": session.get("chat_authorized", False)}


@chat.route("/files/", methods=["POST"])
def files():
    """Query which files are available for a given hashid."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    if not admin_permission.can():
        return {"status": "error", "message": "Only admin users can query files."}, 403
    if "chat_authorized" not in session or not session["chat_authorized"]:
        return {"status": "error", "message": "You are not authorized to use the chat."}, 403
    if not request.is_json:
        return {"status": "error", "message": "Request must be JSON."}, 400
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
    resp = resolve_files(collection, hashid)
    return {"status": "ok", "files": resp}


@chat.route("/", methods=["POST"])
def query():
    """Chat with the model."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    if not admin_permission.can():
        return {"status": "error", "message": "Only admin users have chat permissions."}, 403
    if "chat_authorized" not in session or not session["chat_authorized"]:
        return {"status": "error", "message": "You are not authorized to use the chat."}, 403
    if not request.is_json:
        return {"status": "error", "message": "Request must be JSON."}, 400
    data = request.get_json()
    if "query" not in data:
        return {"status": "error", "message": "Missing 'query' in request."}, 400
    if "about" not in data:
        return {"status": "error", "message": "Missing 'about' in request."}, 400
    if "collection" not in data:
        return {"status": "error", "message": "Missing 'collection' in request."}, 400

    collection = data["collection"]
    about = data["about"]
    hashid = data.get("hashid", None)
    if collection not in ("cc", "fips", "pp"):
        return {"status": "error", "message": "Invalid collection specified."}, 400

    try:
        result = chat_about(data["query"], collection, hashid, about)
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
        return {"status": "error", "message": "Invalid response format."}, 500
    response = choice["message"]["content"]
    if not response:
        return {"status": "error", "message": "Empty response from the model."}, 500
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
    rendered = markdown(response, extras={"cuddled-lists": None, "code-friendly": None})
    cleaned = nh3.clean(rendered).strip()
    for i, source in enumerate(sources):
        tag = f"[{i + 1}]"
        if tag in rendered:
            rendered = rendered.replace(
                tag, f'<a href="{source["url"]}" target="_blank" title="Model used document.">[{source["type"]}]</a>'
            )

    return {"status": "ok", "response": cleaned, "raw": response, "sources": sources}, 200

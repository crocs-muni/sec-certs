from flask import current_app, render_template_string, request, session
from markdown2 import markdown
from nh3 import nh3

from .. import mongo
from ..common.objformats import cert_name
from ..common.permissions import admin_permission
from ..common.views import captcha_required
from ..common.webui import chat_with_model, files_for_hashid, files_for_knowledge_base, get_file_metadata
from . import chat


@chat.route("/authorize/", methods=["POST"])
@captcha_required(json=True)
def authorize():
    """Add "chat_authorized=True" to user's session."""
    session["chat_authorized"] = True
    return {"status": "ok"}


@chat.route("/authorized/")
def authorized():
    """Check if the user is authorized to chat."""
    return {"authorized": session.get("chat_authorized", False)}


@chat.route("/files/", methods=["POST"])
def files():
    """Query which files are available for a given hashid."""
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
    files = files_for_hashid(hashid)
    reports_kb = f"WEBUI_COLLECTION_{collection.upper()}_REPORTS"
    targets_kb = f"WEBUI_COLLECTION_{collection.upper()}_TARGETS"
    reports_kbid = current_app.config.get(reports_kb)
    targets_kbid = current_app.config.get(targets_kb)
    resp = []
    for file in files:
        meta = get_file_metadata(file)
        if meta["meta"]["collection_name"] == reports_kbid:
            resp.append("report")
        elif meta["meta"]["collection_name"] == targets_kbid:
            resp.append("target")
    return {"status": "ok", "files": resp}


@chat.route("/", methods=["POST"])
def query():
    """Chat with the model."""
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
    files = None
    kbs = None
    collection = None
    cert = None
    if "collection" in data:
        collection = data["collection"]
        if collection not in ("cc", "fips", "pp"):
            return {"status": "error", "message": "Invalid collection specified."}, 400
        else:
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
            if "hashid" in data:
                hashid = data["hashid"]
                cert = mongo.db[collection].find_one({"_id": hashid})
                if not cert:
                    return {"status": "error", "message": "Invalid hashid."}, 404
                else:
                    files = files_for_hashid(hashid)

    about = data["about"]
    if about == "entry":
        if files is None:
            return {"status": "error", "message": "Missing 'hashid' for entry query."}, 400
        kbs = None
        system_addition = render_template_string(
            current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_CERT", ""), cert_name=cert_name(cert)
        )
    elif about == "collection":
        if kbs is None:
            return {"status": "error", "message": "Missing knowledge base for collection query."}, 400
        system_addition = current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_ALL", "")
        files = None
    elif about == "both":
        if files is None:
            return {"status": "error", "message": "Missing 'hashid' for both query."}, 400
        if kbs is None:
            return {"status": "error", "message": "Missing knowledge base for both query."}, 400
        system_addition = render_template_string(
            current_app.config.get(f"WEBUI_PROMPT_{collection.upper()}_BOTH", ""), cert_name=cert_name(cert)
        )
    else:
        return {"status": "error", "message": "Invalid 'about' value."}, 400

    result = chat_with_model(data["query"], system_addition, kbs=kbs, files=files)
    if result.status_code != 200:
        return {"status": "error", "message": "Chat request failed."}, result.status_code
    choices = result.json().get("choices", [])
    if not choices:
        return {"status": "error", "message": "No response from the model."}, 500
    choice = choices[0]
    if "message" not in choice or "content" not in choice["message"]:
        return {"status": "error", "message": "Invalid response format."}, 500
    response = choice["message"]["content"]
    if not response:
        return {"status": "error", "message": "Empty response from the model."}, 500
    rendered = markdown(response, extras=["cuddled-lists"])
    cleaned = nh3.clean(rendered)
    return {"status": "ok", "response": cleaned, "raw": response}

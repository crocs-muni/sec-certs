from flask import current_app, request, session, url_for
from markdown2 import markdown
from nh3 import nh3
import time
import secrets
import re

from .. import mongo, redis
from ..common.permissions import admin_permission
from ..common.views import captcha_required
from ..common.webui import chat_full, chat_rag, file_name, file_type, resolve_files
from . import chat


# Remove in-memory store for auth tokens (all tokens are in redis)
CHAT_AUTH_TOKEN_LIFETIME = 600  # 10 minutes


@chat.route("/authorize/", methods=["POST"])
@captcha_required(json=True)
def authorize():
    """Authorize user for chat: admins get infinite expiry, invitees get expiry from invite."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    # Check if this session has an invite token
    invite_token = session.get("chat_invite_token")
    if admin_permission.can():
        # Admin: infinite expiry
        session["chat_authorized"] = True
        session["chat_authorized_via"] = "admin"
        session.pop("chat_authorized_expiry", None)
        session.pop("chat_invite_token", None)
        return {"status": "ok"}
    elif invite_token:
        # Invited user: check token validity and set expiry
        if not re.fullmatch(r"[0-9a-f]{64}", invite_token):
            return {"status": "error", "message": "Invalid invite token format."}, 400
        value = redis.get(f"chat_auth_token:{invite_token}")
        now = int(time.time())
        if not value:
            session.pop("chat_invite_token", None)
            return {"status": "error", "message": "Invalid or expired invite link."}, 400
        try:
            chat_duration = int(value)
        except Exception:
            session.pop("chat_invite_token", None)
            return {"status": "error", "message": "Corrupted invite link data."}, 400
        expiry = now + chat_duration
        session["chat_authorized"] = True
        session["chat_authorized_via"] = "invite"
        session["chat_authorized_expiry"] = expiry
        # Do NOT delete the invite token here; allow multiple users to redeem it
        session.pop("chat_invite_token", None)
        return {"status": "ok", "expires_at": expiry}
    else:
        return {"status": "error", "message": "Not an admin and no invite token present."}, 403


@chat.route("/auth-link/", methods=["POST"])
@captcha_required(json=True)
def create_auth_link():
    """Admin endpoint to generate a short-lived chat auth link with custom durations."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    if not admin_permission.can():
        return {"status": "error", "message": "Only admin users can generate auth links."}, 403
    data = request.get_json(silent=True) or {}
    link_duration = data.get("link_duration", CHAT_AUTH_TOKEN_LIFETIME)
    chat_duration = data.get("chat_duration", CHAT_AUTH_TOKEN_LIFETIME)
    # Validate durations: must be int, in range 60..604800
    try:
        link_duration = int(link_duration)
    except Exception:
        return {"status": "error", "message": "Invalid link_duration. Must be an integer between 60 and 604800 seconds."}, 400
    try:
        chat_duration = int(chat_duration)
    except Exception:
        return {"status": "error", "message": "Invalid chat_duration. Must be an integer between 60 and 604800 seconds."}, 400
    if link_duration < 60 or link_duration > 60 * 60 * 24 * 7:
        return {"status": "error", "message": "link_duration must be between 60 and 604800 seconds."}, 400
    if chat_duration < 60 or chat_duration > 60 * 60 * 24 * 7:
        return {"status": "error", "message": "chat_duration must be between 60 and 604800 seconds."}, 400
    token = secrets.token_hex(32)  # 64 hex chars
    # Store only chat_duration as the value, use redis key expiry for link validity
    redis.setex(f"chat_auth_token:{token}", link_duration, str(chat_duration))
    link = url_for("chat.consume_auth_link", token=token, _external=True)
    return {"status": "ok", "link": link, "link_expires_in": link_duration, "chat_expires_in": chat_duration}


@chat.route("/authorized/")
def authorized():
    """Check if the user is authorized to chat."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    return {"authorized": is_chat_authorized()}


@chat.route("/consume-auth-link/<token>", methods=["GET"])
def consume_auth_link(token):
    """Store invite token in session and instruct user to pass captcha."""
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        return {"status": "error", "message": "Invalid token format."}, 400
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    # Validate that the token exists in redis
    if not redis.exists(f"chat_auth_token:{token}"):
        return {"status": "error", "message": "Invalid or expired invite link."}, 400
    # Only store the token, do not authorize yet
    session["chat_invite_token"] = token
    return {"status": "ok", "message": "Invite token accepted. Please complete captcha to authorize."}


@chat.route("/files/", methods=["POST"])
def files():
    """Query which files are available for a given hashid."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    if not is_chat_authorized():
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


@chat.route("/rag/", methods=["POST"])
def query_rag():
    """Chat with the model."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    if not is_chat_authorized():
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

    query = []
    for message in data["query"]:
        if "role" not in message or "content" not in message:
            return {"status": "error", "message": "Invalid query format."}, 400
        if message["role"] not in ("user", "assistant"):
            return {"status": "error", "message": "Invalid role in query."}, 400
        query.append({"role": message["role"], "content": message["content"]})
    collection = data["collection"]
    about = data["about"]
    hashid = data.get("hashid", None)
    if collection not in ("cc", "fips", "pp"):
        return {"status": "error", "message": "Invalid collection specified."}, 400

    try:
        result = chat_rag(query, collection, hashid, about)
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
        if tag in cleaned:
            cleaned = cleaned.replace(
                tag, f'<a href="{source["url"]}" target="_blank" title="Model used document.">[{source["type"]}]</a>'
            )

    return {"status": "ok", "response": cleaned, "raw": response, "sources": sources}, 200


@chat.route("/full/", methods=["POST"])
def query_full():
    """Chat with the model."""
    if not current_app.config["CHAT_ENABLED"]:
        return {"status": "error", "message": "Chat is not enabled."}, 403
    if not is_chat_authorized():
        return {"status": "error", "message": "You are not authorized to use the chat."}, 403
    if not request.is_json:
        return {"status": "error", "message": "Request must be JSON."}, 400
    data = request.get_json()
    if "query" not in data:
        return {"status": "error", "message": "Missing 'query' in request."}, 400
    if "context" not in data:
        return {"status": "error", "message": "Missing 'context' in request."}, 400
    if "collection" not in data:
        return {"status": "error", "message": "Missing 'collection' in request."}, 400
    if "hashid" not in data:
        return {"status": "error", "message": "Missing 'hashid' in request."}, 400

    query = []
    for message in data["query"]:
        if "role" not in message or "content" not in message:
            return {"status": "error", "message": "Invalid query format."}, 400
        if message["role"] not in ("user", "assistant"):
            return {"status": "error", "message": "Invalid role in query."}, 400
        query.append({"role": message["role"], "content": message["content"]})
    collection = data["collection"]
    hashid = data["hashid"]
    context = data["context"]
    if context not in ("report", "target", "both"):
        return {"status": "error", "message": "Invalid context specified."}, 400
    if collection not in ("cc", "fips", "pp"):
        return {"status": "error", "message": "Invalid collection specified."}, 400

    try:
        result = chat_full(query, collection, hashid, context)
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

    rendered = markdown(response, extras={"cuddled-lists": None, "code-friendly": None})
    cleaned = nh3.clean(rendered).strip()

    return {"status": "ok", "response": cleaned, "raw": response, "sources": []}, 200


# Helper to check session expiry in endpoints
def is_chat_authorized():
    authorized = session.get("chat_authorized", False)
    via = session.get("chat_authorized_via")
    expiry = session.get("chat_authorized_expiry")
    now = int(time.time())
    if not authorized:
        return False
    if via == "admin":
        # Double-check admin status
        if admin_permission.can():
            return True
        else:
            session.pop("chat_authorized", None)
            session.pop("chat_authorized_via", None)
            return False
    if via == "invite":
        if expiry and now > expiry:
            session.pop("chat_authorized", None)
            session.pop("chat_authorized_expiry", None)
            session.pop("chat_authorized_via", None)
            return False
        return True
    return False

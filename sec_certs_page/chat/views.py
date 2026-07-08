import json as jsonlib
from functools import wraps

import requests
from flask import Response, current_app, request, stream_with_context

from ..common.ai.chat import chat_full
from ..common.permissions import chat_permission
from ..common.sentry import metrics
from ..common.views import accounting
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


def sse(event=None, **payload):
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {jsonlib.dumps(payload)}\n\n"


def stream_completion(result):
    try:
        for line in result.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data:"):
                continue
            payload = line[len("data:") :].strip()
            if payload == "[DONE]":
                break
            try:
                chunk = jsonlib.loads(payload)
            except ValueError:
                continue
            if "error" in chunk:
                error = chunk["error"]
                message = error.get("message") if isinstance(error, dict) else str(error)
                yield sse("error", message=message or "Chat request failed.")
                return
            delta = (chunk.get("choices") or [{}])[0].get("delta", {}).get("content")
            if delta:
                yield sse(delta=delta)
    except requests.RequestException as e:
        yield sse("error", message=str(e))
        return
    finally:
        result.close()
    yield sse("done")


@chat.route("/full/", methods=["POST"])
@chat_api
@accounting("daily", 100, json=True)
def query_full():
    """Stream a chat completion about a certificate's full documents."""
    data = request.get_json()
    for field in ("query", "documents", "collection", "hashid"):
        if field not in data:
            return {"status": "error", "message": f"Missing '{field}' in request."}, 400

    query = []
    for message in data["query"]:
        if "role" not in message or "content" not in message:
            return {"status": "error", "message": "Invalid query format."}, 400
        if message["role"] not in ("user", "assistant"):
            return {"status": "error", "message": "Invalid role in query."}, 400
        query.append({"role": message["role"], "content": message["content"]})

    model = data.get("model") or current_app.config["LLM_DEFAULT_MODEL"]
    collection = data["collection"]
    if model not in current_app.config["LLM_MODELS"]:
        return {"status": "error", "message": "Invalid model specified."}, 400
    if collection not in ("cc", "eucc", "fips", "pp"):
        return {"status": "error", "message": "Invalid collection specified."}, 400
    if not isinstance(data["documents"], list):
        return {"status": "error", "message": "Invalid documents specified."}, 400
    documents = set()
    for document in data["documents"]:
        if document not in ("report", "target", "profile"):
            return {"status": "error", "message": "Invalid documents specified."}, 400

        documents.add(document)
    try:
        result = chat_full(query, model, collection, data["hashid"], documents)
    except ValueError as e:
        return {"status": "error", "message": str(e)}, 400
    metrics.count("ai.query", 1, attributes={"model": model, "type": "full", "collection": collection})

    if result.status_code != 200:
        result.close()
        return {"status": "error", "message": "Chat request failed."}, result.status_code

    return Response(
        stream_with_context(stream_completion(result)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

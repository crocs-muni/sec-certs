import shutil
import zipfile
from pathlib import Path

from flask import abort, current_app, request, send_file
from redis.exceptions import LockNotOwnedError
from werkzeug.utils import safe_join

from .. import csrf, redis, sitemap
from . import docs


@docs.route("/upload", methods=["POST"])
@csrf.exempt
def upload_docs():
    if "token" not in request.args:
        return abort(403)
    if request.args["token"] != current_app.config["DOCS_AUTH_TOKEN"]:
        return abort(403)

    lock = redis.lock("upload_docs", sleep=0.1, timeout=20)
    lock.acquire()
    try:
        docs_dir = Path(current_app.instance_path) / "docs"
        shutil.rmtree(docs_dir, ignore_errors=True)
        docs_dir.mkdir()
        with zipfile.ZipFile(request.files["data"], "r") as z:
            z.extractall(docs_dir)
    finally:
        try:
            lock.release()
        except LockNotOwnedError:
            # We lost the lock in the meantime but no biggie
            pass
    return "Docs uploaded correctly"


@docs.route("", strict_slashes=False, defaults={"path": ""})
@docs.route("/<path:path>")
def serve_docs(path):
    docs_path = Path(current_app.instance_path) / "docs"
    full_path = Path(safe_join(str(docs_path), path))
    if full_path.exists():
        if full_path.is_file():
            return send_file(full_path)
        elif full_path.is_dir():
            index_path = full_path / "index.html"
            if index_path.exists() and index_path.is_file():
                return send_file(index_path)
    return abort(404)


@sitemap.register_generator
def sitemap_urls():
    yield "docs.serve_docs", {}
from functools import partial
from itertools import product
from pathlib import Path

import sentry_sdk
from flask import abort, current_app, send_file

from .. import mongo


def _entry_file_path(hashid, dataset_path, document, format):
    return Path(current_app.instance_path) / dataset_path / document / format / f"{hashid}.{format}"


def _entry_download_func(collection, hashid, dataset_path, document, format):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db[collection].find_one({"_id": hashid})
    if doc:
        file_path = _entry_file_path(hashid, dataset_path, document, format)
        if file_path.exists():
            return send_file(file_path)
    return abort(404)


entry_download_report_pdf = partial(_entry_download_func, document="report", format="pdf")
entry_download_report_txt = partial(_entry_download_func, document="report", format="txt")
entry_download_target_pdf = partial(_entry_download_func, document="target", format="pdf")
entry_download_target_txt = partial(_entry_download_func, document="target", format="txt")


def entry_download_files(hashid, dataset_path, documents=("report", "target"), formats=("pdf", "txt")):
    return {
        (document, format): _entry_file_path(hashid, dataset_path, document, format).exists()
        for document, format in product(documents, formats)
    }

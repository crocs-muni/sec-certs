from itertools import product
from pathlib import Path

from flask import current_app


def make_dataset_paths(collection):
    instance_path = Path(current_app.instance_path)
    ns = current_app.config.get_namespace("DATASET_PATH_")

    res = {
        "cve_path": instance_path / ns["cve"],
        "cpe_path": instance_path / ns["cpe"],
        "dset_path": instance_path / ns[collection],
        "output_path": instance_path / ns[f"{collection}_out"],
        "dir_path": instance_path / ns[f"{collection}_dir"],
    }

    for document, format in product(("report", "target"), ("pdf", "txt")):
        path = res["dir_path"] / document / format
        path.mkdir(parents=True, exist_ok=True)
        res[f"{document}_{format}"] = path

    return res

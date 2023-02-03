from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

from sec_certs.dataset.cpe import CPEDataset
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import CustomJSONEncoder
from sec_certs.utils import helpers

logger = logging.getLogger(__name__)


def get_validation_dgsts(filepath: str | Path) -> set[str]:
    with Path(filepath).open("r") as handle:
        return set(json.load(handle))


def compute_precision(y: np.ndarray, y_pred: np.ndarray, **kwargs) -> float:
    prec = []
    for true, pred in zip(y, y_pred):
        set_pred = set(pred) if pred else set()
        set_true = set(true) if true else set()
        if not set_pred and not set_true:
            pass
        else:
            prec.append(len(set_true) / len(set_true.union(set_pred)))
    return np.mean(prec)  # type: ignore


def evaluate(
    x_valid: list[CCCertificate | FIPSCertificate],
    y_valid: list[set[str] | None],
    outpath: Path | str | None,
    cpe_dset: CPEDataset,
) -> None:
    y_pred = [x.heuristics.cpe_matches for x in x_valid]
    precision = compute_precision(np.array(y_valid), np.array(y_pred))

    correctly_classified = []
    badly_classified = []
    n_cpes_lost = 0
    n_certs_has_lost_cpes = 0
    n_certs_lost = 0

    for cert, predicted_cpes, verified_cpes in zip(x_valid, y_pred, y_valid):
        if not verified_cpes:
            verified_cpes = set()
        verified_cpes_dict = {x: cpe_dset[x].title if cpe_dset[x].title else x for x in verified_cpes}

        if not predicted_cpes:
            predicted_cpes = set()
        predicted_cpes_dict = {x: cpe_dset[x].title if cpe_dset[x].title else x for x in predicted_cpes}

        cert_name = cert.name if isinstance(cert, CCCertificate) else cert.web_data.module_name
        vendor = cert.manufacturer if isinstance(cert, CCCertificate) else cert.web_data.vendor

        should_be_removed = {x: cpe_dset[x].title if cpe_dset[x].title else x for x in predicted_cpes - verified_cpes}
        should_be_added = {x: cpe_dset[x].title if cpe_dset[x].title else x for x in verified_cpes - predicted_cpes}

        record = {
            "certificate_name": cert_name,
            "vendor": vendor,
            "heuristic version": helpers.compute_heuristics_version(cert_name) if cert_name else None,
            "predicted_cpes": predicted_cpes_dict,
            "manually_assigned_cpes": verified_cpes_dict,
            "should_be_removed": should_be_removed,
            "should_be_added": should_be_added,
        }

        if not predicted_cpes and verified_cpes:
            n_certs_lost += 1

        if predicted_cpes.issubset(verified_cpes):
            correctly_classified.append(record)
        else:
            badly_classified.append(record)

        if should_be_added:
            n_certs_has_lost_cpes += 1
            n_cpes_lost += len(should_be_added)

    results = {
        "Precision": precision,
        "n_cpes_lost": n_cpes_lost,
        "n_certs_has_lost_cpes": n_certs_has_lost_cpes,
        "n_certs_lost": n_certs_lost,
        "correctly_classified": correctly_classified,
        "badly_classified": badly_classified,
    }
    logger.info(
        f"Precision: {precision}; the classifier now misses {n_cpes_lost} CPE matches from {n_certs_has_lost_cpes} certificates ({n_certs_lost} certificates no longer have a match). In total, {sum([len(x) for x in y_pred if x])} CPEs were matched in {len(y_pred)} certs."
    )

    if outpath:
        with Path(outpath).open("w") as handle:
            json.dump(results, handle, indent=4, cls=CustomJSONEncoder, sort_keys=True)

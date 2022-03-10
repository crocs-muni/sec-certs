import json
import logging
from pathlib import Path
from typing import List, Optional, Set, Union

import numpy as np

import sec_certs.helpers as helpers
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import CustomJSONEncoder

logger = logging.getLogger(__name__)


def get_validation_dgsts(filepath: Union[str, Path]) -> Set[str]:
    with Path(filepath).open("r") as handle:
        return set(json.load(handle))


def compute_precision(y: np.ndarray, y_pred: np.ndarray, **kwargs) -> float:
    prec = []
    for true, pred in zip(y, y_pred):
        set_pred = set(pred) if pred else set()
        set_true = set(true) if true else set()
        if set_pred and not set_true:
            prec.append(0.0)
        elif not set_pred and not set_true:
            prec.append(1.0)
        else:
            prec.append(len(set_true.intersection(set_pred)) / len(set_true))
    return np.mean(prec)


def evaluate(
    x_valid: List[Union[CommonCriteriaCert, FIPSCertificate]],
    y_valid: List[Optional[Set[str]]],
    outpath: Optional[Union[Path, str]],
    cpe_dset: CPEDataset,
) -> None:
    y_pred = [x.heuristics.cpe_matches for x in x_valid]
    precision = compute_precision(np.array(y_valid), np.array(y_pred))

    correctly_classified = []
    badly_classified = []
    n_new_certs_with_match = 0
    n_newly_identified = 0

    for cert, predicted_cpes, verified_cpes in zip(x_valid, y_pred, y_valid):
        if not verified_cpes:
            verified_cpes = set()
        verified_cpes_dict = {x: cpe_dset[x].title if cpe_dset[x].title else x for x in verified_cpes}

        if not predicted_cpes:
            predicted_cpes = set()
        predicted_cpes_dict = {x: cpe_dset[x].title if cpe_dset[x].title else x for x in predicted_cpes}

        cert_name = cert.name if isinstance(cert, CommonCriteriaCert) else cert.web_scan.module_name
        vendor = cert.manufacturer if isinstance(cert, CommonCriteriaCert) else cert.web_scan.vendor
        record = {
            "certificate_name": cert_name,
            "vendor": vendor,
            "heuristic version": helpers.compute_heuristics_version(cert_name) if cert_name else None,
            "predicted_cpes": predicted_cpes_dict,
            "manually_assigned_cpes": verified_cpes_dict,
        }

        if verified_cpes.issubset(predicted_cpes):
            correctly_classified.append(record)
        else:
            badly_classified.append(record)

        if not verified_cpes and predicted_cpes:
            n_new_certs_with_match += 1
        n_newly_identified += len(predicted_cpes - verified_cpes)

    results = {
        "Precision": precision,
        "n_new_certs_with_match": n_new_certs_with_match,
        "n_newly_identified": n_newly_identified,
        "correctly_classified": correctly_classified,
        "badly_classified": badly_classified,
    }
    logger.info(
        f"While keeping precision: {precision}, the classifier identified {n_newly_identified} new CPE matches (Found match for {n_new_certs_with_match} certificates that were previously unmatched) compared to baseline."
    )

    if outpath:
        with Path(outpath).open("w") as handle:
            json.dump(results, handle, indent=4, cls=CustomJSONEncoder, sort_keys=True)

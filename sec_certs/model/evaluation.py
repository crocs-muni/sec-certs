import json
from pathlib import Path
import logging
from typing import List, Set, Union, Optional

from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.sample.cpe import CPE
from sec_certs.serialization import CustomJSONEncoder
import sec_certs.helpers as helpers

import numpy as np

logger = logging.getLogger(__name__)


def get_validation_dgsts(filepath: Union[str, Path]) -> Set[str]:
    with Path(filepath).open('r') as handle:
        data = json.load(handle)
    return set(data.keys())


def compute_precision(y: np.array, y_pred: np.array, **kwargs):
    prec = []
    for true, pred in zip(y, y_pred):
        set_pred = set(pred) if pred else set()
        set_true = set(true) if true else set()
        if set_pred and not set_true:
            prec.append(0)
        elif not set_pred and not set_true:
            prec.append(1)
        else:
            prec.append(len(set_true.intersection(set_pred)) / len(set_true))
    return np.mean(prec)


def evaluate(x_valid: List[Union[CommonCriteriaCert, FIPSCertificate]], y_valid: List[Optional[List[CPE]]], outpath: Optional[Union[Path, str]]):
    y_pred = [x.heuristics.cpe_matches for x in x_valid]
    precision = compute_precision(y_valid, y_pred)

    correctly_classified = []
    badly_classified = []
    n_new_certs_with_match = 0
    n_newly_identified = 0

    for cert, predicted_cpes, verified_cpes in zip(x_valid, y_pred, y_valid):
        verified_cpes_set = set(verified_cpes) if verified_cpes else set()
        predicted_cpes_set = set(predicted_cpes) if predicted_cpes else set()

        record = {'certificate_name': cert.name,
                  'vendor': cert.manufacturer,
                  'heuristic version': helpers.compute_heuristics_version(cert.name),
                  'predicted_cpes': predicted_cpes_set,
                  'manually_assigned_cpes': verified_cpes_set
                  }

        if verified_cpes_set.issubset(predicted_cpes_set):
            correctly_classified.append(record)
        else:
            badly_classified.append(record)

        if not verified_cpes_set and predicted_cpes_set:
            n_new_certs_with_match += 1
        n_newly_identified += len(predicted_cpes_set - verified_cpes_set)

    results = {'Precision': precision, 'n_new_certs_with_match': n_new_certs_with_match,
               'n_newly_identified': n_newly_identified, 'correctly_classified': correctly_classified,
               'badly_classified': badly_classified}
    logger.info(f'While keeping precision: {precision}, the classifier identified {n_newly_identified} new CPE matches (Found match for {n_new_certs_with_match} certificates that were previously unmatched) compared to baseline.')

    if outpath:
        with Path(outpath).open('w') as handle:
            json.dump(results, handle, indent=4, cls=CustomJSONEncoder)
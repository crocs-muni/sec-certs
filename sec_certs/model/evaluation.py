import json
from pathlib import Path
import logging
from typing import Dict, List, Set, Optional, Union

import numpy as np

from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.certificate.common_criteria import CommonCriteriaCert
from sec_certs.dataset.cve import CVEDataset, CVE
from sec_certs.serialization import CustomJSONEncoder
import sec_certs.helpers as helpers
import tqdm

logger = logging.getLogger(__name__)

def get_validation_dgsts(filepath: Union[str, Path]) -> Set[str]:
    with Path(filepath).open('r') as handle:
        data = json.load(handle)
    return set(data.keys())


def get_y_true(certs: List[CommonCriteriaCert]) -> np.array:
    return np.array([np.array([y.cve_id for y in cert.heuristics.related_cves]) if cert.heuristics.related_cves else np.array(['None']) for cert in certs], dtype='object')


def compute_precision(y: np.array, y_pred: np.array, **kwargs):
    prec = []
    for true, pred in zip(y, y_pred):
        set_pred = set(pred)
        if 'None' in set_pred:
            set_pred.remove('None')
        set_true = set(true)
        if 'None' in set_true:
            set_true.remove('None')

        if set_pred and not set_true:
            prec.append(0)
        elif not set_true and not set_pred:
            prec.append(1)
        else:
            prec.append(len(set_true.intersection(set_pred)) / len(set_true))
    return np.mean(prec)

def cpe_evaluate_classifier(x_valid, y_pred, y_true, outpath):
    precision = compute_precision(y_true, y_pred)

    correctly_classified = []
    badly_classified = []
    n_new_certs_with_match = 0
    n_newly_identified = 0

    for (vendor, cert_name), predicted_cpes, verified_cpes in zip(x_valid, y_pred, y_true):
        record = {'certificate_name': cert_name,
                  'vendor': vendor,
                  'heuristic version': helpers.compute_heuristics_version(cert_name),
                  'predicted_cpes': list(predicted_cpes),
                  'manually_assigned_cpes': list(verified_cpes)
                  }
        if set(verified_cpes).issubset(set(predicted_cpes)):
            correctly_classified.append(record)
        else:
            badly_classified.append(record)

        if len(verified_cpes) == 1 and len(predicted_cpes) > 1:
            n_new_certs_with_match += 1
        n_newly_identified += len(set(predicted_cpes) - set(verified_cpes))

    results = {'Precision': precision, 'n_new_certs_with_match': n_new_certs_with_match, 'n_newly_identified': n_newly_identified, 'correctly_classified': correctly_classified, 'badly_classified': badly_classified}
    print(f'While keeping precision: {precision}, the classifier identified {n_newly_identified} new CPE matches (Found match for {n_new_certs_with_match} certificates that were previously unmatched) compared to baseline.')

    with Path(outpath).open('w') as handle:
        json.dump(results, handle, indent=4)
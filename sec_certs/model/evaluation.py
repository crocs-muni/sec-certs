import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Union

import numpy as np

from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.certificate.common_criteria import CommonCriteriaCert
from sec_certs.dataset.cve import CVEDataset, CVE
from sec_certs.serialization import CustomJSONEncoder


def binarize_labels(cve_dset: CVEDataset, instances: List[List[CVE]]) -> np.array:
    cve_indexes = {x.cve_id: index for index, x in enumerate(cve_dset)}
    matrix = []
    for instance in instances:
        positive_indicies = [cve_indexes[x] for x in [y.cve_id for y in instance]]
        row_vector = np.zeros(len(cve_dset))
        row_vector[positive_indicies] = 1
        matrix.append(row_vector)
    return np.array(matrix)


def get_validation_dgsts(filepath: Union[str, Path]) -> Set[str]:
    with Path(filepath).open('r') as handle:
        data = json.load(handle)
    return set(data.keys())


def get_y_true(certs: List[CommonCriteriaCert]) -> List[List[CVE]]:
    return [set(cert.heuristics.related_cves) if cert.heuristics.related_cves else [] for cert in certs]


def compute_precision(y: List[List[CVE]], y_pred: List[List[CVE]], **kwargs):
    prec = []
    for pred, true in zip(y_pred, y):
        set_pred = set(pred)
        set_true = set(true)

        if set_pred and not set_true:
            prec.append(0)
        elif not set_true and not set_pred:
            prec.append(1)
        else:
            prec.append(len(set_true.intersection(set_pred)) / len(set_true))
    return np.mean(prec)


def prepare_classification_report(cert_names: List[str], y_pred: List[List[CVE]], y_true: List[List[CVE]],
                                  keywords: Set[str],
                                  distances: Optional[List[List[float]]],
                                  out_filepath: Optional[Union[str, Path]] = None):
    correctly_classified = []
    badly_classified = []
    results = {'correctly_classified': correctly_classified, 'badly_classified': badly_classified}

    for index, cert in enumerate(cert_names):
        outcome = {'certificate name': cert, 'prediction': [x.to_brief_dict(keywords) for x in y_pred[index]],
                   'ground_truth': [x.to_brief_dict(keywords) for x in y_true[index]]}
        if distances:
            outcome['distances'] = distances[index]

        if set(y_true[index]).issubset(set(y_pred[index])):
            correctly_classified.append(outcome)
        else:
            badly_classified.append(outcome)

    if out_filepath:
        with Path(out_filepath).open('w') as handle:
            json.dump(results, handle, indent=4, cls=CustomJSONEncoder)

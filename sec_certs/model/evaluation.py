import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Union

import numpy as np

from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.certificate.common_criteria import CommonCriteriaCert
from sec_certs.dataset.cve import CVEDataset, CVE


def binarize_labels(cve_dset: CVEDataset, instances: List[List[CVE]]) -> np.array:
    cve_ids = {x.cve_id: index for index, x in enumerate(cve_dset)}
    matrix = []
    for instance in instances:
        positive_indicies = {cve_ids[x] for x in [y.cve_id for y in instance]}
        row_vector = [0] * len(cve_dset)
        for index in positive_indicies:
            row_vector[index] = 1
        matrix.append(row_vector)
    return np.array(matrix)


def get_validation_dgsts(filepath: Union[str, Path]) -> Set[str]:
    with Path(filepath).open('r') as handle:
        data = json.load(handle)
    return set(data.keys())


def get_y_true(certs: List[CommonCriteriaCert]) -> List[List[CVE]]:
    return [cert.heuristics.related_cves if cert.heuristics.related_cves else [] for cert in certs]


def evaluate_classifier(y_pred: np.array, y_true: np.array):
    precisions = []
    for i in range(y_true.shape[0]):
        set_true = set(np.where(y_true[i])[0])
        set_pred = set(np.where(y_pred[i])[0])

        if set_pred and not set_true:
            precisions.append(0)
        elif not set_true and not set_pred:
            precisions.append(1)
        else:
            precisions.append(len(set_true.intersection(set_pred)) / len(set_true))

    return np.mean(precisions)
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


def compute_promising_ratio(y: np.array, y_pred: np.array):
    """
    Computes number of matched vulnerabilities that have lower distance from a certificate than the
    first already discovered vulnerability (any from y). If no new vulnerability with such property was identified,
    0 is assigned instead. Assumes that vulnerabilities are ordered by their similarity to given certificate.
    """
    if len(y_pred) > 200:
        logger.warning('Promising matches metric should be computed only on certificates with ground-truth-verified vulnerability.')

    n_promising = []
    for instance, ground_truth_vulns in zip(y_pred, y):
        known_before = np.array(list(map(lambda x: x in set(ground_truth_vulns), instance)))
        true_indices = np.where(known_before)
        if true_indices[0].size > 0 and true_indices[0][0] != 0:
            n_promising.append(true_indices[0][0])
        else:
            n_promising.append(0)

    return np.mean(n_promising)


def prepare_classification_report(cert_names, y_pred, y_true, distances, cve_dataset, keywords, classifier, out_path):
    def get_cve_representation(cve_dataset, cve_id, keywords, classifier):
        if cve_id == 'None':
            return None,
        else:
            return {
                'cve_id': cve_id,
                'description': cve_dataset[cve_id].description,
                'tokenized': helpers.tokenize(cve_dataset[cve_id].description, keywords),
                'tfidf': classifier.prepare_df_from_description(helpers.tokenize(cve_dataset[cve_id].description, keywords))['TF-IDF'].to_dict(),
            }

    correctly_classified = []
    badly_classified = []
    results = {'correctly_classified': correctly_classified, 'badly_classified': badly_classified}

    for crt, prediction, ground_truth, dis in tqdm.tqdm(zip(cert_names, y_pred, y_true, distances), desc='Preparing classification report', total=len(cert_names)):
        record = {'certificate_name': crt,
                  'tokenized': helpers.tokenize(crt, keywords),
                  'tfidf': classifier.prepare_df_from_description(crt)['TF-IDF'].to_dict(),
                  'distances': dis,
                  'predicted_cves': [get_cve_representation(cve_dataset, cve_id, keywords, classifier) for cve_id in prediction],
                  'true_cves': [get_cve_representation(cve_dataset, cve_id, keywords, classifier) for cve_id in ground_truth]}
        if set(ground_truth).issubset(set(prediction)):
            correctly_classified.append(record)
        else:
            badly_classified.append(record)

    with Path(out_path).open('w') as handle:
        json.dump(results, handle, indent=4)


# def prepare_classification_report(cert_names: List[str], y_pred: List[List[CVE]], y_true: List[List[CVE]],
#                                   keywords: Set[str],
#                                   distances: Optional[List[List[float]]],
#                                   out_filepath: Optional[Union[str, Path]] = None):
#     correctly_classified = []
#     badly_classified = []
#     results = {'correctly_classified': correctly_classified, 'badly_classified': badly_classified}
#
#     for index, cert in enumerate(cert_names):
#         outcome = {'certificate name': cert, 'prediction': [x.to_brief_dict(keywords) for x in y_pred[index]],
#                    'ground_truth': [x.to_brief_dict(keywords) for x in y_true[index]]}
#         if distances:
#             outcome['distances'] = distances[index]
#
#         if set(y_true[index]).issubset(set(y_pred[index])):
#             correctly_classified.append(outcome)
#         else:
#             badly_classified.append(outcome)
#
#     if out_filepath:
#         with Path(out_filepath).open('w') as handle:
#             json.dump(results, handle, indent=4, cls=CustomJSONEncoder)

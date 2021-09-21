import logging
import datetime

from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.model.evaluation import get_validation_dgsts, get_y_true,compute_precision
from sec_certs.model.cve_matching import VulnClassifier
from sklearn.metrics import make_scorer
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import PredefinedSplit


def main():
    logging.basicConfig(level=logging.INFO)
    start = datetime.datetime.now()

    validation_dgsts = get_validation_dgsts('/Users/adam/phd/projects/certificates/datasets/cve_matching_valid_test_split/validation_set.json')
    cc_dset = CCDataset.from_json('/Users/adam/phd/projects/certificates/datasets/cc_full_dataset/CommonCriteria_dataset.json')
    validation_certs = [x for x in cc_dset if x.dgst in validation_dgsts]
    validation_certs = [x for x in validation_certs if x.heuristics.related_cves]
    keywords = cc_dset.generate_cert_name_keywords()

    cve_dset: CVEDataset = CVEDataset.from_json(cc_dset.cve_dataset_path)
    vulnerabilities = [x for x in cve_dset]

    classifier = VulnClassifier(keywords)
    classifier.fit(vulnerabilities)

    scorer = make_scorer(compute_precision)

    grid_search_dict = {
        'cutoff_distance': [0.4, 0.7, 1],
        'n_tokens': [20, 25, 30]
    }

    cert_names = [x.name for x in validation_certs]
    validation_fold = [-1] * len(vulnerabilities) + [0] * len(cert_names)
    ps = PredefinedSplit(validation_fold)
    full_dataset = vulnerabilities + cert_names

    y_true = get_y_true(validation_certs)
    clf = GridSearchCV(classifier, param_grid=grid_search_dict, scoring=scorer, verbose=4, cv=ps, refit=False)
    clf.fit(full_dataset, [0] * len(vulnerabilities) + y_true)

    end = datetime.datetime.now()
    print(f'The computation took {(end - start)} seconds.')


if __name__ == '__main__':
    main()
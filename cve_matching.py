import logging
import datetime

from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.model.evaluation import get_validation_dgsts, binarize_labels, get_y_true, evaluate_classifier
from sec_certs.model.cve_matching import VulnClassifier


def main():
    logging.basicConfig(level=logging.INFO)
    start = datetime.datetime.now()

    validation_dgsts = get_validation_dgsts(
        '/Users/adam/phd/projects/certificates/datasets/cve_matching_valid_test_split/validation_set.json')
    cc_dset = CCDataset.from_json(
        '/Users/adam/phd/projects/certificates/datasets/cc_full_dataset/CommonCriteria_dataset.json')
    validation_certs = [x for x in cc_dset if x.dgst in validation_dgsts]

    keywords = cc_dset.generate_cert_name_keywords()

    cve_dset: CVEDataset = CVEDataset.from_json(cc_dset.cve_dataset_path)
    vulnerabilities = [x for x in cve_dset]

    classifier = VulnClassifier(keywords)
    classifier.fit(vulnerabilities)

    cert_names = [x.name for x in validation_certs]
    y_pred = binarize_labels(cve_dset, classifier.predict(cert_names))
    y_true = binarize_labels(cve_dset, get_y_true(validation_certs))
    precision = evaluate_classifier(y_pred, y_true)
    print(f'Precision: {precision}')

    end = datetime.datetime.now()
    print(f'The computation took {(end - start)} seconds.')


if __name__ == '__main__':
    main()
from sklearn.base import BaseEstimator
from typing import Dict, Tuple, Set, List, Optional, Union
from sec_certs.sample.cpe import CPE
import sec_certs.helpers as helpers
import tqdm
import itertools
import re
from rapidfuzz import process, fuzz
import operator
from pathlib import Path
import json
import logging

import sec_certs.model.evaluation as evaluation
from sec_certs.serialization import CustomJSONEncoder

logger = logging.getLogger(__name__)


class CPEClassifier(BaseEstimator):
    # Validation dataset should be obtained directly from certificates
    # predict should return CPE uris afaik
    cpes_: Dict[str, CPE]
    vendor_to_versions_: Dict[str, Set[str]]  # Look-up dict cpe_vendor: list of viable versions
    vendor_version_to_cpe_: Dict[Tuple[str, str], Set[CPE]]  # Look-up dict (cpe_vendor, cpe_version): List of viable cpe items
    title_to_cpes_: Dict[str, Set[CPE]]  # Look-up dict title: List of cert items
    vendors_: Set[str]

    def __init__(self, match_threshold: int = 80, n_max_matches: int = 10):
        self.match_threshold = match_threshold
        self.n_max_matches = n_max_matches

    def fit(self, X: List[CPE], y: List[str] = None):
        self.clean_lookup_structures()
        self.build_lookup_structures(X)
        return self

    def clean_lookup_structures(self):
        self.vendor_to_versions_ = dict()
        self.vendor_version_to_cpe_ = dict()
        self.title_to_cpes_ = dict()
        self.vendors_ = set()

    def build_lookup_structures(self, X: List[CPE]):
        self.vendor_to_versions_ = {x.vendor: set() for x in X}
        self.vendors_ = set(self.vendor_to_versions_.keys())

        for cpe in tqdm.tqdm(X, desc='Fitting the CPE classifier'):
            self.vendor_to_versions_[cpe.vendor].add(cpe.version)
            if (cpe.vendor, cpe.version) not in self.vendor_version_to_cpe_:
                self.vendor_version_to_cpe_[(cpe.vendor, cpe.version)] = {cpe}
            else:
                self.vendor_version_to_cpe_[(cpe.vendor, cpe.version)].add(cpe)
            if cpe.title not in self.title_to_cpes_:
                self.title_to_cpes_[cpe.title] = {cpe}
            else:
                self.title_to_cpes_[cpe.title].add(cpe)

    def predict(self, X: List[Tuple[str, str]]) -> List[Optional[List[str]]]:
        return [self.predict_single_cert(x) for x in tqdm.tqdm(X, desc='Predicting')]

    def predict_single_cert(self, crt: Tuple[str, str]) -> Optional[List[str]]:
        replace_non_letter_non_numbers_with_space = re.compile(r"(?ui)\W")

        def sanitize_matched_string(string: str):
            string = string.replace('®', '').replace('™', '').lower()
            return replace_non_letter_non_numbers_with_space.sub(' ', string)

        def strip_manufacturer_and_version(string: str, manufacturers: List[str], versions: List[str]):
            for x in manufacturers + versions:
                string = string.lower().replace(sanitize_matched_string(x.lower()), '').strip()
            return string

        candidate_vendors = self.get_candidate_list_of_vendors(crt[0])
        candidate_versions = helpers.compute_heuristics_version(crt[1])
        candidates = self.get_candidate_cpe_matches(candidate_vendors, candidate_versions)

        sanitized_cert_name = sanitize_matched_string(crt[1])
        reasonable_matches = []

        for c in candidates:
            sanitized_title = sanitize_matched_string(c.title) if c.title else sanitize_matched_string(c.vendor + ' ' + c.item_name + ' ' + c.version)
            sanitized_item_name = sanitize_matched_string(c.item_name)
            cert_stripped_manufacturer = strip_manufacturer_and_version(sanitized_cert_name, candidate_vendors, candidate_versions)

            set_match_title = fuzz.token_set_ratio(sanitized_cert_name, sanitized_title)
            partial_match_title = fuzz.partial_ratio(sanitized_cert_name, sanitized_title)

            set_match_item = fuzz.token_set_ratio(cert_stripped_manufacturer, sanitized_item_name)
            partial_match_item = fuzz.partial_ratio(cert_stripped_manufacturer, sanitized_item_name)

            potential = max([set_match_title, partial_match_title, set_match_item, partial_match_item])

            if potential >= self.match_threshold:
                reasonable_matches.append((potential, c))

        if reasonable_matches:
            reasonable_matches = sorted(reasonable_matches, key=operator.itemgetter(0), reverse=True)

            # possibly filter short titles to avoid false positives
            # reasonable_matches = list(filter(lambda x: len(x[1].item_name) > 4, reasonable_matches))

            return [x[1].uri for x in reasonable_matches[:self.n_max_matches]]
            # return reasonable_matches[:N_MAX_MATCHES]

        return None

        # TODO: Fix version with relaxation
        # if RELAX_VERSION and not reasonable_matches:
        #     return self.get_cpe_matches(cert_name, cert_candidate_cpe_vendors, ['-'], relax_version=True, n_max_matches=n_max_matches, threshold=threshold)

    def get_candidate_list_of_vendors(self, manufacturer: str):
        def contains_two_independent_vendors(string: str) -> bool:
            return len(string.split(', ')) == 2

        result = set()
        if not isinstance(manufacturer, str):
            return None
        lower = manufacturer.lower()
        if ' / ' in manufacturer:
            chain = [self.get_candidate_list_of_vendors(x) for x in manufacturer.split(' / ')]
            chain = [x for x in chain if x]
            result = list(set(itertools.chain(*chain)))
            if not result:
                return None
            return result

        if '/ ' in manufacturer:
            chain_one = [self.get_candidate_list_of_vendors(x) for x in manufacturer.split('/ ')]
            chain_one = [x for x in chain_one if x]
            result = list(set(itertools.chain(*chain_one)))
            if not result:
                return None
            return result

        if ' /' in manufacturer:
            chain_one = [self.get_candidate_list_of_vendors(x) for x in manufacturer.split(' /')]
            chain_one = [x for x in chain_one if x]
            result = list(set(itertools.chain(*chain_one)))
            if not result:
                return None
            return result

        if lower in self.vendors_:
            result.add(lower)

        if contains_two_independent_vendors(lower):
            chain = [self.get_candidate_list_of_vendors(x) for x in manufacturer.split(', ')]
            chain = [x for x in chain if x]
            result = list(set(itertools.chain(*chain)))
            if not result:
                return None
            return result

        tokenized = lower.split()

        if tokenized[0] in self.vendors_:
            result.add(tokenized[0])

        if ',' in lower and (y := lower.split(',')[0]) in self.vendors_:
            result.add(y)

        if len(tokenized) > 1 and tokenized[0] + tokenized[1] in self.vendors_:
            result.add(tokenized[0] + tokenized[1])

        # Below are completely manual fixes

        if 'hewlett' in tokenized or 'hewlett-packard' in tokenized:
            result.add('hp')

        if 'thales' in tokenized:
            result.add('thalesesecurity')
            result.add('thalesgroup')

        if 'stmicroelectronics' in tokenized:
            result.add('st')

        if 'athena' in tokenized and 'smartcard' in tokenized:
            result.add('athena-scs')

        if tokenized[0] == 'the' and not result:
            result = self.get_candidate_list_of_vendors(' '.join(tokenized[1:]))

        if not result:
            return None
        return list(result)

    def get_candidate_vendor_version_pairs(self, cert_candidate_cpe_vendors: List[str], cert_candidate_versions: List[str]) -> Optional[List[Tuple[str, str]]]:
        """
        Given parameters, will return Pairs (cpe_vendor, cpe_version) that should are relevant to a given sample
        Parameters
        :param cert_candidate_cpe_vendors: list of CPE vendors relevant to a sample
        :param cert_candidate_versions: List of versions heuristically extracted from the sample name
        :return: List of tuples (cpe_vendor, cpe_version) that can be used in the lookup table to search the CPE dataset.
        """

        def is_cpe_version_among_cert_versions(cpe_version: str, cert_versions: List[str]) -> bool:
            just_numbers = r'(\d{1,5})(\.\d{1,5})' # TODO: The use of this should be double-checked
            for v in cert_versions:
                if (v.startswith(cpe_version) and re.search(just_numbers, cpe_version)) or cpe_version.startswith(v):
                    return True
            return False

        if not cert_candidate_cpe_vendors:
            return None

        candidate_vendor_version_pairs: List[Tuple[str, str]] = []
        for vendor in cert_candidate_cpe_vendors:
            viable_cpe_versions = self.vendor_to_versions_[vendor]
            matched_cpe_versions = [x for x in viable_cpe_versions if is_cpe_version_among_cert_versions(x, cert_candidate_versions)]
            candidate_vendor_version_pairs.extend([(vendor, x) for x in matched_cpe_versions])
        return candidate_vendor_version_pairs

    def get_candidate_cpe_matches(self, candidate_vendors, candidate_versions):
        candidate_vendor_version_pairs = self.get_candidate_vendor_version_pairs(candidate_vendors, candidate_versions)
        return list(itertools.chain.from_iterable([self.vendor_version_to_cpe_[x] for x in candidate_vendor_version_pairs])) if candidate_vendor_version_pairs else []

    def evaluate(self, x_valid, y_valid, outpath: Optional[Union[Path, str]]):
        y_pred = self.predict(x_valid)
        precision = evaluation.compute_precision(y_valid, y_pred)

        correctly_classified = []
        badly_classified = []
        n_new_certs_with_match = 0
        n_newly_identified = 0

        for (vendor, cert_name), predicted_cpes, verified_cpes in zip(x_valid, y_pred, y_valid):
            verified_cpes_set = set(verified_cpes) if verified_cpes else set()
            predicted_cpes_set = set(predicted_cpes) if predicted_cpes else set()

            record = {'certificate_name': cert_name,
                      'vendor': vendor,
                      'heuristic version': helpers.compute_heuristics_version(cert_name),
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

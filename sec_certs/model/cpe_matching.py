import itertools
import logging
import re
from typing import Dict, List, Optional, Set, Tuple

from packaging.version import parse
from rapidfuzz import fuzz
from sklearn.base import BaseEstimator

import sec_certs.helpers as helpers
from sec_certs.sample.cpe import CPE

logger = logging.getLogger(__name__)


class CPEClassifier(BaseEstimator):
    """
    Class that can predict CPE matches for certificate instances.
    Adheres to sklearn BaseEstimator interface.
    Fit method is called on list of CPEs and build two look-up dictionaries, see description of attributes.
    """

    vendor_to_versions_: Dict[str, Set[str]]  # Key: CPE vendor, Value: versions of all CPE records of that vendor
    vendor_version_to_cpe_: Dict[
        Tuple[str, str], Set[CPE]
    ]  # Key: (CPE vendor, version), Value: All CPEs that are of (vendor, version)
    vendors_: Set[str]

    def __init__(self, match_threshold: int = 80, n_max_matches: int = 10):
        self.match_threshold = match_threshold
        self.n_max_matches = n_max_matches

    def fit(self, X: List[CPE], y: Optional[List[str]] = None):
        """
        Just creates look-up structures from provided list of CPEs
        @param X: List of CPEs that can be matched with predict()
        @param y: will be ignored, specified to adhere to sklearn BaseEstimator interface
        """
        self.build_lookup_structures(X)
        return self

    @staticmethod
    def filter_short_cpes(cpes: List[CPE]):
        """
        Short CPE items are super easy to match with 100% rank, but they are hardly informative. This method discards them.
        @param cpes: List of CPEs to filtered
        @return All CPEs in cpes variable which item name has at least 4 characters.
        """
        return list(filter(lambda x: x.item_name is not None and len(x.item_name) > 3, cpes))

    def build_lookup_structures(self, X: List[CPE]):
        """
        Builds several look-up dictionaries for fast matching.
        - vendor_to_version_: each vendor is mapped to set of versions that appear in combination with vendor in CPE dataset
        - vendor_version_to_cpe_: Each (vendor, version) tuple is mapped to a set of CPE items that appear in combination with this tuple in CPE dataset
        - vendors_: Just aggregates set of vendors, used for prunning later on.
        @param X: List of CPEs that will be used to build the dictionaries
        """
        sufficiently_long_cpes = self.filter_short_cpes(X)
        self.vendor_to_versions_ = {x.vendor: set() for x in sufficiently_long_cpes}
        self.vendors_ = set(self.vendor_to_versions_.keys())
        self.vendor_version_to_cpe_ = dict()

        for cpe in helpers.tqdm(sufficiently_long_cpes, desc="Fitting the CPE classifier"):
            self.vendor_to_versions_[cpe.vendor].add(cpe.version)
            if (cpe.vendor, cpe.version) not in self.vendor_version_to_cpe_:
                self.vendor_version_to_cpe_[(cpe.vendor, cpe.version)] = {cpe}
            else:
                self.vendor_version_to_cpe_[(cpe.vendor, cpe.version)].add(cpe)

    def predict(self, X: List[Tuple[str, str, str]]) -> List[Optional[List[str]]]:
        """
        Will predict CPE uris for List of Tuples (vendor, product name, identified versions in product name)
        @param X: tuples (vendor, product name, identified versions in product name)
        @return: List of CPE uris that correspond to given input, None if nothing was found.
        """
        return [self.predict_single_cert(x[0], x[1], x[2]) for x in helpers.tqdm(X, desc="Predicting")]

    def predict_single_cert(
        self,
        vendor: str,
        product_name: str,
        versions: Optional[List[str]],
        relax_version: bool = False,
        relax_title: bool = False,
    ) -> Optional[List[str]]:
        """
        Predict List of CPE uris for triplet (vendor, product_name, list_of_version). The prediction is made as follows:
        1. Sanitize all strings
        2. Find vendors in CPE dataset that are related to the certificate
        3. Based on (vendors, versions) find all CPE items that are considered as candidates for match
        4. Compute string similarity of the candidate CPE matches and certificate name
        5. Evaluate best string similarity, if above threshold, declare it a match.
        6. If no CPE item is matched, we tried again but relax version and check CPEs that don't have their version specified.
        Also, we search for 100% CPE matches on item name instead of title.
        @param vendor: manufacturer of the certificate
        @param product_name: name of the certificate
        @param versions: List of versions that appear in the certificate name
        @param relax_version: bool, see step 6 above.
        @param relax_title: bool
        @return:
        """
        sanitized_vendor = CPEClassifier._discard_trademark_symbols(vendor).lower() if vendor else vendor
        sanitized_product_name = CPEClassifier._fully_sanitize_string(product_name) if product_name else product_name
        candidate_vendors = self.get_candidate_list_of_vendors(sanitized_vendor)
        candidates = self.get_candidate_cpe_matches(candidate_vendors, versions)  # type: ignore
        ratings = [self.compute_best_match(cpe, sanitized_product_name, candidate_vendors, versions, relax_title=relax_title) for cpe in candidates]  # type: ignore
        threshold = self.match_threshold if not relax_version else 100
        final_matches_aux: List[Tuple[float, CPE]] = list(filter(lambda x: x[0] >= threshold, zip(ratings, candidates)))
        final_matches: Optional[List[str]] = [
            x[1].uri for x in final_matches_aux[: self.n_max_matches] if x[1].uri is not None
        ]

        if not relax_title and not final_matches:
            final_matches = self.predict_single_cert(
                vendor, product_name, versions, relax_version=relax_version, relax_title=True
            )

        if not relax_version and not final_matches:
            final_matches = self.predict_single_cert(
                vendor, product_name, ["-"], relax_version=True, relax_title=relax_title
            )

        return final_matches if final_matches else None

    def compute_best_match(
        self,
        cpe: CPE,
        product_name: str,
        candidate_vendors: List[str],
        versions: Optional[List[str]],
        relax_title: bool = False,
    ) -> float:
        """
        Tries several different settings in which string similarity between CPE and certificate name is tested.
        For definition of string similarity, see rapidfuzz package on GitHub. Both token set ratio and partial ratio are tested,
        always both on CPE title and CPE item name.
        @param cpe: CPE to test
        @param product_name: name of the certificate
        @param candidate_vendors: vendors that appear in the certificate
        @param versions: versions that appear in the certificate
        @return: Maximal value of the four string similarities discussed above.
        """
        if relax_title:
            sanitized_title = CPEClassifier._fully_sanitize_string(cpe.title) if cpe.title else CPEClassifier._fully_sanitize_string(cpe.vendor + " " + cpe.item_name + " " + cpe.version + " " + cpe.update + " " + cpe.target_hw)  # type: ignore
        else:
            if cpe.title:
                sanitized_title = CPEClassifier._fully_sanitize_string(cpe.title)
            else:
                return 0
        sanitized_item_name = CPEClassifier._fully_sanitize_string(cpe.item_name)  # type: ignore
        cert_stripped = CPEClassifier._strip_manufacturer_and_version(product_name, candidate_vendors, versions)  # type: ignore

        token_set_ratio_on_title = fuzz.token_set_ratio(product_name, sanitized_title)
        partial_ratio_on_title = fuzz.partial_ratio(product_name, sanitized_title)
        ratings = [token_set_ratio_on_title, partial_ratio_on_title]

        if relax_title:
            token_set_ratio_on_item_name = fuzz.token_set_ratio(cert_stripped, sanitized_item_name)
            partial_ratio_on_item_name = fuzz.partial_ratio(cert_stripped, sanitized_item_name)
            ratings += [token_set_ratio_on_item_name, partial_ratio_on_item_name]

        return max(ratings)

    @staticmethod
    def _fully_sanitize_string(string: str) -> str:
        return CPEClassifier._replace_special_chars_with_space(CPEClassifier._discard_trademark_symbols(string.lower()))

    @staticmethod
    def _replace_special_chars_with_space(string: str) -> str:
        return re.sub(r"[^a-zA-Z0-9 \n\.]", " ", string)

    @staticmethod
    def _discard_trademark_symbols(string: str) -> str:
        return string.replace("®", "").replace("™", "")

    @staticmethod
    def _strip_manufacturer_and_version(string: str, manufacturers: List[str], versions: List[str]) -> str:
        for x in manufacturers + versions:
            string = string.lower().replace(CPEClassifier._replace_special_chars_with_space(x.lower()), "").strip()
        return string

    def _process_manufacturer(self, manufacturer: str, result: Set) -> Optional[List[str]]:
        tokenized = manufacturer.split()
        if tokenized[0] in self.vendors_:
            result.add(tokenized[0])
        if len(tokenized) > 1 and tokenized[0] + tokenized[1] in self.vendors_:
            result.add(tokenized[0] + tokenized[1])

        # Below are completely manual fixes
        if "hewlett" in tokenized or "hewlett-packard" in tokenized or manufacturer == "hewlett packard":
            result.add("hp")
        if "thales" in tokenized:
            result.add("thalesesecurity")
            result.add("thalesgroup")
        if "stmicroelectronics" in tokenized:
            result.add("st")
        if "athena" in tokenized and "smartcard" in tokenized:
            result.add("athena-scs")
        if tokenized[0] == "the" and not result:
            candidate_result = self.get_candidate_list_of_vendors(" ".join(tokenized[1:]))
            return list(candidate_result) if candidate_result else None

        return list(result) if result else None

    def get_candidate_list_of_vendors(self, manufacturer: str) -> Optional[List[str]]:
        """
        Given manufacturer name, this method will find list of plausible vendors from CPE dataset that are likely related.
        @param manufacturer: manufacturer
        @return: List of related manufacturers, None if nothing relevant is found.
        """
        if not manufacturer:
            return None

        result: Set = set()
        splits = re.compile(r"[,/]").findall(manufacturer)

        if splits:
            vendor_tokens = set(
                itertools.chain.from_iterable([[x.strip() for x in manufacturer.split(s)] for s in splits])
            )
            result_aux = [self.get_candidate_list_of_vendors(x) for x in vendor_tokens]
            result_used = list(set(itertools.chain.from_iterable([x for x in result_aux if x])))
            return result_used if result_used else None

        if manufacturer in self.vendors_:
            result.add(manufacturer)

        return self._process_manufacturer(manufacturer, result)

    def get_candidate_vendor_version_pairs(
        self, cert_candidate_cpe_vendors: List[str], cert_candidate_versions: List[str]
    ) -> Optional[List[Tuple[str, str]]]:
        """
        Given parameters, will return Pairs (cpe_vendor, cpe_version) that are relevant to a given sample
        @param cert_candidate_cpe_vendors: list of CPE vendors relevant to a sample
        @param cert_candidate_versions: List of versions heuristically extracted from the sample name
        @return: List of tuples (cpe_vendor, cpe_version) that can be used in the lookup table to search the CPE dataset.
        """

        def is_cpe_version_among_cert_versions(cpe_version: Optional[str], cert_versions: List[str]) -> bool:
            def simple_startswith(seeked_version: str, checked_string: str) -> bool:
                if seeked_version == checked_string:
                    return True
                else:
                    return (
                        checked_string.startswith(seeked_version) and not checked_string[len(seeked_version)].isdigit()
                    )

            if not cpe_version:
                return False
            just_numbers = r"(\d{1,5})(\.\d{1,5})"  # TODO: The use of this should be double-checked
            for v in cert_versions:
                if (simple_startswith(v, cpe_version) and re.search(just_numbers, cpe_version)) or simple_startswith(
                    cpe_version, v
                ):
                    return True
            return False

        if not cert_candidate_cpe_vendors:
            return None

        candidate_vendor_version_pairs: List[Tuple[str, str]] = []
        for vendor in cert_candidate_cpe_vendors:
            viable_cpe_versions = self.vendor_to_versions_.get(vendor, set())
            matched_cpe_versions = [
                x for x in viable_cpe_versions if is_cpe_version_among_cert_versions(x, cert_candidate_versions)
            ]
            candidate_vendor_version_pairs.extend([(vendor, x) for x in matched_cpe_versions])
        return candidate_vendor_version_pairs

    # TODO: Start using it or delete.
    def new_get_candidate_vendor_version_pairs(self, cert_cpe_vendors, cert_versions):
        if not cert_cpe_vendors:
            return None

        candidate_vendor_version_pairs = []
        for vendor in cert_cpe_vendors:
            viable_cpe_versions = {parse(x) for x in self.vendor_to_versions_[vendor]}
            intersection = viable_cpe_versions.intersection({parse(x) for x in cert_versions})
            candidate_vendor_version_pairs.extend([(vendor, str(x)) for x in intersection])
        return candidate_vendor_version_pairs

    def get_candidate_cpe_matches(self, candidate_vendors: List[str], candidate_versions: List[str]):
        """
        Given List of candidate vendors and candidate versions found in certificate, candidate CPE matches are found
        @param candidate_vendors: List of version strings that were found in the certificate
        @param candidate_versions: List of vendor strings that were found in the certificate
        @return:
        """
        candidate_vendor_version_pairs = self.get_candidate_vendor_version_pairs(candidate_vendors, candidate_versions)
        return (
            list(
                itertools.chain.from_iterable([self.vendor_version_to_cpe_[x] for x in candidate_vendor_version_pairs])
            )
            if candidate_vendor_version_pairs
            else []
        )

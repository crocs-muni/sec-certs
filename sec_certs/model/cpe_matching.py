import itertools
import logging
import operator
import re
from typing import Dict, List, Optional, Set, Tuple

import spacy
from rapidfuzz import fuzz
from sklearn.base import BaseEstimator

import sec_certs.helpers as helpers
from sec_certs import constants
from sec_certs.sample.cpe import CPE

logger = logging.getLogger(__name__)


class CPEClassifier(BaseEstimator):
    """
    Class that can predict CPE matches for certificate instances.
    Adheres to sklearn BaseEstimator interface.
    Fit method is called on list of CPEs and build two look-up dictionaries, see description of attributes.
    """

    vendor_to_versions_: Dict[str, Set[str]]  # Key: CPE vendor, Value: versions of all CPE records of that vendor
    vendor_version_to_cpe_: Dict[Tuple[str, str], Set[CPE]]  # Key: (CPE vendor, version), Value: CPEs (vendor, version)
    vendors_: Set[str]

    def __init__(self, match_threshold: int = 80, n_max_matches: int = 10, spacy_model_to_use: str = "en_core_web_sm"):
        self.match_threshold = match_threshold
        self.n_max_matches = n_max_matches
        self.nlp = spacy.load(spacy_model_to_use, disable=["parser", "ner"])

    def fit(self, X: List[CPE], y: Optional[List[str]] = None) -> "CPEClassifier":
        """
        Just creates look-up structures from provided list of CPEs

        :param List[CPE] X: List of CPEs that can be matched with predict()
        :param Optional[List[str]] y: will be ignored, specified to adhere to sklearn BaseEstimator interface, defaults to None
        :return CPEClassifier: return self to allow method chaining
        """
        self._build_lookup_structures(X)
        return self

    @staticmethod
    def _filter_short_cpes(cpes: List[CPE]) -> List[CPE]:
        """
        Short CPE items are super easy to match with 100% rank, but they are hardly informative. This method discards them.

        :param List[CPE] cpes: List of CPEs to filtered
        :return List[CPE]: All CPEs in cpes variable which item name has at least 4 characters.
        """
        return list(filter(lambda x: x.item_name is not None and len(x.item_name) > 3, cpes))

    def _build_lookup_structures(self, X: List[CPE]) -> None:
        """
        Builds several look-up dictionaries for fast matching.
        - vendor_to_version_: each vendor is mapped to set of versions that appear in combination with vendor in CPE dataset
        - vendor_version_to_cpe_: Each (vendor, version) tuple is mapped to a set of CPE items that appear in combination with this tuple in CPE dataset
        - vendors_: Just aggregates set of vendors, used for prunning later on.

        :param List[CPE] X: List of CPEs that will be used to build the dictionaries
        """
        sufficiently_long_cpes = self._filter_short_cpes(X)
        self.vendor_to_versions_ = {x.vendor: set() for x in sufficiently_long_cpes}
        self.vendors_ = set(self.vendor_to_versions_.keys())
        self.vendor_version_to_cpe_ = dict()

        for cpe in helpers.tqdm(sufficiently_long_cpes, desc="Fitting the CPE classifier"):
            self.vendor_to_versions_[cpe.vendor].add(cpe.version)
            if (cpe.vendor, cpe.version) not in self.vendor_version_to_cpe_:
                self.vendor_version_to_cpe_[(cpe.vendor, cpe.version)] = {cpe}
            else:
                self.vendor_version_to_cpe_[(cpe.vendor, cpe.version)].add(cpe)

    def predict(self, X: List[Tuple[str, str, str]]) -> List[Optional[Set[str]]]:
        """
        Will predict CPE uris for List of Tuples (vendor, product name, identified versions in product name)

        :param List[Tuple[str, str, str]] X: tuples (vendor, product name, identified versions in product name)
        :return List[Optional[Set[str]]]: List of CPE uris that correspond to given input, None if nothing was found.
        """
        return [self.predict_single_cert(x[0], x[1], x[2]) for x in helpers.tqdm(X, desc="Predicting")]

    def predict_single_cert(
        self,
        vendor: Optional[str],
        product_name: str,
        versions: Set[str],
        relax_version: bool = False,
        relax_title: bool = False,
    ) -> Optional[Set[str]]:
        """
        Predict List of CPE uris for triplet (vendor, product_name, list_of_version). The prediction is made as follows:
        1. Sanitize vendor name, lemmatize product name.
        2. Find vendors in CPE dataset that are related to the certificate
        3. Based on (vendors, versions) find all CPE items that are considered as candidates for match
        4. Compute string similarity of the candidate CPE matches and certificate name
        5. Evaluate best string similarity, if above threshold, declare it a match.
        6. If no CPE item is matched, try again but relax version and check CPEs that don't have their version specified.
        7. (Also, search for 100% CPE matches on item name instead of title.)

        :param Optional[str] vendor: manufacturer of the certificate
        :param str product_name: name of the certificate
        :param Set[str] versions: List of versions that appear in the certificate name
        :param bool relax_version: See step 6 above., defaults to False
        :param bool relax_title: See step 7 above, defaults to False
        :return Optional[Set[str]]: Set of matching CPE uris, None if no matches found
        """
        lemmatized_product_name = self._lemmatize_product_name(product_name)
        candidate_vendors = self._get_candidate_list_of_vendors(
            CPEClassifier._discard_trademark_symbols(vendor).lower() if vendor else vendor
        )
        candidates = self._get_candidate_cpe_matches(candidate_vendors, versions)

        ratings = [
            self._compute_best_match(cpe, lemmatized_product_name, candidate_vendors, versions, relax_title=relax_title)
            for cpe in candidates
        ]
        threshold = self.match_threshold if not relax_version else 100
        final_matches_aux: List[Tuple[float, CPE]] = list(filter(lambda x: x[0] >= threshold, zip(ratings, candidates)))
        final_matches_aux = sorted(final_matches_aux, key=operator.itemgetter(0, 1), reverse=True)
        final_matches: Optional[Set[str]] = set(
            [x[1].uri for x in final_matches_aux[: self.n_max_matches] if x[1].uri is not None]
        )

        if not relax_title and not final_matches:
            final_matches = self.predict_single_cert(
                vendor, product_name, versions, relax_version=relax_version, relax_title=True
            )

        if not relax_version and not final_matches:
            final_matches = self.predict_single_cert(
                vendor, product_name, {constants.CPE_VERSION_NA}, relax_version=True, relax_title=relax_title
            )

        return final_matches if final_matches else None

    def _compute_best_match(
        self,
        cpe: CPE,
        product_name: str,
        candidate_vendors: Optional[Set[str]],
        versions: Set[str],
        relax_title: bool = False,
    ) -> float:
        """
        Tries several different settings in which string similarity between CPE and certificate name is tested.
        For definition of string similarity, see rapidfuzz package on GitHub. Both token set ratio and partial ratio are tested,
        always both on CPE title and CPE item name.

        :param CPE cpe: CPE to test
        :param str product_name: name of the certificate
        :param Optional[Set[str]] candidate_vendors: vendors that appear in the certificate
        :param Set[str] versions: versions that appear in the certificate
        :param bool relax_title: if to relax title or not, defaults to False
        :return float: Maximal value of the four string similarities discussed above.
        """
        if relax_title:
            sanitized_title = (
                CPEClassifier._fully_sanitize_string(cpe.title)
                if cpe.title
                else CPEClassifier._fully_sanitize_string(
                    cpe.vendor + " " + cpe.item_name + " " + cpe.version + " " + cpe.update + " " + cpe.target_hw
                )
            )
        else:
            if cpe.title:
                sanitized_title = CPEClassifier._fully_sanitize_string(cpe.title)
            else:
                return 0

        sanitized_item_name = CPEClassifier._fully_sanitize_string(cpe.item_name)
        cert_stripped = CPEClassifier._strip_manufacturer_and_version(product_name, candidate_vendors, versions)
        standard_version_product_name = self._standardize_version_in_cert_name(product_name, versions)

        ratings = [
            fuzz.token_set_ratio(product_name, sanitized_title),
            fuzz.token_set_ratio(standard_version_product_name, sanitized_title),
            fuzz.partial_ratio(product_name, sanitized_title),
            fuzz.partial_ratio(standard_version_product_name, sanitized_title),
        ]

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
    def _strip_manufacturer_and_version(string: str, manufacturers: Optional[Set[str]], versions: Set[str]) -> str:
        to_strip = versions | manufacturers if manufacturers else versions
        for x in to_strip:
            string = string.lower().replace(CPEClassifier._replace_special_chars_with_space(x.lower()), "").strip()
        return string

    @staticmethod
    def _standardize_version_in_cert_name(string: str, detected_versions: Set[str]) -> str:
        for ver in detected_versions:
            version_regex = r"(" + r"(\bversion)\s*" + ver + r"+) | (\bv\s*" + ver + r"+)"
            string = re.sub(version_regex, " " + ver, string, flags=re.IGNORECASE)
        return string

    def _process_manufacturer(self, manufacturer: str, result: Set) -> Set[str]:
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
            candidate_result = self._get_candidate_list_of_vendors(" ".join(tokenized[1:]))
            return set(candidate_result) if candidate_result else set()

        return set(result) if result else set()

    def _get_candidate_list_of_vendors(self, manufacturer: Optional[str]) -> Set[str]:
        """
        Given manufacturer name, this method will find list of plausible vendors from CPE dataset that are likely related.

        :param Optional[str] manufacturer: manufacturer
        :return Set[str]: List of related manufacturers, None if nothing relevant is found.
        """
        result: Set[str] = set()
        if not manufacturer:
            return result

        splits = re.compile(r"[,/]").findall(manufacturer)

        if splits:
            vendor_tokens = set(
                itertools.chain.from_iterable([[x.strip() for x in manufacturer.split(s)] for s in splits])
            )
            result_aux = [self._get_candidate_list_of_vendors(x) for x in vendor_tokens]
            result_used = set(set(itertools.chain.from_iterable([x for x in result_aux if x])))
            return result_used if result_used else set()

        if manufacturer in self.vendors_:
            result.add(manufacturer)

        return self._process_manufacturer(manufacturer, result)

    def _get_candidate_vendor_version_pairs(
        self, cert_candidate_cpe_vendors: Set[str], cert_candidate_versions: Set[str]
    ) -> Optional[List[Tuple[str, str]]]:
        """
        Given parameters, will return Pairs (cpe_vendor, cpe_version) that are relevant to a given sample


        :param Set[str] cert_candidate_cpe_vendors: list of CPE vendors relevant to a sample
        :param Set[str] cert_candidate_versions: List of versions heuristically extracted from the sample name
        :return Optional[List[Tuple[str, str]]]: List of tuples (cpe_vendor, cpe_version) that can be used in the lookup table to search the CPE dataset.
        """

        def is_cpe_version_among_cert_versions(cpe_version: Optional[str], cert_versions: Set[str]) -> bool:
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

    def _get_candidate_cpe_matches(self, candidate_vendors: Set[str], candidate_versions: Set[str]) -> List[CPE]:
        """
        Given List of candidate vendors and candidate versions found in certificate, candidate CPE matches are found

        :param Set[str] candidate_vendors: List of version strings that were found in the certificate
        :param Set[str] candidate_versions: List of vendor strings that were found in the certificate
        :return List[CPE]: List of CPE records that could match, to be refined later
        """
        candidate_vendor_version_pairs = self._get_candidate_vendor_version_pairs(candidate_vendors, candidate_versions)
        return (
            list(
                itertools.chain.from_iterable([self.vendor_version_to_cpe_[x] for x in candidate_vendor_version_pairs])
            )
            if candidate_vendor_version_pairs
            else []
        )

    def _lemmatize_product_name(self, product_name: str) -> str:
        if not product_name:
            return product_name
        return " ".join([token.lemma_ for token in self.nlp(CPEClassifier._fully_sanitize_string(product_name))])

from __future__ import annotations

import itertools
import logging
import operator
import re
from re import Pattern

from rapidfuzz import fuzz

from sec_certs import cert_rules, constants
from sec_certs.sample.cpe import CPE
from sec_certs.utils.strings import (
    discard_trademark_symbols,
    fully_sanitize_string,
    lemmatize_product_name,
    load_spacy_model,
    standardize_version_in_cert_name,
)
from sec_certs.utils.tqdm import tqdm

logger = logging.getLogger(__name__)


class CPEClassifier:
    """
    Class that can predict CPE matches for certificate instances.
    Adheres to sklearn `sklearn.base.BaseEstimator` interface.
    Fit method is called on list of CPEs and build two look-up dictionaries, see description of attributes.
    """

    vendor_to_versions_: dict[str, set[str]]  # Key: CPE vendor, Value: versions of all CPE records of that vendor
    vendor_version_to_cpe_: dict[tuple[str, str], set[CPE]]  # Key: (CPE vendor, version), Value: CPEs (vendor, version)
    vendors_: set[str]

    def __init__(self, match_threshold: int = 80, n_max_matches: int = 10, spacy_model_to_use: str = "en_core_web_sm"):
        self.match_threshold = match_threshold
        self.n_max_matches = n_max_matches
        self.nlp = load_spacy_model(spacy_model_to_use)

    def fit(self, X: list[CPE], y: list[str] | None = None) -> CPEClassifier:
        """
        Just creates look-up structures from provided list of CPEs

        :param List[CPE] X: List of CPEs that can be matched with predict()
        :param Optional[List[str]] y: will be ignored, specified to adhere to sklearn BaseEstimator interface, defaults to None
        :return CPEClassifier: return self to allow method chaining
        """
        self._build_lookup_structures(X)
        return self

    @staticmethod
    def _filter_short_cpes(cpes: list[CPE]) -> list[CPE]:
        """
        Short CPE items are super easy to match with 100% rank, but they are hardly informative. This method discards them.

        :param List[CPE] cpes: List of CPEs to filtered
        :return List[CPE]: All CPEs in cpes variable which item name has at least 4 characters.
        """
        return list(filter(lambda x: x.item_name is not None and len(x.item_name) > 3, cpes))

    def _build_lookup_structures(self, X: list[CPE]) -> None:
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
        self.vendor_version_to_cpe_ = {}

        for cpe in tqdm(sufficiently_long_cpes, desc="Fitting the CPE classifier"):
            self.vendor_to_versions_[cpe.vendor].add(cpe.version)
            self.vendor_version_to_cpe_.setdefault((cpe.vendor, cpe.version), set()).add(cpe)

    def predict(self, X: list[tuple[str, str, str]]) -> list[set[str] | None]:
        """
        Will predict CPE uris for List of Tuples (vendor, product name, identified versions in product name)

        :param List[Tuple[str, str, str]] X: tuples (vendor, product name, identified versions in product name)
        :return List[Optional[Set[str]]]: List of CPE uris that correspond to given input, None if nothing was found.
        """
        return [self.predict_single_cert(x[0], x[1], x[2]) for x in tqdm(X, desc="Predicting")]

    def predict_single_cert(
        self,
        vendor: str | None,
        product_name: str,
        versions: set[str],
        relax_version: bool = False,
        relax_title: bool = False,
    ) -> set[str] | None:
        """
        Predict List of CPE uris for triplet (vendor, product_name, list_of_versions). The prediction is made as follows:
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
        lemmatized_product_name = lemmatize_product_name(self.nlp, product_name)
        candidate_vendors = self._get_candidate_list_of_vendors(
            discard_trademark_symbols(vendor).lower() if vendor else vendor
        )
        candidates = self._get_candidate_cpe_matches(candidate_vendors, versions)
        candidates = self._filter_candidates_by_platform(candidates, product_name)
        candidates = self._filter_candidates_by_update(candidates, lemmatized_product_name)

        ratings = [
            self._compute_best_match(cpe, lemmatized_product_name, candidate_vendors, versions, relax_title=relax_title)
            for cpe in candidates
        ]
        threshold = self.match_threshold if not relax_version else 100
        final_matches_aux: list[tuple[float, CPE]] = list(filter(lambda x: x[0] >= threshold, zip(ratings, candidates)))
        final_matches_aux = sorted(final_matches_aux, key=operator.itemgetter(0, 1), reverse=True)
        final_matches: set[str] | None = {
            x[1].uri for x in final_matches_aux[: self.n_max_matches] if x[1].uri is not None
        }

        if not relax_title and not final_matches:
            final_matches = self.predict_single_cert(
                vendor, product_name, versions, relax_version=relax_version, relax_title=True
            )

        if not relax_version and not final_matches:
            final_matches = self.predict_single_cert(
                vendor, product_name, {constants.CPE_VERSION_NA}, relax_version=True, relax_title=relax_title
            )

        return final_matches if final_matches else None

    def _filter_candidates_by_update(self, cpes: list[CPE], cert_title: str) -> list[CPE]:
        """
        Update means `service pack` or `release`.
        """

        def filter_condition(regex: Pattern, cpe: CPE, min_value: int, soft: bool = True):
            if matches := re.findall(regex, cpe.update):
                return int(re.findall(r"\d+", matches[0])[0]) >= min_value
            return soft

        update_regexes = [cert_rules.SERVICE_PACK_RE, cert_rules.RELEASE_RE]

        for update_regex in update_regexes:
            if matches := re.findall(update_regex, cert_title):
                min_value = min([int(re.findall(r"\d+", x)[0]) for x in matches])
                soft = not any(re.search(update_regex, cpe.update + str(cpe.title)) for cpe in cpes)
                return [x for x in cpes if filter_condition(update_regex, x, min_value, soft)]

        return cpes

    def _filter_candidates_by_platform(self, cpes: list[CPE], cert_title: str) -> list[CPE]:
        def filter_condition(cpe: CPE, cert_platforms: set[str]) -> bool:
            if not cert_platforms and cpe.target_hw == "*":
                return True
            if cert_platforms and cpe.target_hw == "*":
                return any(re.search(cert_rules.PLATFORM_REGEXES[x], str(cpe.title)) for x in cert_platforms)
            if not cert_platforms and cpe.target_hw != "*":
                return False
            if cert_platforms and cpe.target_hw != "*":
                target_hw_platforms = [
                    platform
                    for platform, regex in cert_rules.PLATFORM_REGEXES.items()
                    if re.search(regex, cpe.target_hw)
                ]
                assert len(target_hw_platforms) <= 1
                can_return_true = any(
                    re.search(cert_rules.PLATFORM_REGEXES[x], cpe.target_hw + str(cpe.title)) for x in cert_platforms
                )
                if not target_hw_platforms:
                    return can_return_true

                return can_return_true and target_hw_platforms[0] in cert_platforms
            return True

        crt_platforms = {
            platform for platform, regex in cert_rules.PLATFORM_REGEXES.items() if re.search(regex, cert_title)
        }
        return [x for x in cpes if filter_condition(x, crt_platforms)]

    def _compute_best_match(
        self,
        cpe: CPE,
        product_name: str,
        candidate_vendors: set[str] | None,
        versions: set[str],
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
                fully_sanitize_string(cpe.title)
                if cpe.title
                else fully_sanitize_string(
                    cpe.vendor + " " + cpe.item_name + " " + cpe.version + " " + cpe.update + " " + cpe.target_hw
                )
            )
        else:
            if cpe.title:
                sanitized_title = fully_sanitize_string(cpe.title)
            else:
                return 0

        # Sometimes, sanitization shortens CPE title to very short length. E.g., CPEs in Japanese unicode symbols that get all deteled.
        if len(sanitized_title) < 5:
            return 0

        sanitized_item_name = fully_sanitize_string(cpe.item_name)
        sanitized_cpe_stripped_manufacturer = re.sub(r"\b" + rf"{cpe.vendor}" + r"\b", "", sanitized_title)
        standard_version_product_name = standardize_version_in_cert_name(product_name, versions)

        # The expression below is currently unused, it could assist with some matches though
        # cert_stripped = strip_manufacturer_and_version(product_name, candidate_vendors, versions)

        # On some ratings, we require 100 match regardless of the treshold in settings.
        ratings = [
            fuzz.token_set_ratio(product_name, sanitized_title),
            fuzz.token_set_ratio(standard_version_product_name, sanitized_title),
            fuzz.partial_token_sort_ratio(product_name, sanitized_title, score_cutoff=100),
            fuzz.partial_token_sort_ratio(standard_version_product_name, sanitized_title, score_cutoff=100),
            fuzz.partial_ratio(product_name, sanitized_title, score_cutoff=100),
            fuzz.partial_ratio(standard_version_product_name, sanitized_title, score_cutoff=100),
        ]

        # Big-IP has dumb CPEs that contain only that string in item name, which leads to false positives.
        if relax_title and cpe.item_name != "big-ip":
            ratings += [
                fuzz.token_set_ratio(product_name, sanitized_cpe_stripped_manufacturer, score_cutoff=100),
                fuzz.partial_ratio(product_name, sanitized_cpe_stripped_manufacturer, score_cutoff=100),
                fuzz.token_set_ratio(product_name, sanitized_item_name, score_cutoff=100),
                fuzz.partial_ratio(product_name, sanitized_item_name, score_cutoff=100),
            ]

        return max(ratings)

    def _process_manufacturer(self, manufacturer: str, result: set) -> set[str]:
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

    def _get_candidate_list_of_vendors(self, manufacturer: str | None) -> set[str]:
        """
        Given manufacturer name, this method will find list of plausible vendors from CPE dataset that are likely related.

        :param Optional[str] manufacturer: manufacturer
        :return Set[str]: List of related manufacturers, None if nothing relevant is found.
        """
        result: set[str] = set()
        if not manufacturer:
            return result

        splits = re.compile(r"[,/]").findall(manufacturer)

        if splits:
            vendor_tokens = set(
                itertools.chain.from_iterable([x.strip() for x in manufacturer.split(s)] for s in splits)
            )
            result_aux = [self._get_candidate_list_of_vendors(x) for x in vendor_tokens]
            result_used = set(itertools.chain.from_iterable(x for x in result_aux if x))
            return result_used if result_used else set()

        if manufacturer in self.vendors_:
            result.add(manufacturer)

        return self._process_manufacturer(manufacturer, result)

    def _get_candidate_vendor_version_pairs(
        self, cert_candidate_cpe_vendors: set[str], cert_candidate_versions: set[str]
    ) -> list[tuple[str, str]] | None:
        """
        Given parameters, will return Pairs (cpe_vendor, cpe_version) that are relevant to a given sample


        :param Set[str] cert_candidate_cpe_vendors: list of CPE vendors relevant to a sample
        :param Set[str] cert_candidate_versions: List of versions heuristically extracted from the sample name
        :return Optional[List[Tuple[str, str]]]: List of tuples (cpe_vendor, cpe_version) that can be used in the lookup table to search the CPE dataset.
        """

        def is_cpe_version_among_cert_versions(cpe_version: str | None, cert_versions: set[str]) -> bool:
            def simple_startswith(seeked_version: str, checked_string: str) -> bool:
                if seeked_version == checked_string:
                    return True
                return checked_string.startswith(seeked_version) and not checked_string[len(seeked_version)].isdigit()

            if not cpe_version:
                return False
            just_numbers = r"(\d{1,5})(\.\d{1,5})"

            # This assures that on cert version with at least two tokens, we don't match only one-token CPE.
            # E.g. cert with version 7.6 must not match CPE record of version 7
            if len(cert_versions) == 1 and len(list(cert_versions)[0]) >= 3 and len(cpe_version) < 3:
                return False

            # Except from startswith stuff, this also mandates that for long enough cert vesions (e.g. `3.1`) we do not
            # match too short CPE versions, e.g. `3`
            for v in cert_versions:
                if (
                    (simple_startswith(v, cpe_version) and re.search(just_numbers, cpe_version))
                    or simple_startswith(cpe_version, v)
                ) and (len(v) < 3 or len(cpe_version) >= 3):
                    return True
            return False

        if not cert_candidate_cpe_vendors:
            return None

        candidate_vendor_version_pairs: list[tuple[str, str]] = []
        for vendor in cert_candidate_cpe_vendors:
            viable_cpe_versions = self.vendor_to_versions_.get(vendor, set())
            matched_cpe_versions = [
                x for x in viable_cpe_versions if is_cpe_version_among_cert_versions(x, cert_candidate_versions)
            ]
            candidate_vendor_version_pairs.extend([(vendor, x) for x in matched_cpe_versions])
        return candidate_vendor_version_pairs

    def _get_candidate_cpe_matches(self, candidate_vendors: set[str], candidate_versions: set[str]) -> list[CPE]:
        """
        Given List of candidate vendors and candidate versions found in certificate, candidate CPE matches are found

        :param Set[str] candidate_vendors: List of version strings that were found in the certificate
        :param Set[str] candidate_versions: List of vendor strings that were found in the certificate
        :return List[CPE]: List of CPE records that could match, to be refined later
        """
        candidate_vendor_version_pairs = self._get_candidate_vendor_version_pairs(candidate_vendors, candidate_versions)
        return (
            list(itertools.chain.from_iterable(self.vendor_version_to_cpe_[x] for x in candidate_vendor_version_pairs))
            if candidate_vendor_version_pairs
            else []
        )

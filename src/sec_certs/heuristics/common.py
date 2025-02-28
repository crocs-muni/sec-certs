from __future__ import annotations

import itertools
import logging
import re
from collections.abc import Iterable

from tqdm import tqdm

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.dataset import CertSubType
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.model.transitive_vulnerability_finder import TransitiveVulnerabilityFinder
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.cpe import CPE
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.utils.profiling import staged

logger = logging.getLogger(__name__)


@staged(logger, "Computing heuristics: Finding CPE matches for certificates")
def compute_cpe_heuristics(cpe_dataset: CPEDataset, certs: Iterable[CertSubType]) -> None:
    """
    Computes matching CPEs for the certificates.
    """
    WINDOWS_WEAK_CPES: set[CPE] = {
        CPE("", "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x64:*", "Microsoft Windows on X64"),
        CPE("", "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x86:*", "Microsoft Windows on X86"),
    }

    def filter_condition(cpe: CPE) -> bool:
        """
        Filters out very weak CPE matches that don't improve our database.
        """
        if cpe.title and (cpe.version == "-" or cpe.version == "*") and not any(char.isdigit() for char in cpe.title):
            return False
        if (
            not cpe.title
            and cpe.item_name
            and (cpe.version == "-" or cpe.version == "*")
            and not any(char.isdigit() for char in cpe.item_name)
        ):
            return False
        if re.match(constants.RELEASE_CANDIDATE_REGEX, cpe.update):
            return False
        return cpe not in WINDOWS_WEAK_CPES

    logger.info("Computing CPE heuristics.")
    clf = CPEClassifier(config.cpe_matching_threshold, config.cpe_n_max_matches)
    clf.fit([x for x in cpe_dataset if filter_condition(x)])

    for cert in tqdm(certs, desc="Predicting CPE matches with the classifier"):
        cert.compute_heuristics_version()
        cert.heuristics.cpe_matches = (
            clf.predict_single_cert(cert.manufacturer, cert.name, cert.heuristics.extracted_versions)
            if cert.name
            else None
        )


def get_all_cpes_in_dataset(cpe_dset: CPEDataset, certs: Iterable[Certificate]) -> set[CPE]:
    cpe_matches = [[cpe_dset.cpes[y] for y in x.heuristics.cpe_matches] for x in certs if x.heuristics.cpe_matches]
    return set(itertools.chain.from_iterable(cpe_matches))


def enrich_automated_cpes_with_manual_labels(certs: Iterable[Certificate]) -> None:
    """
    Prior to CVE matching, it is wise to expand the database of automatic CPE matches with those that were manually assigned.
    """
    for cert in certs:
        if not cert.heuristics.cpe_matches and cert.heuristics.verified_cpe_matches:
            cert.heuristics.cpe_matches = cert.heuristics.verified_cpe_matches
        elif cert.heuristics.cpe_matches and cert.heuristics.verified_cpe_matches:
            cert.heuristics.cpe_matches = set(cert.heuristics.cpe_matches).union(
                set(cert.heuristics.verified_cpe_matches)
            )


@staged(logger, "Computing heuristics: CVEs in certificates.")
def compute_related_cves(
    cpe_dset: CPEDataset, cve_dset: CVEDataset, cpe_match_dict: dict, certs: Iterable[Certificate]
) -> None:
    """
    Computes CVEs for the certificates, given their CPE matches.
    """

    logger.info("Computing related CVEs")
    if not cve_dset.look_up_dicts_built:
        all_cpes = get_all_cpes_in_dataset(cpe_dset, certs)
        cve_dset.build_lookup_dict(cpe_match_dict, all_cpes)

    enrich_automated_cpes_with_manual_labels(certs)
    cpe_rich_certs = [x for x in certs if x.heuristics.cpe_matches]

    for cert in tqdm(cpe_rich_certs, desc="Computing related CVES"):
        related_cves = cve_dset.get_cves_from_matched_cpe_uris(cert.heuristics.cpe_matches)
        cert.heuristics.related_cves = related_cves if related_cves else None

    n_vulnerable = len([x for x in cpe_rich_certs if x.heuristics.related_cves])
    n_vulnerabilities = sum([len(x.heuristics.related_cves) for x in cpe_rich_certs if x.heuristics.related_cves])
    logger.info(
        f"In total, we identified {n_vulnerabilities} vulnerabilities in {n_vulnerable} vulnerable certificates."
    )


@staged(
    logger,
    "Computing heuristics: Transitive vulnerabilities in referenc(ed/ing) certificates.",
)
def compute_transitive_vulnerabilities(certs: dict[str, CertSubType]) -> None:
    logger.info("Computing transitive vulnerabilities")
    if not certs:
        return

    some_cert = next(iter(certs.values()))

    if isinstance(some_cert, FIPSCertificate):
        transitive_cve_finder = TransitiveVulnerabilityFinder(lambda cert: str(cert.cert_id))
        transitive_cve_finder.fit(certs, lambda cert: cert.heuristics.policy_processed_references)
    elif isinstance(some_cert, CCCertificate):
        transitive_cve_finder = TransitiveVulnerabilityFinder(lambda cert: str(cert.heuristics.cert_id))
        transitive_cve_finder.fit(certs, lambda cert: cert.heuristics.report_references)
    else:
        raise ValueError("Members of `certs` object must be either FIPSCertificate or CCCertificate instances.")

    for cert in certs.values():
        transitive_cve = transitive_cve_finder.predict_single_cert(cert.dgst)
        cert.heuristics.direct_transitive_cves = transitive_cve.direct_transitive_cves
        cert.heuristics.indirect_transitive_cves = transitive_cve.indirect_transitive_cves

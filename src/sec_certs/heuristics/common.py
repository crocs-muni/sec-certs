from __future__ import annotations

import itertools
import logging
import re
from collections.abc import Iterable

from sec_certs import constants
from sec_certs.cert_rules import security_level_csv_scan
from sec_certs.configuration import config
from sec_certs.dataset.cc_scheme import CCSchemeDataset
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.dataset import CertSubType
from sec_certs.dataset.protection_profile import ProtectionProfileDataset
from sec_certs.model.cc_matching import CCSchemeMatcher
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.model.reference_finder import ReferenceFinder
from sec_certs.model.sar_transformer import SARTransformer
from sec_certs.model.transitive_vulnerability_finder import TransitiveVulnerabilityFinder
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cc_certificate_id import CertificateId
from sec_certs.sample.cc_scheme import EntryType
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.cpe import CPE
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.utils.helpers import choose_lowest_eal
from sec_certs.utils.profiling import staged
from sec_certs.utils.tqdm import tqdm

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


@staged(logger, "Computing heuristics: Linking certificates to protection profiles")
def link_to_protection_profiles(
    certs: Iterable[CCCertificate],
    pp_dset: ProtectionProfileDataset,
) -> None:
    for cert in certs:
        if cert.protection_profile_links:
            pps = [pp_dset.get_pp_by_pp_link(x) for x in cert.protection_profile_links]
            pp_digests = {x.dgst for x in pps if x}
            cert.heuristics.protection_profiles = pp_digests if pp_digests else None
    logger.info(
        f"Linked {len([x for x in certs if x.heuristics.protection_profiles])} certificates to their protection profiles."
    )


@staged(logger, "Computing heuristics: references between certificates.")
def compute_references(certs: dict[str, CCCertificate]) -> None:
    def ref_lookup(kw_attr):
        def func(cert):
            kws = getattr(cert.pdf_data, kw_attr)
            if not kws:
                return set()
            res = set()
            for scheme, matches in kws["cc_cert_id"].items():
                for match in matches:
                    try:
                        canonical = CertificateId(scheme, match).canonical
                        res.add(canonical)
                    except Exception:
                        res.add(match)
            return res

        return func

    for ref_source in ("report", "st"):
        kw_source = f"{ref_source}_keywords"
        dep_attr = f"{ref_source}_references"

        finder = ReferenceFinder()
        finder.fit(certs, lambda cert: cert.heuristics.cert_id, ref_lookup(kw_source))  # type: ignore

        for dgst in certs:
            setattr(certs[dgst].heuristics, dep_attr, finder.predict_single_cert(dgst, keep_unknowns=False))


@staged(logger, "Computing heuristics: Deriving information about certificate ids from artifacts.")
def compute_normalized_cert_ids(certs: Iterable[CCCertificate]) -> None:
    for cert in certs:
        cert.compute_heuristics_cert_id()


@staged(logger, "Computing heuristics: Matching scheme data.")
def compute_scheme_data(scheme_dset: CCSchemeDataset, certs: dict[str, CCCertificate]):
    for scheme in scheme_dset:
        if certified := scheme.lists.get(EntryType.Certified):
            active_certs = [cert for cert in certs.values() if cert.status == "active"]
            matches, _ = CCSchemeMatcher.match_all(certified, scheme.country, active_certs)
            for dgst, match in matches.items():
                certs[dgst].heuristics.scheme_data = match
        if archived := scheme.lists.get(EntryType.Archived):
            archived_certs = [cert for cert in certs.values() if cert.status == "archived"]
            matches, _ = CCSchemeMatcher.match_all(archived, scheme.country, archived_certs)
            for dgst, match in matches.items():
                certs[dgst].heuristics.scheme_data = match


@staged(logger, "Computing heuristics: Deriving information about laboratories involved in certification.")
def compute_cert_labs(certs: Iterable[CCCertificate]) -> None:
    for cert in certs:
        cert.compute_heuristics_cert_lab()


@staged(logger, "Computing heuristics: SARs")
def compute_sars(certs: Iterable[CCCertificate]) -> None:
    transformer = SARTransformer().fit(certs)
    for cert in certs:
        cert.heuristics.extracted_sars = transformer.transform_single_cert(cert)


@staged(logger, "Computing heuristics: EALs")
def compute_eals(certs: Iterable[CCCertificate], pp_dataset: ProtectionProfileDataset) -> None:
    def compute_cert_eal(cert: CCCertificate) -> str | None:
        res = [x for x in cert.security_level if re.match(security_level_csv_scan, x)]
        if res and len(res) == 1:
            return res[0]
        elif res and len(res) > 1:
            raise ValueError(f"Expected single EAL in security_level field, got: {res}")
        else:
            if cert.heuristics.protection_profiles:
                eals: set[str] = {
                    eal for x in cert.heuristics.protection_profiles if (eal := pp_dataset[x].web_data.eal) is not None
                }
                return choose_lowest_eal(eals)
            else:
                return None

    for cert in certs:
        cert.heuristics.eal = compute_cert_eal(cert)

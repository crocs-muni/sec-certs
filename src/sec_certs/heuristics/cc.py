import logging
from collections.abc import Iterable

from sec_certs.dataset.cc_scheme import CCSchemeDataset
from sec_certs.dataset.protection_profile import ProtectionProfileDataset
from sec_certs.model.cc_matching import CCSchemeMatcher
from sec_certs.model.reference_finder import ReferenceFinder
from sec_certs.model.sar_transformer import SARTransformer
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cc_certificate_id import CertificateId
from sec_certs.sample.cc_scheme import EntryType
from sec_certs.utils.profiling import staged

logger = logging.getLogger(__name__)


@staged(logger, "Computing heuristics: Linking certificates to protection profiles")
def link_to_protection_profiles(pp_dset: ProtectionProfileDataset, certs: Iterable[CCCertificate]) -> None:
    for cert in certs:
        if cert.protection_profiles is None:
            continue
        cert.protection_profiles = {pp_dset.pps.get((x.pp_name, x.pp_link), x) for x in cert.protection_profiles}


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

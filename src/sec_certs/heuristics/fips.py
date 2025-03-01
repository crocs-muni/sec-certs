from __future__ import annotations

import logging

from sec_certs.model.reference_finder import ReferenceFinder
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.utils.profiling import staged

logger = logging.getLogger(__name__)


@staged(logger, "Computing heuristics: references between certificates.")
def compute_references(certs: dict[str, FIPSCertificate], keep_unknowns: bool = False) -> None:
    # Previously, a following procedure was used to prune reference_candidates:
    #   - A set of algorithms was obtained via self.auxiliary_datasets.algorithm_dset.get_algorithms_by_id(reference_candidate)
    #   - If any of these algorithms had the same vendor as the reference_candidate, the candidate was rejected
    #   - The rationale is that if an ID appears in a certificate s.t. an algorithm with the same ID was produced by the same vendor, the reference likely refers to alg.
    #   - Such reference should then be discarded.
    #   - We are uncertain of the effectivity of such measure, disabling it for now.
    logger.info("Computing references")
    for cert in certs.values():
        cert.prune_referenced_cert_ids()

    policy_reference_finder = ReferenceFinder()
    policy_reference_finder.fit(
        certs,
        lambda cert: str(cert.cert_id),
        lambda cert: cert.heuristics.policy_prunned_references,
    )

    module_reference_finder = ReferenceFinder()
    module_reference_finder.fit(
        certs,
        lambda cert: str(cert.cert_id),
        lambda cert: cert.heuristics.module_prunned_references,
    )

    for cert in certs.values():
        cert.heuristics.policy_processed_references = policy_reference_finder.predict_single_cert(
            cert.dgst, keep_unknowns
        )
        cert.heuristics.module_processed_references = module_reference_finder.predict_single_cert(
            cert.dgst, keep_unknowns
        )

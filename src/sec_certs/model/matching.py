from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from heapq import heappop, heappush
from typing import Any, Generic, TypeVar

from rapidfuzz import fuzz

from sec_certs.sample.certificate import Certificate

CertSubType = TypeVar("CertSubType", bound=Certificate)


class AbstractMatcher(Generic[CertSubType], ABC):
    entry: Any

    @abstractmethod
    def match(self, cert: CertSubType) -> float:
        raise NotImplementedError

    def _compute_match(self, one: str, other: str) -> float:
        return max(
            [
                fuzz.token_set_ratio(one, other),
                fuzz.partial_token_sort_ratio(one, other, score_cutoff=100),
                fuzz.partial_ratio(one, other, score_cutoff=100),
            ]
        )

    @staticmethod
    def _match_certs(matchers: Sequence[AbstractMatcher], certs: list[CertSubType], threshold: float):
        scores: list[tuple[float, int, int]] = []
        matched_is: set[int] = set()
        matched_js: set[int] = set()
        for i, cert in enumerate(certs):
            for j, matcher in enumerate(matchers):
                score = matcher.match(cert)
                triple = (100 - score, i, j)
                heappush(scores, triple)
        results = {}
        for triple in (heappop(scores) for _ in range(len(scores))):
            inv_score, i, j = triple
            # Do not match already matched entries/certs.
            if i in matched_is or j in matched_js:
                continue
            # Compute the actual score from the inverse.
            score = 100 - inv_score
            # Do not match if we are below threshold, all the following will be as well.
            if score < threshold:
                break
            # Match cert dgst to entry
            matched_is.add(i)
            matched_js.add(j)
            cert = certs[i]
            entry = matchers[j].entry
            results[cert.dgst] = entry
        return results

import typing
from abc import ABC, abstractmethod
from heapq import heappop, heappush
from typing import Generic

from sec_certs.sample.certificate import Certificate

CertSubType = typing.TypeVar("CertSubType", bound=Certificate)


class AbstractMatcher(Generic[CertSubType], ABC):
    @abstractmethod
    def match(self, cert: CertSubType) -> float:
        raise NotImplementedError

    @staticmethod
    def _match_certs(matchers, certs, threshold):
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
            cert = certs[i]
            entry = matchers[j].entry
            results[cert.dgst] = entry
        return results

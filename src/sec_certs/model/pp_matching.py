from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sec_certs.model.matching import AbstractMatcher

if TYPE_CHECKING:
    from sec_certs.sample.pp_scheme import PPSchemeEntry
    from sec_certs.sample.protection_profile import ProtectionProfile

_EAL_RE = re.compile(r"^EAL\d")


class PPSchemeMatcher(AbstractMatcher["ProtectionProfile"]):
    """
    Heuristic matcher between PPSchemeEntry objects (scraped from national portals)
    and ProtectionProfile certificates (from the CC portal).
    """

    def __init__(self, entry: PPSchemeEntry) -> None:
        self.entry = entry

    def match(self, cert: ProtectionProfile) -> float:
        entry = self.entry

        # Identical PP link → definite match
        if entry.pp_link and cert.web_data.pp_link and entry.pp_link == cert.web_data.pp_link:
            return 100.0

        name_score = self._compute_match(entry.name, cert.web_data.name or "")

        date_score = 100.0 if entry.not_valid_before == cert.web_data.not_valid_before else 0.0

        entry_eals = {x for x in entry.security_level if _EAL_RE.match(x)}
        cert_eals = {x for x in (cert.web_data.security_level or set()) if _EAL_RE.match(x)}
        eal_score = (100.0 if entry_eals == cert_eals else 0.0) if entry_eals and cert_eals else 0.0

        return (6 * name_score + 2 * date_score + 2 * eal_score) / 10

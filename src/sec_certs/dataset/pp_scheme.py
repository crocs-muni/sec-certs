from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.pp_scheme import PP_SCHEME_SCRAPERS, PPSchemeRecord
from sec_certs.serialization.json import ComplexSerializableType

if TYPE_CHECKING:
    from sec_certs.sample.pp_scheme import PPScraper

logger = logging.getLogger(__name__)


class PPSchemeDataset(JSONPathDataset, ComplexSerializableType):
    """
    A dataset of Protection Profile records scraped from national scheme portals.

    Holds a mapping of scheme code (e.g. "US", "SE", "KR", "FR") to a list of
    PPSchemeRecord objects scraped from the corresponding national portal.
    """

    def __init__(self, schemes: dict[str, list[PPSchemeRecord]], json_path: str | Path | None = None):
        super().__init__(json_path)
        self.schemes = schemes

    @property
    def serialized_attributes(self) -> list[str]:
        return ["schemes"]

    def __iter__(self):
        for records in self.schemes.values():
            yield from records

    def __len__(self) -> int:
        return sum(len(v) for v in self.schemes.values())

    def __getitem__(self, scheme: str) -> list[PPSchemeRecord]:
        return self.schemes[scheme.upper()]

    def to_dict(self):
        return {"schemes": self.schemes}

    @classmethod
    def from_dict(cls, dct: Mapping) -> PPSchemeDataset:
        return cls(dct["schemes"])

    @classmethod
    def from_scrapers(
        cls,
        scrapers: list[PPScraper] | None = None,
        json_path: str | Path | None = None,
    ) -> PPSchemeDataset:
        """Scrape all national scheme portals and return a PPSchemeDataset."""
        if scrapers is None:
            scrapers = PP_SCHEME_SCRAPERS
        schemes: dict[str, list[PPSchemeRecord]] = {}
        for scraper in scrapers:
            try:
                records = scraper.scrape()
                schemes.setdefault(scraper.scheme, []).extend(records)
                logger.info("Scraped %d records from scheme %s.", len(records), scraper.scheme)
            except Exception as e:
                logger.warning("Failed to scrape scheme %s: %s", scraper.scheme, e)
        return cls(schemes, json_path=json_path)

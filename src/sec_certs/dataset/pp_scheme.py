from __future__ import annotations

import logging

from sec_certs.sample.pp_scheme import PP_SCHEME_SCRAPERS, PPSchemeRecord, PPScraper

logger = logging.getLogger(__name__)


class PPSchemeDataset:
    # Dataset of PPSchemeRecord objects scraped from national scheme portals

    def __init__(self, schemes: dict[str, list[PPSchemeRecord]]):
        self.schemes = schemes

    def __iter__(self):
        for records in self.schemes.values():
            yield from records

    def __len__(self) -> int:
        return sum(len(v) for v in self.schemes.values())

    @classmethod
    def from_scrapers(cls, scrapers: list[PPScraper] | None = None) -> PPSchemeDataset:
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
        return cls(schemes)

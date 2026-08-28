from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Final, cast

import dateutil
from bs4 import BeautifulSoup, Tag

from sec_certs import constants
from sec_certs.cert_rules import FIPS_ALGS_IN_TABLE

if TYPE_CHECKING:
    from sec_certs.sample.fips import FIPSCertificate


class FIPSHTMLParser:
    def __init__(self, soup: BeautifulSoup):
        self._soup = soup

    def get_web_data_and_algorithms(self) -> tuple[set[str], FIPSCertificate.WebData]:
        from sec_certs.sample.fips import FIPSCertificate

        divs = self._soup.find_all("div", class_="panel panel-default")
        details_div, vendor_div, related_files_div, validation_history_div = divs
        details_dict = self._build_details_dict(details_div)

        vendor_dict = self._build_vendor_dict(vendor_div)
        related_files_dict = self._build_related_files_dict(related_files_div)
        validation_history_dict = self._build_validation_history_dict(validation_history_div)

        algorithms = set()
        if "algorithms" in details_dict:
            algorithms_data = details_dict.pop("algorithms")
            for category, alg_ids in algorithms_data.items():
                algorithms |= {category + x for x in alg_ids}

        return algorithms, FIPSCertificate.WebData(
            **{**details_dict, **vendor_dict, **related_files_dict, **validation_history_dict}
        )

    def _build_details_dict(self, details_div: Tag) -> dict[str, Any]:
        def parse_single_detail_entry(key: str, entry: Tag) -> tuple[str, Any]:
            normalized_key = DETAILS_KEY_NORMALIZATION_DICT[key]
            normalization_func = DETAILS_KEY_TO_NORMALIZATION_FUNCTION.get(normalized_key)
            normalized_entry = (
                FIPSHTMLParser.normalize_string(entry.text) if not normalization_func else normalization_func(entry)
            )
            return normalized_key, normalized_entry

        rows = details_div.find_all("div", class_="row padrow")
        entries = zip(
            [cast(Tag, x.find("div", class_="col-md-3")) for x in rows],
            [cast(Tag, x.find("div", class_="col-md-9")) for x in rows],
        )
        normalized_entries = [(FIPSHTMLParser.normalize_string(key.text), entry) for key, entry in entries]
        parsed_entries = [
            parse_single_detail_entry(*x) for x in normalized_entries if x[0] in DETAILS_KEY_NORMALIZATION_DICT
        ]
        details = dict(parsed_entries)

        if "caveat" in details:
            details["mentioned_certs"] = FIPSHTMLParser.get_mentioned_certs_from_caveat(details["caveat"])

        # Temporarily disabled, as this isn't extracting anything useful. Only UNKNOWN#1-9 algs were extracted over whole dataset.
        # if "description" in entries:
        #     algs = FIPSHTMLParser.get_algs_from_description(entries["description"])
        #     if "algorithms" in entries:
        #         entries["algorithms"].update({"UNKNOWN": x for x in algs})
        #     else:
        #         entries["algorithms"] = {"UNKNOWN": x for x in algs}

        return details

    @staticmethod
    def _build_vendor_dict(vendor_div: Tag) -> dict[str, Any]:
        if not (link := vendor_div.find("a")):
            panel_body = cast(Tag, vendor_div.find("div", class_="panel-body"))
            return {"vendor_url": None, "vendor": str(next(panel_body.children)).strip()}
        return {"vendor_url": link.get("href"), "vendor": link.text.strip()}

    @staticmethod
    def _build_related_files_dict(related_files_div: Tag) -> dict[str, Any]:
        if cert_link := [x for x in related_files_div.find_all("a") if "Certificate" in x.text]:
            href = cast(str, cert_link[0].get("href"))
            return {"certificate_pdf_url": constants.FIPS_BASE_URL + href}
        return {"certificate_pdf_url": None}

    @staticmethod
    def _build_validation_history_dict(validation_history_div: Tag) -> dict[str, Any]:
        from sec_certs.sample.fips import FIPSCertificate

        def parse_row(row):
            validation_date, validation_type, lab = row.find_all("td")
            return FIPSCertificate.ValidationHistoryEntry(
                dateutil.parser.parse(validation_date.text).date(), validation_type.text, lab.text
            )

        rows = cast(Tag, validation_history_div.find("tbody")).find_all("tr")
        history: list[FIPSCertificate.ValidationHistoryEntry] | None = [parse_row(x) for x in rows] if rows else None
        return {"validation_history": history}

    @staticmethod
    def get_mentioned_certs_from_caveat(caveat: str) -> dict[str, int]:
        ids_found: dict[str, int] = {}
        r_key = r"(?P<word>\w+)?\s?(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)+(?P<id>\d+)"
        for m in re.finditer(r_key, caveat):
            if m.group("word") and m.group("word").lower() in {"rsa", "shs", "dsa", "pkcs", "aes"}:
                continue
            if m.group("id") in ids_found:
                ids_found[m.group("id")] += 1
            else:
                ids_found[m.group("id")] = 1
        return ids_found

    @staticmethod
    def get_algs_from_description(description: str) -> set[str]:
        return {m.group() for m in re.finditer(FIPS_ALGS_IN_TABLE, description)}

    @staticmethod
    def parse_algorithms(algorithms_div: Tag) -> dict[str, set[str]]:
        dct: dict[str, set[str]] = {}
        table = algorithms_div.find("tbody")
        # Two types of organization on the CMVP website:
        #  - One is a table with algo references in text
        #  - Other is just divs for rows, one per algo
        if table:
            rows = table.find_all("tr")
            for row in rows:
                cells = row.find_all("td")
                dct[str(cells[0].text)] = {m.group() for m in re.finditer(FIPS_ALGS_IN_TABLE, cells[1].text)}
        else:
            rows = algorithms_div.find_all("div", class_="col-md-12")
            for row in rows:
                category = cast(Tag, row.find("div", class_="col-md-3"))
                algorithm = cast(Tag, row.find("div", class_="col-md-4"))
                dct[str(category.text)] = {str(algorithm.text).strip()}
        return dct

    @staticmethod
    def normalize_type(mod_type: Tag) -> str:
        tag_text = str(mod_type.text).strip()
        return "-".join(s.capitalize() for s in tag_text.split("-"))

    @staticmethod
    def normalize_string(string: str) -> str:
        return " ".join(string.split())

    @staticmethod
    def parse_tested_configurations(tested_configurations: Tag) -> list[str] | None:
        configurations = [y.text for y in tested_configurations.find_all("li")]
        return None if configurations == ["N/A"] else configurations

    @staticmethod
    def normalize_embodiment(embodiment_element: Tag) -> str:
        text = FIPSHTMLParser.normalize_string(embodiment_element.text)
        embodiment_normalization_dict = {
            "Multi-chip embedded": "Multi-Chip Embedded",
            "Multi-chip Standalone": "Multi-Chip Stand Alone",
            "Multi-chip standalone": "Multi-Chip Stand Alone",
            "Single-chip": "Single Chip",
        }
        return embodiment_normalization_dict.get(text, text)


DETAILS_KEY_NORMALIZATION_DICT: Final[dict[str, str]] = {
    "Module Name": "module_name",
    "Standard": "standard",
    "Status": "status",
    "Sunset Date": "date_sunset",
    "Validation Dates": "date_validation",
    "Overall Level": "level",
    "Caveat": "caveat",
    "Security Level Exceptions": "exceptions",
    "Module Type": "module_type",
    "Embodiment": "embodiment",
    "Approved Algorithms": "algorithms",
    "Tested Configuration(s)": "tested_conf",
    "Description": "description",
    "Historical Reason": "historical_reason",
    "Hardware Versions": "hw_versions",
    "Firmware Versions": "fw_versions",
    "Revoked Reason": "revoked_reason",
    "Revoked Link": "revoked_link",
    "Software Versions": "sw_versions",
    "Product URL": "product_url",
}

DETAILS_KEY_TO_NORMALIZATION_FUNCTION: dict[str, Callable] = {
    "date_sunset": lambda x: dateutil.parser.parse(x.text).date(),
    "algorithms": getattr(FIPSHTMLParser, "parse_algorithms"),
    "tested_conf": getattr(FIPSHTMLParser, "parse_tested_configurations"),
    "exceptions": lambda x: [y.text for y in x.find_all("li")],
    "status": lambda x: FIPSHTMLParser.normalize_string(x.text).lower(),
    "level": lambda x: int(FIPSHTMLParser.normalize_string(x.text)),
    "embodiment": getattr(FIPSHTMLParser, "normalize_embodiment"),
    "module_type": getattr(FIPSHTMLParser, "normalize_type"),
}

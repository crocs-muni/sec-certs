from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from bs4 import Tag

from sec_certs import constants

logger = logging.getLogger(__name__)


def html_row_get_maintenance_div(cell: Tag) -> Tag | None:
    divs = cell.find_all("div")
    for d in divs:
        if d.find("div") and d.stripped_strings and list(d.stripped_strings)[0] == "Maintenance Report(s)":
            return d
    return None


def parse_maintenance_div(main_div: Tag) -> list[tuple[Any, ...]]:
    possible_updates = list(main_div.find_all("li"))
    maintenance_updates = set()
    for u in possible_updates:
        text = list(u.stripped_strings)[0]
        main_date = datetime.strptime(text.split(" ")[0], "%Y-%m-%d").date() if text else None
        main_title = text.split("– ")[1]
        main_report_link = None
        main_st_link = None
        links = u.find_all("a")
        for link in links:
            if link.get("title").startswith("Maintenance Report:"):
                main_report_link = constants.CC_PORTAL_BASE_URL + link.get("href")
            elif link.get("title").startswith("Maintenance ST"):
                main_st_link = constants.CC_PORTAL_BASE_URL + link.get("href")
            else:
                logger.error("Unknown link in Maintenance part!")
        maintenance_updates.add((main_date, main_title, main_report_link, main_st_link))
    return list(maintenance_updates)

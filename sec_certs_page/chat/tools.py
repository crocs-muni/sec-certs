"""
title: Tool for searching sec-certs.org
author: Jan Jancar
description: This tool allows users to search for certificates on the sec-certs.org website.
requirements: requests, beautifulsoup4
version: 1.0
license: MIT
"""

import json
from typing import Literal

import requests
from bs4 import BeautifulSoup

# Note, this file is a "tool" for the Open WebUI service, it is not a part of this application.


class Tools:
    def __init__(self):
        pass

    def search(self, query: str, scheme: Literal["cc"] | Literal["fips"], page: int = 1) -> str:
        """
        Search the sec-certs.org website for CC or FIPS 140 certificates and output results
        in JSON.

        :param query: The search term to look for in the certificates.
        :param scheme: The scheme to search in, either "cc" for Common Criteria or "fips" for FIPS.
        :param page: The page number to retrieve results from.
        :return: A string containing the search results formatted for display.
        """

        url = f"https://sec-certs.org/{scheme}/mergedsearch/"
        per_page = 100
        params = {"searchType": "by-name", "q": query, "page": page, "per_page": per_page}
        resp = requests.get(url, params=params)  # type: ignore
        if resp.status_code != 200:
            return f"Error: Unable to fetch data from {url}. Status code: {resp.status_code}"
        soup = BeautifulSoup(resp.text, "lxml")
        results = soup.find_all("tr", class_="search-result")
        if not results:
            return "No certificates found."
        output = []
        for result in results:
            category = result.find("span", class_="result-category").text.strip()
            id = result.find("span", class_="result-id").text.strip()
            name = result.find("span", class_="result-name").text.strip()
            status = result.find("span", class_="result-status").text.strip()
            cert_date = result.find("span", class_="result-cert-date").text.strip()
            archive_date = result.find("span", class_="result-archive-date").text.strip()
            output.append(
                {
                    "name": name,
                    "category": category,
                    "id": id,
                    "status": status,
                    "certification_date": cert_date,
                    "archival_date": archive_date,
                }
            )
        info = soup.find("div", class_="pagination-page-info")
        if info:
            results_info = info.text.strip()
        else:
            results_info = "No results information available."
        pages = soup.find("ul", class_="pagination")
        if pages:
            min_page = None
            max_page = None
            for li in pages.find_all("li"):
                try:
                    tpage = int(li.text.strip())
                except ValueError:
                    continue
                if min_page is None or tpage < min_page:
                    min_page = tpage
                if max_page is None or tpage > max_page:
                    max_page = tpage
            page_info = f"Page {page} of total {max_page} pages."
        else:
            page_info = "No pagination information available."
        result = {
            "query": query,
            "scheme": scheme,
            "page": page,
            "per_page": per_page,
            "results_info": results_info,
            "page_info": page_info,
            "results": output,
        }
        return json.dumps(result, indent=2, ensure_ascii=False)

"""
title: sec-certs.org tool
author: Jan Jancar
description: This tool allows users to search for certificates on the sec-certs.org website, get their text data, and retrieve JSON data for specific certificates.
requirements: requests, beautifulsoup4
version: 1.0
license: MIT
"""

import json
from typing import Literal

import requests
from bs4 import BeautifulSoup

# Note, this file is a "tool" for the Open WebUI service, it is not a part of this application.


def search(query: str, scheme: Literal["cc"] | Literal["fips"], page: int, sort, status) -> str:
    url = f"https://sec-certs.org/{scheme}/mergedsearch/"
    per_page = 100
    if scheme not in ["cc", "fips"]:
        return f"Error: Invalid scheme '{scheme}'. Valid options are 'cc' for Common Criteria or 'fips' for FIPS 140."
    params = {
        "searchType": "by-name",
        "q": query,
        "page": page,
        "per_page": per_page,
        "sort": sort,
        "status": status,
    }
    headers = {"User-Agent": "WebUI"}
    resp = requests.get(url, params=params, headers=headers)  # type: ignore
    if resp.status_code != 200:
        return f"Error: Unable to fetch data from {url}. Status code: {resp.status_code}"
    soup = BeautifulSoup(resp.text, "lxml")
    results = soup.find_all("tr", class_="search-result")
    if not results:
        return "No certificates found."
    output = []
    for result in results:
        category = result.find("span", class_="result-category").find("span")["title"]
        href = result.find("a", class_="result-link")["href"]
        link = "https://sec-certs.org" + href
        dgst = href.split("/")[-2]
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
                "dgst": dgst,
                "link": link,
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


class Tools:
    def __init__(self):
        pass

    def get_text(
        self,
        dgst: str,
        scheme: Literal["cc"] | Literal["fips"],
        document: Literal["cert"] | Literal["report"] | Literal["target"],
    ) -> str:
        """
        Fetch the text data for a certificate (if the document parameter is "cert"), or a certification report
        (if the document parameter is "report"), or a security target (if the document parameter is "target") from sec-certs.org.

        :param dgst: The digest of the certificate to fetch.
        :param scheme: The scheme of the certificate, either "cc" for Common Criteria or "fips" for FIPS 140.
        :param document: The type of document to fetch, either "cert" for certificate, "report" for certification report, or "target" for security target.
        :return: A string containing the document data, or an error message if the input is invalid.
        """
        url = f"https://sec-certs.org/{scheme}/{dgst}/{document}.txt"
        if scheme not in ["cc", "fips"]:
            return (
                f"Error: Invalid scheme '{scheme}'. Valid options are 'cc' for Common Criteria or 'fips' for FIPS 140."
            )
        if document not in ["cert", "report", "target"]:
            return f"Error: Invalid document type '{document}'. Valid options are 'cert', 'report', or 'target'."
        resp = requests.get(url)
        if resp.status_code != 200:
            return f"Error: Unable to fetch data from {url}. Status code: {resp.status_code}"
        return resp.content.decode()

    def get_json(self, dgst: str, scheme: Literal["cc"] | Literal["fips"]) -> str:
        """
        Fetch the JSON data for a certificate from sec-certs.org.

        :param dgst: The digest of the certificate to fetch.
        :param scheme: The scheme of the certificate, either "cc" for Common Criteria or "fips" for FIPS 140.
        :return: A JSON string containing the certificate data, or an error message if the input is invalid.
        """
        url = f"https://sec-certs.org/{scheme}/{dgst}/cert.json"
        if scheme not in ["cc", "fips"]:
            return (
                f"Error: Invalid scheme '{scheme}'. Valid options are 'cc' for Common Criteria or 'fips' for FIPS 140."
            )
        resp = requests.get(url)
        if resp.status_code != 200:
            return f"Error: Unable to fetch data from {url}. Status code: {resp.status_code}"
        return resp.content.decode()

    def cc_search(
        self,
        query: str,
        page: int = 1,
        sort: Literal["match"] | Literal["name"] | Literal["cert_date"] | Literal["archive_date"] = "match",
        status: Literal["any"] | Literal["active"] | Literal["archived"] = "any",
    ) -> str:
        """
        Search the sec-certs.org website for CC certificates and output results in JSON.

        :param query: The search term to look for in the certificates.
        :param page: The page number to retrieve results from.
        :param sort: The sorting method for the results, default is "match".
        :param status: The status of the certificates to filter by, default is "any".
        :return: A JSON string containing the search results, or an error message if the input is invalid.
        """
        if sort not in ["match", "name", "cert_date", "archive_date"]:
            return f"Error: Invalid sort parameter '{sort}'. Valid options are 'match', 'name', 'cert_date', or 'archive_date'."
        if status not in ["any", "active", "archived"]:
            return f"Error: Invalid status parameter '{status}'. Valid options are 'any', 'active', or 'archived'."
        return search(query, "cc", page, sort, status)

    def fips_search(
        self,
        query: str,
        page: int = 1,
        sort: (
            Literal["match"]
            | Literal["number"]
            | Literal["first_cert_date"]
            | Literal["last_cert_date"]
            | Literal["sunset_date"]
            | Literal["level"]
            | Literal["vendor"]
        ) = "match",
        status: Literal["Any"] | Literal["Active"] | Literal["Historical"] | Literal["Revoked"] = "Any",
    ) -> str:
        """
        Search the sec-certs.org website for FIPS 140 certificates and output results in JSON.

        :param query: The search term to look for in the certificates.
        :param page: The page number to retrieve results from.
        :param sort: The sorting method for the results, default is "match".
        :param status: The status of the certificates to filter by, default is "Any".
        :return: A JSON string containing the search results, or an error message if the input is invalid.
        """
        if sort not in ["match", "number", "first_cert_date", "last_cert_date", "sunset_date", "level", "vendor"]:
            return f"Error: Invalid sort parameter '{sort}'. Valid options are 'match', 'number', 'first_cert_date', 'last_cert_date', 'sunset_date', 'level', or 'vendor'."
        if status not in ["Any", "Active", "Historical", "Revoked"]:
            return f"Error: Invalid status parameter '{status}'. Valid options are 'Any', 'Active', 'Historical', or 'Revoked'."
        return search(query, "fips", page, sort, status)


if __name__ == "__main__":
    tool = Tools()
    # Example usage of the tool
    print(tool.cc_search("Athena"))
    print(tool.get_text("358bc60e1aa999c5", "cc", "cert"))
    print(tool.get_json("358bc60e1aa999c5", "cc"))
    print(tool.fips_search("Athena IDProtect"))

"""
title: Tool for searching sec-certs.org
author: Jan Jancar
description: This tool allows users to search for certificates on the sec-certs.org website.
requirements: requests, beautifulsoup4
version: 1.0
license: MIT
"""
import requests
from bs4 import BeautifulSoup
from typing import Literal


class Tools:
    def __init__(self):
        pass

    def search(self, query: str, scheme: Literal["cc"] | Literal["fips"], page: int = 1) -> str:
        """
        Search the sec-certs.org website for certificates.

        :param query: The search term to look for in the certificates.
        :param scheme: The scheme to search in, either "cc" for Common Criteria or "fips" for FIPS.
        :param page: The page number to retrieve results from.
        :return: A string containing the search results formatted for display.
        """

        url = f"https://sec-certs.org/{scheme}/mergedsearch/"
        params = {
            "searchType": "by-name",
            "q": query,
            "page": page
        }
        resp = requests.get(url, params=params)
        if resp.status_code != 200:
            return f"Error: Unable to fetch data from {url}. Status code: {resp.status_code}"
        soup = BeautifulSoup(resp.text, 'lxml')
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
                f"Certificate: {name}\n"
                f"Category: {category}\n"
                f"ID: {id}\n"
                f"Status: {status}\n"
                f"Certification Date: {cert_date}\n"
                f"Archive Date: {archive_date}\n"
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
        return results_info + "\n" + page_info + "\n------" + "---\n".join(output)


if __name__ == "__main__":
    tools = Tools()
    result = tools.search("Athena", "cc")
    print(result)  # This will print the response from the search function

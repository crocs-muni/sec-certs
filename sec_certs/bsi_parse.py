import re
import time

from typing import List
import requests
from bs4 import BeautifulSoup
from serialization import ComplexSerializableType

"""
architecture of the BSI page we should use:
    -The table with class "textualData link smallerFont"
    -1st <td> of each rows contains the link to the product's page and has a class
    -the link is in a <a> element

    What I want to do:
    Get a list of all <a> elements that have a <td class = * white-space-nowrap> as parent
"""

"""
https://www.bsi.bund.de/EN/Topics/Certification/certified_products/Archiv_reports.html?nn=513452
this link leads to all of the certs before 2010, and gather links to all of their pdfs
"""

test_url = "https://www.bsi.bund.de/SharedDocs/Zertifikate_CC/CC/Digitale_Signatur_Kartenlesegeraete/1046.html" \
           ";jsessionid=AF4A9C0B7D27992808B8EA8C426454BE.internet461?nn=513452 "

root_url = "https://www.bsi.bund.de/EN/Topics/Certification/certified_products/digital_signature" \
           "/digital_signature_node.html "


"""
Class used to browse BSI webpage -> get link to all categories
This class will search for every category, and create a handler for each that will
retrieve the links to the products
"""


class BsiBrowser(ComplexSerializableType):
    url: str
    handler_list: list
    link_list: list
    cert_dict: dict

    def __init__(self, url, handler_list, link_list):
        self.url = url
        self.soup = BeautifulSoup(requests.get(self.url).content, "html.parser")
        self.link_list = []
        self.handler_list = []
        self.cert_dict = {}

    @property
    def serialized_attributes(self) -> List[str]:
        return ['handler_list', 'link_list']

    def parse(self):
        """
        Retrieve all the links from the anchor list in a proper format
        """
        self.handler_list = [
            BsiHandler("https://www.bsi.bund.de/" + a['href'], [])
            for a in self.soup.find_all('a', href=True, recursive=True, class_='c-navigation-teaser')
        ]

    def process(self):
        self.parse()
        for handler in self.handler_list:
            handler.parse()
        tmp_list = [
            BSICertificate(url, [], [])
            for handler in self.handler_list
            for url in handler.link_list
        ]
        tmp_list.extend(
            [BSICertificate(arch_url, [], [])
             for handler in self.handler_list
             for arch_handler in handler.handler_list
             for arch_url in arch_handler.link_list]
        )
        for cert in tmp_list:
            self.cert_dict.update({cert.id[0]: tuple(cert.pdf_links)})
        return tmp_list


class BsiHandler(BsiBrowser):
    """
    Class used to retrieve the links for all products under a category
    """

    url: str
    link_list: list
    soup: BeautifulSoup

    def __init__(self, url, link_list):
        self.url = url
        self.soup = BeautifulSoup(requests.get(self.url).content, "html.parser")
        self.link_list = []
        self.handler_list = []

    @property
    def serialized_attributes(self) -> List[str]:
        return ['link_list']

    def parse(self):
        # Iterating over the anchors to filter them

        self.link_list = [
            "https://www.bsi.bund.de/" + a['href']
            for a in self.soup.find_all('a', href=True, recursive=True)
            if 'white-space-nowrap' in str(a.parent.get('class'))
        ]

        self.handler_list = [
            BsiHandler("https://www.bsi.bund.de/" + a['href'], [])
            for a in self.soup.find_all('a', href=True, recursive=True,
                                        title=re.compile('Archive'))
        ]
        if self.handler_list:
            for handler in self.handler_list:
                handler.parse()
        # ------------------------------------------------------------------------------------------------


class BSICertificate(ComplexSerializableType):
    """
    a class that will contain essentials data to compare to CC certs
    """
    html_content: list
    certification_date: str
    valid_until: str
    soup: BeautifulSoup
    id: str
    pdf_links: List[str]

    def __init__(self, url, html_content, pdf_links):
        self.soup = BeautifulSoup(requests.get(url).content, "html.parser")
        self.id = self.soup.find("title").contents
        self.pdf_links = [
            "https://www.bsi.bund.de/" + a['href']
            for a in self.soup.find_all('a', href=True, recursive=True, class_='RichTextDownloadLink Publication FTpdf')
        ]

    @property
    def serialized_attributes(self) -> List[str]:
        return ['html_content', 'pdf_links']


subpage = BSICertificate(test_url, [], [])

start = time.time()
browser = BsiBrowser(root_url, [], [])
result = browser.process()
end = time.time() - start
print(browser.cert_dict)
print(end)
print(len(result))

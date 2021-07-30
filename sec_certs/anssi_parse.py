import time
from typing import List
import requests
from bs4 import BeautifulSoup
from serialization import ComplexSerializableType

"""
After inspecting the ANSSI webpage, the architecture should be like BSI:
    -on the main page, retrieve the <ul class="nav-categories"> element
    -get all <li> elements
    -do the handler trick on the webpage
    -get pdf links
"""


url = "https://www.ssi.gouv.fr/en/products/certified-products/"

SSI_PREFIX = "https://www.ssi.gouv.fr"

class AnssiBrowser(ComplexSerializableType):
    url: str
    handler_list: List
    link_list: List
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
        retrieve all categories
        """
        if self.soup.find('ul', class_='nav-categories') is not None:
            self.handler_list = [
                AnssiHandler(SSI_PREFIX+a['href'], [], [])
                for a in
                self.soup.find('ul', class_='nav-categories').find_all("a")
                if time.sleep(2) is None
            ]

    def process(self):
        self.parse()
        for handler in self.handler_list:
            handler.parse()
        results = [
            AnssiCertificate(url)
            for handler in self.handler_list
            for url in handler.link_list
            if time.sleep(2) is None
        ]
        for certs in results:
            self.cert_dict.update({certs.key: certs.pdf_links})
        return results





"""
the link to a product page is inside <td class="titre"> elements
"""
class AnssiHandler(AnssiBrowser):
    url: str
    link_list: List
    soup: BeautifulSoup

    def parse(self):
        if self.soup.find('table', class_='produits-liste cc') is not None:
            self.link_list = [
                SSI_PREFIX+a['href'] for a in
                self.soup.find('table', class_='produits-liste cc').find_all('a', recursive=True, href=True)
                if a['href'] != ""
            ]


class AnssiCertificate(ComplexSerializableType):
    url: str
    key: str
    soup: BeautifulSoup
    pdf_links: List

    def __init__(self, url):
        self.soup = BeautifulSoup(requests.get(url).content, "html.parser")
        #-------------------------------------------------------------------------------------------
        """This section is retrieving the reference of the product's certificate (e.g. 2020/67)"""
        self.key = self.soup.find(
            'div', class_="ref-date"
        ).find_all(
            'span', recursive=True, class_="donnees")[0].contents[0]
        #--------------------------------------------------------------------------------------------


        self.pdf_links = [
            SSI_PREFIX+a['href']
            for a in self.soup.find('div', class_="box-produit-telechargements").find_all('a')
        ]


browser = AnssiBrowser("https://www.ssi.gouv.fr/en/products/certified-products/", [], [])
list = browser.process()
print(list[0].pdf_links)
print(browser.cert_dict[0])
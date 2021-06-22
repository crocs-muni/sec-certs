import re
import time

import pandas as pd
import requests
from bs4 import BeautifulSoup
from serialization import ComplexSerializableType, CustomJSONDecoder, CustomJSONEncoder

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

    def __init__(self, url):
        self.url = url
        self.soup = BeautifulSoup(requests.get(self.url).content, "html.parser")
        self.link_list = []
        self.handler_list = []
        self.archive_list = []

    def parse(self):

        self.handler_list = \
            [BsiHandler("https://www.bsi.bund.de/" + a['href'])
             for a in self.soup.find_all('a', href=True, recursive=True)
             if 'c-navigation-teaser' in str(a.get('class'))]


class BsiHandler(BsiBrowser):
    """
    Class used to retrieve the links for all products under a category
    """

    url: str
    link_list: list
    soup: BeautifulSoup

    def __init__(self, url):
        self.url = url
        self.soup = BeautifulSoup(requests.get(self.url).content, "html.parser")
        self.link_list = []
        self.handler_list = []

    def parse(self):

        self.link_list = \
            ["https://www.bsi.bund.de/" + a['href'] for a in self.soup.find_all('a', href=True, recursive=True) if
             'white-space-nowrap' in str(a.parent.get('class'))]

        self.handler_list = \
            [BsiHandler("https://www.bsi.bund.de/" + a['href'])
             for a in self.soup.find_all('a', href=True, recursive=True, title=re.compile('Archive'))]

        if len(self.handler_list) != 0:
            for handler in self.handler_list:
                handler.parse()

        # ------------------------------------------------------------------------------------------------



# To end the processing, a last class will be used with final links
# to retrieve simple data written on the page


class Bsitmp(ComplexSerializableType):
    """
    a class that will contain essentials data to compare to CC certs
    """
    html_content: list
    certification_date: str
    valid_until: str
    soup: BeautifulSoup
    id: str
    pdf_links: list[str]

    def __init__(self, url):
        # self.html_content = pd.read_html(url)
        # self.certification_date = self.html_content[0].to_numpy()[3][1]
        # self.valid_until = self.html_content[0].to_numpy()[4][1]
        self.soup = BeautifulSoup(requests.get(url).content, "html.parser")
        self.id = self.soup.find("meta", property='title')
        self.pdf_links = \
            ["https://www.bsi.bund.de/" + a['href']
             for a in self.soup.find_all('a', href=True, recursive=True, class_='RichTextDownloadLink Publication FTpdf')]
        # for a in self.soup.find_all('a', href=True, recursive=True, class_='RichTextDownloadLink Publication FTpdf'):
        #     self.pdf_links.append("https://www.bsi.bund.de/" + a['href'])


def process(base_url: str):
    browser = BsiBrowser(base_url)
    browser.parse()
    tmp_list = []
    for handler in browser.handler_list:
        handler.parse()
        for url in handler.link_list:
            temp = Bsitmp(url)
            # print(temp.html_content)
            tmp_list.append(temp)
        for arch_handler in handler.handler_list:
            for arch_url in arch_handler.link_list:
                arch_temp = Bsitmp(arch_url)
                tmp_list.append(arch_temp)
    return tmp_list


start = time.time()
result = process(root_url)
end = time.time() - start
print(end)
print(len(result))

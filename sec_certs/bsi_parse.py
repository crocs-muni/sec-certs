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

# root_page = requests.get(root_url)
#
# root_html_content = pd.read_html(root_url).__str__()
#
# soup = BeautifulSoup(root_page.content, "html.parser")
#
# """
# Class linked to the parents of the anchors we need
# """
# BSI_LINK_CLASS = {'odd', 'white-space-nowrap', 'even'}
#
# link_row_list = soup.find_all('a', href=True, recursive=True)
#
# a_link_list = []
# """
# Iterating over the anchors to filter them
# """
# for a in link_row_list:
#     if 'white-space-nowrap' in str(a.parent.get('class')):
#         a_link_list.append(a)
# print(a_link_list)
# link_list = []
# """
# Retrieve all the links from the anchor list in a proper format
# """
# for a in a_link_list:
#     link_list.append("https://www.bsi.bund.de/" + a['href'])
# print(link_list)


HANDLER_LIST = []

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
        self.root_url = root_url
        self.soup = BeautifulSoup(requests.get(self.url).content, "html.parser")
        self.link_list = []
        self.handler_list = []
        self.archive_list = []

    def parse(self):
        """
        Iterating over the anchors to filter them
        """
        a_link_list = []
        for a in self.soup.find_all('a', href=True, recursive=True):
            if 'c-navigation-teaser' in str(a.get('class')):
                a_link_list.append(a)
        """
        Retrieve all the links from the anchor list in a proper format
        """
        for a in a_link_list:
            link = "https://www.bsi.bund.de/" + a['href']
            self.link_list.append(link)
            handler = BsiHandler(link)
            self.handler_list.append(handler)
            # HANDLER_LIST.append(handler)


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
        # Iterating over the anchors to filter them

        a_link_list = []
        # Find the products displayed on the page
        for a in self.soup.find_all('a', href=True, recursive=True):
            if 'white-space-nowrap' in str(a.parent.get('class')):
                a_link_list.append(a)
        # Retrieve all the links from the anchor list in a proper format
        for a in a_link_list:
            self.link_list.append("https://www.bsi.bund.de/" + a['href'])

        # -------------Finding the link to the archived certs---------------------------------------------
        for a in self.soup.find_all('a', href=True, recursive=True,
                                    title=re.compile('Archive')):  # use of a regex to find the keyword
            self.link_list.append("https://www.bsi.bund.de/" + a['href'])
        for link in self.link_list:
            self.handler_list.append(BsiHandler(link))
        if len(self.handler_list) != 0:
            for handler in self.handler_list:
                handler.parse()
        # ------------------------------------------------------------------------------------------------


# class BsiArchive(BsiBrowser):
#     """
#     This class will be on the same level as handler, and will instantiate handlers one layer down
#     """
#
#     def parse(self):
#         for a in self.soup.find_all('a', href=True, recursive=True,
#                                     title=re.compile('Archive')):  # use of a regex to find the keyword
#             self.link_list.append("https://www.bsi.bund.de/" + a['href'])
#         for link in self.link_list:
#             self.handler_list.append(BsiHandler(link))


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
        self.pdf_links = []
        for a in self.soup.find_all('a', href=True, recursive=True, class_='RichTextDownloadLink Publication FTpdf'):
            self.pdf_links.append("https://www.bsi.bund.de/" + a['href'])


subpage = Bsitmp(test_url)


# print(subpage.certification_date)


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


def archive_search(soup: BeautifulSoup):
    """
    #TODO finish the traversal, according to the page architecture, finding the <a> elements with a title containing
    'Archive'
    The easiest way would be to run the search on each page with a handler
    """
    archive_link_list = []
    for a in soup.find_all('a', href=True, recursive=True,
                           title=re.compile('Archive')):  # use of a regex to find the keyword
        archive_link_list.append("https://www.bsi.bund.de/" + a['href'])
    print(archive_link_list)


testsoup = BeautifulSoup(requests.get(
    'https://www.bsi.bund.de/EN/Topics/Certification/certified_products/digital_signature/digital_signature_node.html').content,
                         "html.parser")

# archive_search(testsoup)

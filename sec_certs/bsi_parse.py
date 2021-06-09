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

"""
Class used to retrieve the links for all products under a category
"""


class BsiHandler(ComplexSerializableType):
    root_url: str
    link_list: list
    soup: BeautifulSoup

    def __init__(self, root_url):
        self.root_url = root_url
        self.soup = BeautifulSoup(requests.get(self.root_url).content, "html.parser")
        self.link_list = []

    def parse(self):
        """
        Iterating over the anchors to filter them
        """
        a_link_list = []
        for a in self.soup.find_all('a', href=True, recursive=True):
            if 'white-space-nowrap' in str(a.parent.get('class')):
                a_link_list.append(a)
        """
        Retrieve all the links from the anchor list in a proper format
        """
        for a in a_link_list:
            self.link_list.append("https://www.bsi.bund.de/" + a['href'])


"""
Class used to browse BSI webpage -> get link to all categories
This class will search for every category, and create a handler for each that will
retrieve the links to the products
"""


class BsiBrowser(BsiHandler):
    handler_list: list[BsiHandler]
    link_list: list

    def __init__(self, url):
        super().__init__(url)
        self.handler_list = []

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
            self.handler_list.append(BsiHandler(link))


"""
To end the processing, a last class will be used with final links
to retrieve simple data written on the page
"""


# print(soup.prettify())


# def parse_subpage(url):
#     html_content = pd.read_html(url)
#     print(html_content[0].to_numpy()[4][1])
#
#
# parse_subpage(test_url)


class Bsitmp(ComplexSerializableType):
    """a class that will contain essentials data to compare to CC certs
    #TODO rework the class to get the whole page -> switch to BSoup
    """
    html_content: list
    certification_date: str
    valid_until: str
    soup: BeautifulSoup
    id: str

    def __init__(self, url):
        self.html_content = pd.read_html(url)
        self.certification_date = self.html_content[0].to_numpy()[3][1]
        self.valid_until = self.html_content[0].to_numpy()[4][1]
        self.soup = BeautifulSoup(requests.get(url).content, "html.parser")
        self.id = self.soup.find("meta", property='title')




subpage = Bsitmp(test_url)

# print(subpage.certification_date)


def process(root_url: str):
    browser = BsiBrowser(root_url)
    browser.parse()
    tmp_list = []
    for handler in browser.handler_list:
        handler.parse()
        for url in handler.link_list:
            temp = Bsitmp(url)
            print(temp.html_content)
            tmp_list.append(temp)
    return tmp_list


print(process(root_url)[0])


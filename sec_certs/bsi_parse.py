import pandas as pd
import requests
import helpers
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

root_page = requests.get(root_url)

root_html_content = pd.read_html(root_url).__str__()

soup = BeautifulSoup(root_page.content, "html.parser")

"""
Class linked to the parents of the anchors we need
"""
BSI_LINK_CLASS = {'odd', 'white-space-nowrap', 'even'}

link_row_list = soup.find_all('a', href=True, recursive=True)

a_link_list = []
"""
Iterating over the anchors to filter them
"""
for a in link_row_list:
    if 'white-space-nowrap' in str(a.parent.get('class')):
        a_link_list.append(a)
print(a_link_list)
link_list = []
"""
Retrieve all the links from the anchor list in a proper format
"""
for a in a_link_list:
    link_list.append("https://www.bsi.bund.de/"+a['href'])
print(link_list)


class BsiHandler(ComplexSerializableType):
    root_url: str
    link_list: list
    soup: BeautifulSoup

    def __init__(self,root_url):
        self.root_url = root_url
        self.soup = BeautifulSoup(requests.get(self.root_url).content, "html.parser")

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








#print(soup.prettify())


# def parse_subpage(url):
#     html_content = pd.read_html(url)
#     print(html_content[0].to_numpy()[4][1])
#
#
# parse_subpage(test_url)


# class Bsitmp(ComplexSerializableType):
#     """a class that will contain essentials data to compare to CC certs"""
#     html_content: list
#     certification_date: str
#     valid_until: str
#
#     def __init__(self, url):
#         self.html_content = pd.read_html(url)
#         self.certification_date = self.html_content[0].to_numpy()[3][1]
#         self.valid_until = self.html_content[0].to_numpy()[4][1]
#
#
# subpage = Bsitmp(test_url)
#
# print(subpage)

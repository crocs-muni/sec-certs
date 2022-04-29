import cssutils
from bs4 import BeautifulSoup
from cssutils import CSSParser
from cssutils.css import CSSStyleSheet
from cssutils.serialize import CSSSerializer, Preferences


def clean_css(css: str, html: str) -> str:
    """
    Clean up the given CSS to only include rules that affect the given HTML.
    Also minifies the output CSS.
    """
    original_sheet = CSSParser().parseString(css)
    new_sheet = CSSStyleSheet()
    soup = BeautifulSoup(html, "lxml")

    for rule in original_sheet:
        selector = rule.selectorText if ":" not in rule.selectorText else rule.selectorText.split(":")[0]
        if soup.select(selector):
            new_sheet.add(rule)

    prefs = Preferences()
    prefs.useMinified()
    serializer = CSSSerializer(prefs)
    cssutils.setSerializer(serializer)
    return new_sheet.cssText.decode()

from sec_certs.utils.frontpage.base import FrontpageParser
from sec_certs.utils.frontpage.nscib import NSCIBFrontpageParser

__all__ = [
    "FrontpageParser",
    "NSCIBFrontpageParser",
    "scheme_frontpage_parsers",
]

scheme_frontpage_parsers: dict[str, FrontpageParser] = {
    "NL": NSCIBFrontpageParser(),
}

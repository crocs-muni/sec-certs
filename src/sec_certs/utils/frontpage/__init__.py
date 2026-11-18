from sec_certs.utils.frontpage.base import FrontpageParser
from sec_certs.utils.frontpage.canada import CanadaFrontpageParser
from sec_certs.utils.frontpage.nscib import NSCIBFrontpageParser

__all__ = [
    "FrontpageParser",
    "CanadaFrontpageParser",
    "NSCIBFrontpageParser",
    "scheme_frontpage_parsers",
]

scheme_frontpage_parsers: dict[str, FrontpageParser] = {
    "NL": NSCIBFrontpageParser(),
    "CA": CanadaFrontpageParser(),
}

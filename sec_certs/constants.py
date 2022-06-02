import re
from enum import Enum

RESPONSE_OK = 200
RETURNCODE_OK = "ok"
RETURNCODE_NOK = "nok"
REQUEST_TIMEOUT = 10

MIN_CORRECT_CERT_SIZE = 5000

MIN_CC_HTML_SIZE = 5000000
MIN_CC_CSV_SIZE = 700000
MIN_CC_PP_DATASET_SIZE = 2500000


class CertFramework(Enum):
    CC = "Common Criteria"
    FIPS = "FIPS"


CPE_VERSION_NA = "-"

FIPS_BASE_URL = "https://csrc.nist.gov"
FIPS_MODULE_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/"
FIPS_NOT_AVAILABLE_CERT_SIZE = 10000
FIPS_ALG_URL = "https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=implementation&page="

FIPS_MIP_STATUS_RE = re.compile(r"^(?P<status>[a-zA-Z ]+?) +\((?P<since>\d{1,2}/\d{1,2}/\d{4})\)$")

TAG_MATCH_COUNTER = "count"
TAG_MATCH_MATCHES = "matches"

TAG_CERT_HEADER_PROCESSED = "cert_header_processed"

TAG_CERT_ID = "cert_id"
TAG_CC_SECURITY_LEVEL = "cc_security_level"
TAG_CC_VERSION = "cc_version"
TAG_CERT_LAB = "cert_lab"
TAG_CERT_ITEM = "cert_item"
TAG_CERT_ITEM_VERSION = "cert_item_version"
TAG_DEVELOPER = "developer"
TAG_REFERENCED_PROTECTION_PROFILES = "ref_protection_profiles"
TAG_HEADER_MATCH_RULES = "match_rules"
TAG_PP_TITLE = "pp_title"
TAG_PP_GENERAL_STATUS = "pp_general_status"
TAG_PP_VERSION_NUMBER = "pp_version_number"
TAG_PP_ID = "pp_id"
TAG_PP_ID_REGISTRATOR = "pp_id_registrator"
TAG_PP_DATE = "pp_date"
TAG_PP_AUTHORS = "pp_authors"
TAG_PP_REGISTRATOR = "pp_registrator"
TAG_PP_REGISTRATOR_SIMPLIFIED = "pp_registrator_simplified"
TAG_PP_SPONSOR = "pp_sponsor"
TAG_PP_EDITOR = "pp_editor"
TAG_PP_REVIEWER = "pp_reviewer"
TAG_KEYWORDS = "keywords"


FILE_ERRORS_STRATEGY = "surrogateescape"
STOP_ON_UNEXPECTED_NUMS = False
APPEND_DETAILED_MATCH_MATCHES = False
MAX_ALLOWED_MATCH_LENGTH = 300
LINE_SEPARATOR = " "

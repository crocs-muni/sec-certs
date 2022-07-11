import re

RESPONSE_OK = 200
RETURNCODE_OK = "ok"
RETURNCODE_NOK = "nok"
REQUEST_TIMEOUT = 10

MIN_CORRECT_CERT_SIZE = 5000

MIN_CC_HTML_SIZE = 5000000
MIN_CC_CSV_SIZE = 700000
MIN_CC_PP_DATASET_SIZE = 2500000

CPE_VERSION_NA = "-"

FIPS_BASE_URL = "https://csrc.nist.gov"
FIPS_CMVP_URL = FIPS_BASE_URL + "/projects/cryptographic-module-validation-program"
FIPS_CAVP_URL = FIPS_BASE_URL + "/projects/Cryptographic-Algorithm-Validation-Program"
FIPS_MODULE_URL = FIPS_CMVP_URL + "/certificate/{}"
FIPS_ALG_SEARCH_URL = FIPS_CAVP_URL + "/validation-search?searchMode=implementation&page="
FIPS_SP_URL = "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{}.pdf"
FIPS_ACTIVE_MODULES_URL = (
    FIPS_CMVP_URL + "/validated-modules/search?SearchMode=Advanced&CertificateStatus=Active&ValidationYear=0"
)
FIPS_HISTORICAL_MODULES_URL = (
    FIPS_CMVP_URL + "/validated-modules/search?SearchMode=Advanced&CertificateStatus=Historical&ValidationYear=0"
)
FIPS_REVOKED_MODULES_URL = (
    FIPS_CMVP_URL + "/validated-modules/search?SearchMode=Advanced&CertificateStatus=Revoked&ValidationYear=0"
)
FIPS_ALG_URL = FIPS_CAVP_URL + "/details?source={}&number={}"
FIPS_IUT_URL = "https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/IUT-List"
FIPS_MIP_URL = (
    "https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/Modules-In-Process-List"
)

FIPS_DOWNLOAD_DELAY = 1

FIPS_MIP_STATUS_RE = re.compile(r"^(?P<status>[a-zA-Z ]+?) +\((?P<since>\d{1,2}/\d{1,2}/\d{4})\)$")

TAG_CERT_ID = "cert_id"
TAG_CC_SECURITY_LEVEL = "cc_security_level"
TAG_CC_VERSION = "cc_version"
TAG_CERT_LAB = "cert_lab"
TAG_CERT_ITEM = "cert_item"
TAG_CERT_ITEM_VERSION = "cert_item_version"
TAG_DEVELOPER = "developer"
TAG_REFERENCED_PROTECTION_PROFILES = "ref_protection_profiles"
TAG_HEADER_MATCH_RULES = "match_rules"

FILE_ERRORS_STRATEGY = "surrogateescape"
MAX_ALLOWED_MATCH_LENGTH = 300
LINE_SEPARATOR = " "

GARBAGE_LINES_THRESHOLD = 30
GARBAGE_SIZE_THRESHOLD = 1000
GARBAGE_AVG_LLEN_THRESHOLD = 10
GARBAGE_EVERY_SECOND_CHAR_THRESHOLD = 15
GARBAGE_ALPHA_CHARS_THRESHOLD = 0.5

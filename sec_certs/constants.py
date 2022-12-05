import re
from pathlib import Path

DUMMY_NONEXISTING_PATH = Path("/this/is/dummy/nonexisting/path")

RESPONSE_OK = 200
RETURNCODE_OK = "ok"
RETURNCODE_NOK = "nok"
REQUEST_TIMEOUT = 10

MIN_CORRECT_CERT_SIZE = 5000

MIN_FIPS_HTML_SIZE = 64000

MIN_CC_HTML_SIZE = 5000000
MIN_CC_CSV_SIZE = 700000
MIN_CC_PP_DATASET_SIZE = 2500000

CPE_VERSION_NA = "-"

RELEASE_CANDIDATE_REGEX: re.Pattern = re.compile(r"rc\d{0,2}$", re.IGNORECASE)

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

CC_AUSTRALIA_BASE_URL = "https://www.cyber.gov.au"
CC_AUSTRALIA_CERTIFIED_URL = (
    CC_AUSTRALIA_BASE_URL + "/acsc/view-all-content/programs/australian-information-security-evaluation-program"
)
CC_CANADA_CERTIFIED_URL = "https://www.cyber.gc.ca/en/tools-services/common-criteria/certified-products"
CC_CANADA_INEVAL_URL = "https://www.cyber.gc.ca/en/tools-services/common-criteria/products-evaluation"
CC_ANSSI_BASE_URL = "https://www.ssi.gouv.fr"
CC_ANSSI_CERTIFIED_URL = CC_ANSSI_BASE_URL + "/en/products/certified-products/"
CC_BSI_BASE_URL = "https://www.bsi.bund.de/"
CC_BSI_CERTIFIED_URL = CC_BSI_BASE_URL + "EN2021/Topics/Certification/certified_products/certified_products_node.html"
CC_INDIA_CERTIFIED_URL = "https://www.commoncriteria-india.gov.in/product-certified"
CC_INDIA_ARCHIVED_URL = "https://www.commoncriteria-india.gov.in/archived-prod-cer"
CC_ITALY_BASE_URL = "https://www.ocsi.gov.it"
CC_ITALY_CERTIFIED_URL = CC_ITALY_BASE_URL + "/index.php/elenchi-certificazioni/prodotti-certificati.html"
CC_ITALY_INEVAL_URL = CC_ITALY_BASE_URL + "/index.php/elenchi-certificazioni/in-corso-di-valutazione.html"
CC_JAPAN_BASE_URL = "https://www.ipa.go.jp/security/jisec/jisec_e"
CC_JAPAN_CERT_BASE_URL = CC_JAPAN_BASE_URL + "/certified_products"
CC_JAPAN_CERTIFIED_URL = CC_JAPAN_BASE_URL + "/certified_products/certfy_list_e31.html"
CC_JAPAN_ARCHIVED_URL = CC_JAPAN_BASE_URL + "/certified_products/certfy_list_e_archive.html"
CC_JAPAN_INEVAL_URL = CC_JAPAN_BASE_URL + "/prdct_in_eval.html"
CC_MALAYSIA_BASE_URL = "https://iscb.cybersecurity.my"
CC_MALAYSIA_CERTIFIED_URL = (
    CC_MALAYSIA_BASE_URL + "/en/index.php/certification/product-certification/mycc/certified-products-and-systems"
)
CC_MALAYSIA_INEVAL_URL = (
    CC_MALAYSIA_BASE_URL
    + "/en/index.php/certification/product-certification/mycc/list-of-products-and-systems-under-evaluation-or-maintenance"
)
CC_NETHERLANDS_BASE_URL = "https://www.tuv-nederland.nl/common-criteria"
CC_NETHERLANDS_CERTIFIED_URL = CC_NETHERLANDS_BASE_URL + "/certificates.html"
CC_NETHERLANDS_INEVAL_URL = CC_NETHERLANDS_BASE_URL + "/ongoing-certifications.html"
CC_NORWAY_CERTIFIED_URL = "https://sertit.no/certified-products/category1919.html"
CC_NORWAY_ARCHIVED_URL = "https://sertit.no/certified-products/product-archive/"
CC_KOREA_EN_URL = "https://itscc.kr/main/main.do?accessMode=home_en"
CC_KOREA_CERTIFIED_URL = "https://itscc.kr/certprod/list.do"
CC_KOREA_PRODUCT_URL = "https://itscc.kr/certprod/view.do?product_id={}&product_class=1"
CC_SINGAPORE_BASE_URL = "https://www.csa.gov.sg"
CC_SINGAPORE_CERTIFIED_URL = (
    CC_SINGAPORE_BASE_URL + "/Programmes/certification-and-labelling-schemes/csa-common-criteria/product-list"
)
CC_SINGAPORE_ARCHIVED_URL = (
    CC_SINGAPORE_BASE_URL + "/Programmes/certification-and-labelling-schemes/csa-common-criteria/product-archives"
)
CC_SPAIN_BASE_URL = "https://oc.ccn.cni.es"
CC_SPAIN_CERTIFIED_URL = CC_SPAIN_BASE_URL + "/en/certified-products/certified-products"
CC_SWEDEN_BASE_URL = "https://www.fmv.se"
CC_SWEDEN_CERTIFIED_URL = CC_SWEDEN_BASE_URL + "/verksamhet/ovrig-verksamhet/csec/certifikat-utgivna-av-csec/"
CC_SWEDEN_INEVAL_URL = CC_SWEDEN_BASE_URL + "/verksamhet/ovrig-verksamhet/csec/pagaende-certifieringar/"
CC_SWEDEN_ARCHIVED_URL = CC_SWEDEN_BASE_URL + "/verksamhet/ovrig-verksamhet/csec/arkiverade-certifikat-aldre-an-5-ar/"
CC_TURKEY_ARCHIVED_URL = "https://statik.tse.org.tr/upload/tr/dosya/icerikyonetimi/3300/03112021143434-2.pdf"
CC_USA_BASE_URL = "https://www.niap-ccevs.org"
CC_USA_CERTIFIED_URL = CC_USA_BASE_URL + "/Product/PCL.cfm"
CC_USA_INEVAL_URL = CC_USA_BASE_URL + "/Product/PINE.cfm"
CC_USA_ARCHIVED_URL = CC_USA_BASE_URL + "/Product/Archived.cfm"

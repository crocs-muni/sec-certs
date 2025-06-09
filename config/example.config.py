# A Flask SECRET_KEY used for sensitive operations (like signing session cookies),
# needs to be properly random.
# For example the output of "openssl rand -hex 32" or "python -c 'import os; print(os.urandom(16))'"
SECRET_KEY = "some proper randomness here"
SESSION_PROTECTION = "strong"
PREFERRED_URL_SCHEME = "https"
SERVER_NAME = "localhost:5000"

# Sentry
# SENTRY_INGEST is the URL of your Sentry ingest endpoint.
SENTRY_INGEST = ""
SENTRY_ENV = "development"  # or "production"
SENTRY_ERROR_SAMPLE_RATE = 1.0
SENTRY_TRACES_SAMPLE_RATE = 1.0

# Turnstile
TURNSTILE_SITEKEY = ""
TURNSTILE_SECRET = ""

# Email
MAIL_SERVER = "mail.example.com"  # The outgoing SMTP server to use
MAIL_DEBUG = False  # Whether to print out SMTP commands and responses (very verbose!)
MAIL_PORT = 465  # SMTP port to connect to
MAIL_USE_TLS = False  # Whether to use STARTTLS
MAIL_USE_SSL = True  # Whether to connect using SSL/TLS
MAIL_USERNAME = "username"  # The username to use for auth
MAIL_PASSWORD = ""  # The password to use for auth
MAIL_DEFAULT_SENDER = "seccerts@example.com"  # The sender address
# MAIL_SUPPRESS_SEND = True                     # Whether to suppress all sending (for testing)

# WebUI
CHAT_ENABLED = False  # Whether to enable the WebUI chat feature
WEBUI_URL = ""  # The URL of the WebUI API
WEBUI_KEY = ""  # Your WebUI API key
WEBUI_MODEL = "llama-4-scout-17b-16e-instruct"  # The model to use for the WebUI
WEBUI_SYSTEM_PROMPT = "You are a helpful assistant for the sec-certs project and an expert in security certifications. You can answer questions about Common Criteria and FIPS 140 certifications. Use the information from files and knowledge bases provided to you as much as possible. "
WEBUI_PROMPT_CC_ALL = "You are answering questions about Common Criteria certificates. In your knowledge base, you have information about the Common Criteria certification reports and security targets."
WEBUI_PROMPT_CC_CERT = "You are answering questions about a Common Criteria certificate '{{ cert_name }}'."
WEBUI_PROMPT_CC_BOTH = "You are answering questions about a Common Criteria certificate '{{ cert_name }}'. In your knowledge base, you have information about all of the Common Criteria certification reports and security targets."
WEBUI_PROMPT_FIPS_ALL = "You are answering questions about FIPS 140 certificates. In your knowledge base, you have information about the FIPS 140 security policies."
WEBUI_PROMPT_FIPS_CERT = "You are answering questions about a FIPS 140 certificate '{{ cert_name }}'."
WEBUI_PROMPT_FIPS_BOTH = "You are answering questions about a FIPS 140 certificate '{{ cert_name }}'. In your knowledge base, you have information about all of the FIPS 140 security policies."
WEBUI_PROMPT_PP_ALL = "You are answering questions about Common Criteria Protection Profiles. In your knowledge base, you have information about the Protection Profiles and their certification reports."
WEBUI_PROMPT_PP_CERT = "You are answering questions about a Common Criteria Protection Profile '{{ cert_name }}'."
WEBUI_PROMPT_PP_BOTH = "You are answering questions about a Common Criteria Protection Profile '{{ cert_name }}'. In your knowledge base, you have information about all of the Protection Profiles and their certification reports."
WEBUI_COLLECTION_CC_REPORTS = ""  # The ID of the knowledge base of Common Criteria certification reports
WEBUI_COLLECTION_CC_TARGETS = ""  # The ID of the knowledge base of Common Criteria security targets
WEBUI_COLLECTION_FIPS_TARGETS = ""  # The ID of the knowledge base of FIPS 140 security policies
WEBUI_COLLECTION_PP_REPORTS = (
    ""  # The ID of the knowledge base of Common Criteria Protection Profile certification reports
)
WEBUI_COLLECTION_PP_TARGETS = ""  # The ID of the knowledge base of Common Criteria Protection Profile security targets

# MongoDB
MONGO_URI = "mongodb://localhost:27017/seccerts"

# Redis (for Flask-Redis, dramatiq and Flask-Caching)
# Redis databases are split up like this:
#  0 -> Flask-Redis
#  1 -> dramatiq
#  2 -> Flask-Caching
REDIS_BASE = "redis://localhost:6379/"
REDIS_URL = REDIS_BASE + "0"

# dramatiq
DRAMATIQ_BROKER_URL = REDIS_BASE + "1"

# Cache
CACHE_TYPE = "RedisCache"
CACHE_REDIS_URL = REDIS_BASE + "2"

# nginx
USE_X_ACCEL_REDIRECT = False
X_ACCEL_REDIRECT_PATH = ""

# WHOOSH
WHOOSH_INDEX_PATH = "search"

# The way the Common Criteria certificate reference graphs are built.
# Can be "BOTH" to collect the references from both certificate documents and security targets,
# or "CERT_ONLY" for collecting references from certs only,
# or "ST_ONLY" for collecting references from security targets only.
CC_GRAPH = "CERT_ONLY"

# Number of items per page in the search listing.
SEARCH_ITEMS_PER_PAGE = 20

# Paths inside the instance directory where the CVE and CPE dataset will be stored.
DATASET_PATH_CVE = "cve.json"
DATASET_PATH_CVE_COMPRESSED = "cve.json.gz"
DATASET_PATH_CPE = "cpe.json"
DATASET_PATH_CPE_COMPRESSED = "cpe.json.gz"
DATASET_PATH_CPE_MATCH = "cpe_match.json"
DATASET_PATH_CPE_MATCH_COMPRESSED = "cpe_match.json.gz"

# Paths inside the instance directory where the CC, PP and FIPS datasets will be stored and processed.
DATASET_PATH_CC = "cc_dataset"
DATASET_PATH_CC_OUT = "cc.json"
DATASET_PATH_CC_OUT_MU = "cc_mu.json"
DATASET_PATH_CC_OUT_SCHEME = "cc_scheme.json"
DATASET_PATH_CC_OUT_PP = "pp.json"
DATASET_PATH_CC_DIR = "cc"
DATASET_PATH_CC_ARCHIVE = "cc.tar.gz"

DATASET_PATH_PP = "pp_dataset"
DATASET_PATH_PP_OUT = DATASET_PATH_CC_OUT_PP
DATASET_PATH_PP_DIR = "pp"
DATASET_PATH_PP_ARCHIVE = "pp.tar.gz"

DATASET_PATH_FIPS = "fips_dataset"
DATASET_PATH_FIPS_OUT = "fips.json"
DATASET_PATH_FIPS_OUT_ALGORITHMS = "fips_algorithms.json"
DATASET_PATH_FIPS_DIR = "fips"
DATASET_PATH_FIPS_ARCHIVE = "fips.tar.gz"

# Path for the sec-certs tool settings file inside the instance directory
TOOL_SETTINGS_PATH = "settings.yaml"

# Whether notification subscriptions are enabled.
SUBSCRIPTIONS_ENABLED = True

# Whether to skip the actual update (from remote CC, PP and FIPS servers) in the nightly update task. Useful for debugging.
CC_SKIP_UPDATE = False
PP_SKIP_UPDATE = False
FIPS_SKIP_UPDATE = False
FIPS_IUT_SKIP_UPDATE = False
FIPS_MIP_SKIP_UPDATE = False
CVE_SKIP_UPDATE = False
CPE_SKIP_UPDATE = False
CPE_MATCH_SKIP_UPDATE = False

# Whether to anonymize the site (for review).
ANONYMOUS = False
ANONYMOUS_GIT = ""

# Event navbar to show during special occasions
EVENT_NAVBAR = None

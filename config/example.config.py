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

# Paths inside the instance directory where the CC and FIPS datasets will be stored and processed.
DATASET_PATH_CC = "cc_dataset"
DATASET_PATH_CC_OUT = "cc.json"
DATASET_PATH_CC_OUT_MU = "cc_mu.json"
DATASET_PATH_CC_OUT_SCHEME = "cc_scheme.json"
DATASET_PATH_CC_DIR = "cc"
DATASET_PATH_CC_ARCHIVE = "cc.tar.gz"

DATASET_PATH_FIPS = "fips_dataset"
DATASET_PATH_FIPS_OUT = "fips.json"
DATASET_PATH_FIPS_DIR = "fips"
DATASET_PATH_FIPS_ARCHIVE = "fips.tar.gz"

# Path for the sec-certs tool settings file inside the instance directory
TOOL_SETTINGS_PATH = "settings.yaml"

# Whether notification subscriptions are enabled.
SUBSCRIPTIONS_ENABLED = True

# Whether to skip the actual update (from remote CC and FIPS servers) in the nightly update task. Useful for debugging.
CC_SKIP_UPDATE = False
FIPS_SKIP_UPDATE = False

# Whether to anonymize the site (for review).
ANONYMOUS = False
ANONYMOUS_GIT = ""

# A Flask SECRET_KEY used for sensitive operations (like signing session cookies),
# needs to be properly random.
# For example the output of "openssl rand -hex 32" or "python -c 'import os; print(os.urandom(16))'"
SECRET_KEY = "some proper randomness here"
SESSION_PROTECTION = "strong"
PREFERRED_URL_SCHEME = "https"
SERVER_NAME = "example.com:5000"

# Sentry
# SENTRY_INGEST is the URL of your Sentry ingest endpoint.
SENTRY_INGEST = ""
SENTRY_ERROR_SAMPLE_RATE = 1.0
SENTRY_TRACES_SAMPLE_RATE = 1.0

# MongoDB
MONGO_URI = "mongodb://localhost:27017/seccerts"

# Redis (for Flask-Redis, Celery and Flask-Caching)
# Redis databases are split up like this:
#  0 -> Flask-Redis
#  1 -> Celery
#  2 -> Flask-Caching
REDIS_BASE = "redis://localhost:6379/"
REDIS_URL = REDIS_BASE + "0"

# Celery
CELERY_BROKER_URL = REDIS_BASE + "1"
CELERY_RESULT_BACKEND = REDIS_BASE + "1"

# Cache
CACHE_TYPE = "RedisCache"
CACHE_REDIS_URL = REDIS_BASE + "2"

# The way the Common Criteria certificate reference graphs are built.
# Can be "BOTH" to collect the references from both certificate documents and security targets,
# or "CERT_ONLY" for collecting references from certs only,
# or "ST_ONLY" for collecting references from security targets only.
CC_GRAPH = "CERT_ONLY"

# Number of items per page in the search listing.
SEARCH_ITEMS_PER_PAGE = 20
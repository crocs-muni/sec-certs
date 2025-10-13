# Copilot Instructions for sec-certs (page branch)

## Repository Overview

This is the **page branch** of the sec-certs repository, containing a Flask web application that serves certificate data at [sec-certs.org](https://sec-certs.org). The web application displays and analyzes Common Criteria (CC), FIPS 140, and Protection Profile (PP) security certificates.

**Key Facts:**
- **Type**: Flask web application (~7,700 lines of Python across 62 files)
- **Languages/Frameworks**: Python 3.10+, Flask, MongoDB, Redis, dramatiq (task queue)
- **Python Version Required**: 3.10, 3.11, or 3.12
- **Dependencies**: Managed via `pyproject.toml`
- **Main Package**: `sec_certs_page/` (14 subdirectories including cc, fips, pp, admin, etc.)
- **External Services**: MongoDB (certificate storage), Redis (caching and task queue), Whoosh (search indexing)
- **Related**: Works in HEAD-to-HEAD fashion with the `main` branch of this repository (the sec-certs tool)

## Critical Setup Requirements

### MongoDB and Redis are required for tests
**MongoDB and Redis must be installed.** The tests, expect that a MongoDB server binary is available and use it to spin up a temporary MongoDB server that is filled with test data. Similarly, a fake Redis server is used and caching is disabled.

### Environment Setup
Only steps 1. through 4. are necessary for running the tests.

1. **Create a Python virtual environment** (always do this first):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Linux/Mac
   pip install -U setuptools wheel pip
   ```

2. **Install the application** in editable mode:
   ```bash
   pip install -e .
   ```

3. **Install the sec-certs tool** (this is a dependency but must be installed from the main branch):
   ```bash
   # Clone main branch separately or use: sec-certs @ git+https://github.com/crocs-muni/sec-certs.git#main
   # The tool is already declared as a dependency in pyproject.toml
   ```

4. **Download the spaCy language model**:
   ```bash
   python -m spacy download en_core_web_sm
   ```

### Standalone Setup
The following setup is not necessary when running tests, but is required for running the standalone app.

5. **Create the instance directory and configuration**:
   ```bash
   mkdir -p instance
   cp config/example.config.py instance/config.py
   cp config/example.settings.yaml instance/settings.yaml
   ```

6. **Edit `instance/config.py`**:
   - Set `SECRET_KEY` to random value (e.g., output of `openssl rand -hex 32`)
   - Update MongoDB URI if needed (default: `mongodb://localhost:27017/seccerts`)
   - Update Redis URLs if needed (default: `redis://localhost:6379/`)
   - For local development, comment out or remove the `SERVER_NAME` line
   - For local development, set the TURNSTILE secrets to the development ones.
   `TURNSTILE_SITEKEY = "1x00000000000000000000BB"` and `TURNSTILE_SECRET = "1x0000000000000000000000000000000AA"`.

7. **Start MongoDB and Redis**:
   ```bash
   # MongoDB (in separate terminal):
   mongod --dbpath /data/db
   
   # Redis (in separate terminal):
   redis-server
   ```

## Build and Run Instructions

### Running the Flask Application

**Standard development server:**
```bash
flask -A sec_certs_page run
```

**With host/port options:**
```bash
flask -A sec_certs_page run -h 0.0.0.0 -p 5000
```

**Alternative using app.py:**
```bash
python app.py
```

### Running Background Workers (Optional)

The application uses dramatiq for background tasks and periodiq for periodic tasks:

```bash
# dramatiq worker (in separate terminal):
dramatiq sec_certs_page:broker -p 2 -t 1

# periodiq worker (in separate terminal):
periodiq sec_certs_page:broker -p 2 -t 1
```

These workers are only needed if you're working with background tasks (certificate updates, notifications, etc.).
Tests do not require these workers, instead use mocking to test these tasks directly.

## Testing

### Prerequisites for Tests
 - MongoDB binary must be available under `mongod`.

### Running Tests

**Run all tests:**
```bash
pytest
```

**Run tests with coverage:**
```bash
pytest --cov sec_certs_page tests
```

**Run fast tests only tests:**
```bash
pytest -m "not slow"
```

**Test against remote server:**
```bash
TEST_REMOTE=1 pytest -m "remote"
```

### Test Markers
- `@pytest.mark.remote` - Tests that can run against remote server
- `@pytest.mark.slow` - Slow-running tests

### Test Environment
Tests automatically set `TESTING=true` environment variable (configured in `pyproject.toml` via `pytest-env`).

## Code Quality and Linting

### Pre-commit Hooks (STRONGLY RECOMMENDED)

This project uses pre-commit hooks to enforce code quality. **Always install and run pre-commit before committing:**

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

### Linters and Formatters

The pre-commit configuration (`.pre-commit-config.yaml`) runs:

1. **Black** (code formatter) - configured for 120 character line length
   ```bash
   black --check .
   # or to auto-format:
   black .
   ```

2. **isort** (import sorting)
   ```bash
   isort --check-only .
   # or to auto-sort:
   isort .
   ```

3. **mypy** (type checking)
   ```bash
   mypy .
   ```

**All three must pass for commits to be accepted.** You can bypass pre-commit hooks with `git commit -n`, but this is strongly discouraged.

### Configuration Details
- Black: 120 char line length, excludes virtual envs
- isort: Multi-line mode 3, trailing commas, 120 char line length
- mypy: Ignores missing imports, uses numpy typing plugin

## Project Structure

### Root Directory Files
```
.
├── .dockerignore          # Docker ignore patterns
├── .gitignore             # Git ignore patterns
├── .pre-commit-config.yaml # Pre-commit hook configuration
├── Dockerfile             # Docker build configuration
├── README.md              # Main documentation
├── app.py                 # Simple app entry point
├── config/                # Example configuration files
│   ├── example.config.py
│   ├── example.settings.yaml
│   └── example.uwsgi.ini
├── docs/                  # Documentation
│   ├── database.md        # MongoDB schema documentation
│   └── tasks.md           # Background tasks documentation
├── fabfile.py             # Deployment fabric tasks
├── poetry.lock            # Poetry dependency lockfile
├── pyproject.toml         # Project configuration and dependencies
├── sec_certs_page/        # Main application package
└── tests/                 # Test suite
    ├── conftest.py
    └── functional/        # Functional tests
```

### Main Package Structure (`sec_certs_page/`)
```
sec_certs_page/
├── __init__.py           # App initialization, Flask config, extensions setup
├── about/                # About page blueprint
├── admin/                # Admin interface blueprint
├── cc/                   # Common Criteria certificates blueprint
├── chat/                 # Chat feature blueprint
├── common/               # Shared utilities and components
├── dashboard.py          # Dashboard views
├── docs/                 # Documentation blueprint
├── fips/                 # FIPS 140 certificates blueprint
├── jinja.py              # Jinja template filters and globals
├── notifications/        # Email notification blueprint
├── pp/                   # Protection Profiles blueprint
├── static/               # Static assets (CSS, JS, images)
├── tasks.py              # Background task definitions
├── templates/            # Jinja templates
├── views.py              # General views
└── vuln/                 # Vulnerability data blueprint
```

### Instance Directory (`instance/`)
**This directory is gitignored and created at runtime.** It contains:
- `config.py` - Flask configuration (from `config/example.config.py`)
- `settings.yaml` - sec-certs tool settings (from `config/example.settings.yaml`)
- Certificate datasets (cc/, fips/, pp/)
- Search index (search/)
- CVE/CPE data files
- Generated webassets cache
- Generated documentation from the main tool (docs/) uploaded by its actions run

### MongoDB Collections
The app uses these MongoDB collections (database: `seccerts`), more are defined in `docs/database.md`:
- `cc` - Common Criteria certificates
- `cc_diff` - CC certificate change history
- `cc_log` - CC update task logs
- `fips` - FIPS 140 certificates
- `fips_diff` - FIPS certificate change history
- `fips_mip` - FIPS modules in process
- `fips_iut` - FIPS implementation under test
- `pp` - Protection Profiles
- `pp_diff` - PP change history
- `users` - Admin users
- `subs` - Notification subscriptions
- `cve` - CVE dataset entries
- `cpe` - CPE dataset entries

### Key Application Files

**`sec_certs_page/__init__.py`** - Main app initialization:
- Creates Flask app with instance configuration
- Initializes MongoDB, Redis, dramatiq broker
- Sets up Flask extensions (login, caching, CORS, CSRF, etc.)
- Registers all blueprints
- Configures Sentry monitoring (production)

**`fabfile.py`** - Deployment tasks using Fabric (for production deployment)

## Docker Support

**Build and run with Docker:**
```bash
docker build -t sec-certs-page .
docker run -p 5000:5000 sec-certs-page
```

The Dockerfile:
- Uses Ubuntu Noble base image
- Installs MongoDB 8.0 and Redis
- Installs Python 3, system dependencies
- Sets up user with uid 1001
- Clones and installs from page branch
- Downloads spaCy model
- Sets up instance configuration
- Exposes port 5000
- Runs MongoDB, Redis, and Flask on startup

## Common Workflows and Commands

### Development Workflow

Generally, you do not run the app directly. Instead, implement tests and run those.
```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run tests
pytest -m "not slow"
```

### Before Committing
```bash
# 1. Run pre-commit hooks
pre-commit run --all-files

# 2. Run tests
pytest

# 3. If all pass, commit
git add .
git commit -m "Your message"
```

## Important Notes and Gotchas

### Critical Issues to Avoid

1. **The `instance/` directory must exist** with proper config files before running the app
2. **Don't commit the `instance/` directory** - it's gitignored for security reasons
3. **The app requires Python 3.10+** - lower versions will fail
4. **Pre-commit hooks must pass** - black, isort, and mypy all need to succeed
5. **Use pytest when testing** - it sets the proper test environment variables

### Environment Variables

- `INSTANCE_PATH` - Override instance directory location, set by `pytest-env` for testing.
- `TESTING` - Set to "true" for test mode (disables dramatiq, Sentry)
- `TEST_REMOTE` - Set to "1" to run tests against https://sec-certs.org

### Working with the Main Branch

This `page` branch depends on the `main` branch of sec-certs. The typical setup is:
```bash
git clone -b page https://github.com/crocs-muni/sec-certs page
git clone -b main https://github.com/crocs-muni/sec-certs tool
cd tool && pip install -e .
cd ../page && pip install -e .
```

## Trust These Instructions

These instructions have been validated and tested. If you encounter an issue not covered here:
1. Verify your virtual environment is activated
2. Check that you're using Python 3.10+

Only search for additional information if these basics are confirmed and the issue persists.

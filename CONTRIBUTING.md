# Contributing

Your contribution is warmly welcomed. You can help by:

 1. Spreading the word about this project, using our website [sec-certs.org](https://sec-certs.org)
 2. Trying the tool and reporting issues and suggestions for improvement (open a GitHub issue)
 3. Adding new regular expressions to extract relevant information from certificates (update `rules.yaml`)
 4. Performing additional analysis with extracted data (let us know about your findings)
 5. Improving the code (Follow Github contribution guidelines, ideally contact us first about your plan)

## Dependencies

For complete list of system dependencies, see [docs/installation](https://sec-certs.org/docs/installation.html).

### Requirements

Requirements are maintained via [uv](https://docs.astral.sh/uv/). The main ideas are:
- List actual dependencies in [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) without (unnecessarily) pinning them.
- Use `uv lock` to resolve and lock the dependencies.
- Use `uv sync --inexact` to install these dependencies. Use `--inexact` to keep the `en_core_web_sm` model installed by spacy.
- Tests, linting and Docker all run against this reproducible environment of pinned requirements.

## Branches

`main` is the default branch against which all pull requests are to be made. This branch is not neccessarily stable, only the releases are.

## Releases and version strings

- Version string is not indexed in `git` but can be retreived maintained by `setuptools-scm` from git tags instead.
- `setuptools-scm` will automatically, upon editable/real install of a package, infer its version and write it to `sec_certs/_version.py`. This file is not indexed as well. See more at [setuptools-scm GitHub](https://github.com/pypa/setuptools_scm)
- On publishing a release, the tool is automatically published to [PyPi](https://pypi.org/project/sec-certs/) and [DockerHub](https://hub.docker.com/repository/docker/seccerts/sec-certs).

Note on single-sourcing the package version: More can be read [here](https://packaging.python.org/en/latest/guides/single-sourcing-package-version/). The downside of our approach is that `.git` folder and editable/real installation is needed to infer the version of the package. Releases can be inferred without installing the project.

### Currently, the release process is as follows

1. Update dependencies with `pre-commit autoupdate`, pin new versions of linters into `pyproject.toml`.
2. Run `uv lock` to update dependencies, commit the changes.
5. Create a release from GitHub UI. Include release notes, add proper version tag and publish the release (or create it from scratch with new tag).
6. This will automatically update PyPi and DockerHub packages.

## Quality assurance

All commits shall pass the lint pipeline of the following tools:

- Mypy (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) for settings)
- Ruff (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) for settings)

These tools can be installed via [dev_requirements.txt](https://github.com/crocs-muni/sec-certs/blob/main/requirements/dev_requirements.txt) You can use [pre-commit](https://pre-commit.com/) tool to register git hook that will evaluate these checks prior to any commit and abort the commit for you. Note that the pre-commit is not meant to automatically fix the issues, just warn you.

It should thus suffice to:

```bash
pip3 install -r ./dev_requirements.txt &&
pre-commit install &&
pre-commit run --all-files
```

To invoke the tools manually, you can, in the repository root, use:
- Mypy: `mypy .`
- Ruff: `ruff .` (or with `--fix` flag to apply fixes)
- Ruff format: `ruff format --check .`

## Tests

Tests are run with `pytest`. The tests are located in `tests` folder and are run with `pytest tests`. The tests are also run on every push to the repository with Github Actions.
There are two custom markers for the tests:
- `slow` for tests that take longer time to run
- `remote` for tests that require remote resources and are thus flaky.

To exclude slow tests, use `pytest -m "not slow"`. To exclude remote tests, use `pytest -m "not remote"`. To run only slow tests, use `pytest -m "slow"`. To run only remote tests, use `pytest -m "remote"`.

## Documentation

Every public method of a module that can be leveraged as an API by user should be documented. The docstring style should
be `sphinx-oneline`.

The documentation is built using `sphinx` with `mnyst` extension that allows for markdown files. Folder `notebooks/examples` is symbolically linked to `/docs` and its contents will be automatically parsed. These notebooks are supposed to be runnable from Binder.

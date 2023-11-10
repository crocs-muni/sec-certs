# Contributing

You contribution is warmly welcomed. You can help by:

 0. Spread the word about this project, look at generated processed webpages
 1. Trying the tool and reporting issues and suggestions for improvement (open Github issue)
 2. Add new regular expressions to extract relevant information from certificates (update cert_rules.py)
 3. Perform additional analysis with extracted data (analyze_certificates.py)
 3. Improve the code (TODO: Follow Github contribution guidelines, ideally contact us first about your plan)

## Dependencies

For complete list of system dependencies, see [docs/installation](https://seccerts.org/docs/installation.html).

### Requirements

Requirements are maintained with [pip-tools](https://github.com/jazzband/pip-tools). The main ideas are:
- List actual dependencies in [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) without pinning them.
- Additionally, [compile.sh](https://github.com/crocs-muni/sec-certs/blob/main/requirements/compile.sh) script is used to compile pinned versions of requirements that reside in `.txt` files in the same folder.
- Tests, linting and Docker all run against this reproducible environment of pinned requirements.
- To install all requirements, use `pip install -U pip-tools && pip-sync requirements/all_requirements.txt`

## Branches

`main` is the default branch against which all pull requests are to be made. This branch is not neccessarily stable, only the releases are.

## Releases and version strings

- Version string is not indexed in `git` but can be retreived maintained by `setuptools-scm` from git tags instead.
- `setuptools-scm` will automatically, upon editable/real install of a package, infer its version and write it to `sec_certs/_version.py`. This file is not indexed as well. See more at [setuptools-scm GitHub](https://github.com/pypa/setuptools_scm)
- On publishing a release, the tool is automatically published to [PyPi](https://pypi.org/project/sec-certs/) and [DockerHub](https://hub.docker.com/repository/docker/seccerts/sec-certs).

Note on single-sourcing the package version: More can be read [here](https://packaging.python.org/en/latest/guides/single-sourcing-package-version/). The downside of our approach is that `.git` folder and editable/real install is needed to infer the version of the package. Releases can be infered without installing the project.

### Currently, the release process is as follows

1. Update dependencies with `pre-commit autoupdate`, pin new versions of linters into `pyproject.toml` and run `cd requirements && ./compile.sh`.
2. Create a release from GitHub UI. Include release notes, add proper version tag and publish the release (or create it from scratch with new tag).
3. This will automatically update PyPi and DockerHub packages.


## Quality assurance

All commits shall pass the lint pipeline of the following tools:

- Mypy (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) for settings)
- Ruff (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) for settings)

These tools can be installed via [dev_requirements.txt](https://github.com/crocs-muni/sec-certs/blob/main/dev_requirements.txt) You can use [pre-commit](https://pre-commit.com/) tool to register git hook that will evalute these checks prior to any commit and abort the commit for you. Note that the pre-commit is not meant to automatically fix the issues, just warn you.

It should thus suffice to:

```bash
pip3 install -r ./dev_requirements.txt &&
pre-commit install &&
pre-commit run --all-files
```

To ivoke the tools manually, you can, in the repository root, use:
- Mypy: `mypy .`
- Ruff: `ruff ." (or with `--fix` flag to apply fixes)
- Ruff formatL `ruff format --check .`

## Documentation

Every public method of a module that can be leveraged as an API by user should be documented. The docstrng style should
be `sphinx-oneline`.

The documentation is built using `sphinx` with `mnyst` extension that allows for markdown files. Folder `notebooks/examples` is symbolically linked to `/docs` and its contents will be automatically parsed. These notebooks are supposed to be runnable from Binder.

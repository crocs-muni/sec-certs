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
- List actual dependencies in `.in` files inside [requirements](https://github.com/crocs-muni/sec-certs/blob/main/requirements) folder without pinning them.
- Those dependencies are loaded into [setup.py](https://github.com/crocs-muni/sec-certs/blob/main/setup.py) file.
- Additionally, [compile.sh](https://github.com/crocs-muni/sec-certs/blob/main/requirements/compile.sh) script is used to compile pinned versions of requirements that reside in `.txt` files in the same folder.
- Tests, linting and Docker all run against this reproducible environment of pinned requirements.

## Branches

`main` is the default branch against which all pull requests are to be made. This branch is not neccessarily stable, only the releases are.

## Releases and version strings

- On each revision pushed onto `main` that has `*.*.*` tag, a draft release is created with prepared changelog (this step can be skipped and the Release created right from the GitHub GUI).
- This draft release is to be published manually by the maintainer.
- Version string is not indexed in `git` but can be retreived maintained by `setuptools-scm` from git tags instead.
- `setuptools-scm` will automatically, upon editable/real install of a package, infer its version and write it to `sec_certs/_version.py`. This file is not indexed as well. See more at [setuptools-scm GitHub](https://github.com/pypa/setuptools_scm)
- On publishing a release, the tool is automatically published to [PyPi](https://pypi.org/project/sec-certs/) and [DockerHub](https://hub.docker.com/repository/docker/seccerts/sec-certs).

Note on single-sourcing the package version: More can be read [here](https://packaging.python.org/en/latest/guides/single-sourcing-package-version/). The downside of our approach is that `.git` folder and editable/real install is needed to infer the version of the package. Releases can be infered without installing the project.

### Currently, the release process is as follows

1. (skip this optionally) Tag a revision with `*.*.*` tag -- this will create a draft release in GitHub.
2. Modify changelog and publish the release (or create it from scratch with new tag).
3. This will automatically update PyPi and DockerHub packages.


## Quality assurance

All commits shall pass the lint pipeline of the following tools:

- Mypy (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) for settings)
- Black (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) for settings)
- isort (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/main/pyproject.toml) for settings)
- Flake8 (see [.flake8](https://github.com/crocs-muni/sec-certs/blob/main/.flake8) for settings)

These tools can be installed via [dev_requirements.txt](https://github.com/crocs-muni/sec-certs/blob/main/dev_requirements.txt) You can use [pre-commit](https://pre-commit.com/) tool register git hook that will evalute these checks prior to any commit and abort the commit for you. Note that the pre-commit is not meant to automatically fix the issues, just warn you.

It should thus suffice to:

```bash
pip3 install -r ./dev_requirements.txt &&
pre-commit install &&
pre-commit run --all-files
```

To ivoke the tools manually, you can, in the repository root, use:
- Mypy: `mypy .`
- Black: `black --check .` (without the flag to reformat)
- isort: `isort --check-only .` (without the flag to actually fix the issue)
- Flake8: `flake8 .`

## Documentation

Every public method of a module that can be leveraged as an API by user should be documented. The docstrng style should
be `sphinx-oneline`.

The documentation is built using `sphinx` with `mnyst` extension that allows for markdown files. Folder `notebooks/examples` is symbolically linked to `/docs` and its contents will be automatically parsed. These notebooks are supposed to be runnable from Binder.
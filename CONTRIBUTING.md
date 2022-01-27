## Contributing

You contribution is warmly welcomed. You can help by:

 0. Spread the word about this project, look at generated processed webpages
 1. Trying the tool and reporting issues and suggestions for improvement (open Github issue)
 2. Add new regular expressions to extract relevant information from certificates (update cert_rules.py) 
 3. Perform additional analysis with extracted data (analyze_certificates.py)
 3. Improve the code (TODO: Follow Github contribution guidelines, ideally contact us first about your plan)

## Branches

- `dev` is the default branch against which all pull requests are to be made. 
- `master` is protected branch where stable releases reside. Each push or PR to master should be properly tagged by [semantic version](https://semver.org/) as it will invoke actions to publish docker image and PyPi package. 

## Quality assurance

All commits shall pass the lint pipeline of the following tools:

- Mypy (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/dev/pyproject.toml) for settings)
- Black (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/dev/pyproject.toml) for settings)
- isort (see [pyproject.toml](https://github.com/crocs-muni/sec-certs/blob/dev/pyproject.toml) for settings)
- Flake8 (see [.flake8](https://github.com/crocs-muni/sec-certs/blob/dev/.flake8) for settings)

These tools can be installed via [dev_requirements.txt](https://github.com/crocs-muni/sec-certs/blob/dev/dev_requirements.txt) You can use [pre-commit](https://pre-commit.com/) tool register git hook that will evalute these checks prior to any commit and abort the commit for you. Note that the pre-commit is not meant to automatically fix the issues, just warn you. 

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
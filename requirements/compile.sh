#!/bin/bash

# See CONTRIBUTING.md for description

pip-compile --no-header --resolver=backtracking --output-file=requirements.txt ./../pyproject.toml
pip-compile --no-header --resolver=backtracking --extra dev -o dev_requirements.txt ./../pyproject.toml
pip-compile --no-header --resolver=backtracking --extra test -o test_requirements.txt ./../pyproject.toml

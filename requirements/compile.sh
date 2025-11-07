#!/bin/bash

# See CONTRIBUTING.md for description

pip-compile --upgrade --no-header -o requirements.txt ./../pyproject.toml
pip-compile --upgrade --no-header --extra dev -o dev_requirements.txt ./../pyproject.toml
pip-compile --upgrade --no-header --extra test -o test_requirements.txt ./../pyproject.toml
pip-compile --upgrade --no-header --extra nlp -o nlp_requirements.txt ./../pyproject.toml
pip-compile --upgrade --no-header --extra docling -o docling_requirements.txt ./../pyproject.toml
pip-compile --upgrade --no-header --extra dev --extra test --extra nlp --extra docling -o all_requirements.txt ./../pyproject.toml

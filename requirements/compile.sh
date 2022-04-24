#!/bin/bash

# See CONTRIBUTING.md for description

pip-compile requirements.in --no-header
pip-compile dev_requirements.in --no-header
pip-compile test_requirements.in --no-header

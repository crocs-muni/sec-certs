#!/bin/bash

# See CONTRIBUTING.md for description

pip-compile requirements.in --no-header --annotation-style line
pip-compile dev_requirements.in --no-header --annotation-style line
pip-compile test_requirements.in --no-header --annotation-style line

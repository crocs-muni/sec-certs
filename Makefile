
test:
	pytest

test-remote:
	env TEST_REMOTE=yes pytest -m remote

typecheck:
	mypy sec_certs_page

import-sort:
	isort sec_certs_page

format:
	black sec_certs_page

codestyle:
	flake8 sec_certs_page

.PHONY: test test-remote typecheck import-sort format codestyle
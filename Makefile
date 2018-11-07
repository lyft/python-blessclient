# bash needed for pipefail
SHELL := /bin/bash

# Pull in persistant config
-include ~/.blessclient.cfg

.PHONY: client
client:
	rm -rf ./blessclient.run
	virtualenv venv
	venv/bin/pip install -e .
	ln -s venv/bin/blessclient ./blessclient.run

.PHONY: clean
clean:
	rm -rf blessclient.run coverage.xml .coverage blessclient.egg-info/ build/ venv/
	find . -name "*.pyc" -type f -delete

.PHONY: develop
develop:
	pip install -r requirements-dev.txt

.PHONY: test
test: test_lint test_unit

test_lint:
	mkdir -p build
	set -o pipefail; flake8 | sed "s#^\./##" > build/flake8.txt || (cat build/flake8.txt && exit 1)

.PHONY: test_unit
test_unit:
	py.test --cov=blessclient tests/

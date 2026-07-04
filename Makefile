# TokenDNA developer convenience targets.
# `make install` sets up everything (core + platform + collector sub-packages);
# `make test` runs the full suite the same way CI does.

PY ?= python

.PHONY: install test lint clean

install:  ## install core requirements + the platform/ and collector/ sub-packages
	pip install -r requirements.txt pytest pytest-asyncio ruff
	pip install -e ./platform

test:  ## run the full suite (backend + platform) — matches CI
	$(PY) -m pytest -q --import-mode=importlib tests platform/tests

lint:  ## static checks
	ruff check .

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache

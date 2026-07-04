# TokenDNA developer convenience targets.
# `make install` sets up everything (core + platform + collector sub-packages);
# `make test` runs the full suite the same way CI does.

PY ?= python

.PHONY: install test lint clean

install:  ## install core requirements + test/lint tooling
	pip install -r requirements.txt pytest pytest-asyncio ruff

test:  ## run the full suite — matches CI
	$(PY) -m pytest -q --import-mode=importlib tests

lint:  ## static checks
	ruff check .

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache

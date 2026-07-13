# TokenDNA developer convenience targets.
# `make install` sets up core deps; `make test` runs the full suite like CI.
# `make trial-up` / `make trial-reset` drive the self-host evaluation trial.

PY ?= python
TRIAL_COMPOSE = docker compose -f deploy/trial/docker-compose.trial.yml --env-file .env.trial

.PHONY: install test lint clean trial-up trial-reset trial-down

install:  ## install core requirements + test/lint tooling
	pip install -r requirements.txt pytest pytest-asyncio ruff

test:  ## run the full suite — matches CI
	$(PY) -m pytest -q --import-mode=importlib tests

lint:  ## static checks
	ruff check .

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache

# ── Self-host trial (real OIDC, SQLite, local volume) ─────────────────────────
trial-up:  ## build + run the self-host trial (needs .env.trial — see .env.trial.example)
	@test -f .env.trial || { echo "Missing .env.trial — copy .env.trial.example and fill it in."; exit 1; }
	$(TRIAL_COMPOSE) up -d --build
	@echo "Trial up on http://localhost:8000  (console: /console, health: /healthz)"

trial-reset:  ## wipe imported trial data + re-seed demo fixtures (no rebuild)
	$(TRIAL_COMPOSE) down -v
	$(TRIAL_COMPOSE) up -d
	@echo "Trial reset: imported data wiped, demo fixtures re-seeded."

trial-down:  ## stop the trial (keeps the data volume)
	$(TRIAL_COMPOSE) down

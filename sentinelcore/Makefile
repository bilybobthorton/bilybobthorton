# SentinelCore — dev convenience commands
# Run from the sentinelcore/ directory

PYTHON := PYTHONPATH=. python3
COMPOSE := docker compose -f infra/docker-compose.yml

.PHONY: help up down build logs migrate train-synthetic test lint \
        prod-up prod-down prod-build prod-logs prod-deploy prod-migrate

help:
	@echo ""
	@echo "  SentinelCore — available commands"
	@echo ""
	@echo "  ── Development ─────────────────────────────────────────────────"
	@echo "  make up              Start dev stack (postgres, redis, api, worker, dashboard, nginx)"
	@echo "  make down            Stop dev containers"
	@echo "  make build           Rebuild dev images"
	@echo "  make logs            Tail dev container logs"
	@echo "  make migrate         Run Alembic migrations (dev)"
	@echo "  make train-synthetic Generate synthetic ML model (dev only)"
	@echo "  make test            Run pytest suite"
	@echo "  make lint            Run ruff linter"
	@echo ""
	@echo "  ── Production ──────────────────────────────────────────────────"
	@echo "  make prod-up         Start production stack"
	@echo "  make prod-down       Stop production stack"
	@echo "  make prod-build      Rebuild production images"
	@echo "  make prod-logs       Tail production logs"
	@echo "  make prod-migrate    Run migrations against production DB"
	@echo "  make prod-deploy     Pull + build + migrate + restart (rolling)"
	@echo ""

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

build:
	$(COMPOSE) build --no-cache

logs:
	$(COMPOSE) logs -f

migrate:
	$(COMPOSE) run --rm migrate

train-synthetic:
	$(PYTHON) -m engine.ml.trainer --synthetic

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check api/ engine/ --ignore E501

dev-api:
	$(PYTHON) -m uvicorn api.main:app --reload --port 8000

dev-worker:
	$(PYTHON) -m celery -A api.tasks.celery_app worker --loglevel=info

dev-dashboard:
	cd dashboard && npm run dev

# ── Production targets ────────────────────────────────────────────────────────
PROD_COMPOSE := docker compose -f infra/docker-compose.prod.yml

prod-up:
	$(PROD_COMPOSE) up -d

prod-down:
	$(PROD_COMPOSE) down

prod-build:
	$(PROD_COMPOSE) build --no-cache

prod-logs:
	$(PROD_COMPOSE) logs -f

prod-migrate:
	$(PROD_COMPOSE) run --rm migrate

prod-deploy:
	bash scripts/deploy.sh

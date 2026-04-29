# SentinelCore — dev convenience commands
# Run from the sentinelcore/ directory

PYTHON := PYTHONPATH=. python3
COMPOSE := docker compose -f infra/docker-compose.yml

.PHONY: help up down build logs migrate train-synthetic test lint

help:
	@echo ""
	@echo "  SentinelCore — available commands"
	@echo ""
	@echo "  make up              Start full stack (postgres, redis, api, worker, dashboard, nginx)"
	@echo "  make down            Stop all containers"
	@echo "  make build           Rebuild all Docker images"
	@echo "  make logs            Tail all container logs"
	@echo "  make migrate         Run Alembic migrations"
	@echo "  make train-synthetic Generate synthetic ML model (dev only)"
	@echo "  make test            Run pytest suite"
	@echo "  make lint            Run ruff linter"
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

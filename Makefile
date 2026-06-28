# ForgeShield OT — developer convenience targets
SHELL := /bin/bash
COMPOSE := docker compose

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: env
env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example — edit it with your Supabase + AI values")

.PHONY: up
up: env ## Build and start the full stack
	$(COMPOSE) up --build -d
	@echo "Backend:  http://localhost:8000/docs"
	@echo "Frontend: http://localhost:5173"

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: reset
reset: ## Stop the stack and delete the database volume, then start fresh
	$(COMPOSE) down -v
	$(COMPOSE) up --build -d

.PHONY: logs
logs: ## Tail logs for all services
	$(COMPOSE) logs -f

.PHONY: migrate
migrate: ## Run alembic migrations inside the backend container
	$(COMPOSE) exec backend alembic upgrade head

.PHONY: makemigration
makemigration: ## Autogenerate an alembic revision (use M="message")
	$(COMPOSE) exec backend alembic revision --autogenerate -m "$(M)"

.PHONY: seed
seed: ## Load idempotent demo data (and Supabase demo users if service key present)
	$(COMPOSE) exec backend python -m app.seed.cli

.PHONY: test
test: ## Run the backend pytest suite
	$(COMPOSE) exec backend pytest -q

.PHONY: lint
lint: ## Lint + type-check the backend
	$(COMPOSE) exec backend ruff check app
	$(COMPOSE) exec backend mypy app

.PHONY: fmt
fmt: ## Auto-format the backend
	$(COMPOSE) exec backend ruff format app
	$(COMPOSE) exec backend ruff check --fix app

.PHONY: fe-test
fe-test: ## Run frontend unit tests
	$(COMPOSE) exec frontend npm run test -- --run

.PHONY: shell
shell: ## Open a shell in the backend container
	$(COMPOSE) exec backend bash

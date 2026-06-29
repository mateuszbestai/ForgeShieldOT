# ForgeShield OT — developer convenience targets
SHELL := /bin/bash
COMPOSE := docker compose

# ---- Local LLM (llama.cpp / Foundation-Sec-8B-Reasoning GGUF) ----
LLAMA_GGUF    ?= foundation-sec-8b-reasoning-q4_k_m.gguf
LLAMA_HF_REPO ?= fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF
LLAMA_VOLUME  ?= forgeshield-ot_llama-models

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

.PHONY: llama-pull
llama-pull: ## Download/resume the Foundation-Sec GGUF into the llama-models volume (public; no HF token)
	docker volume create $(LLAMA_VOLUME) >/dev/null
	docker run --rm --user 0 -v $(LLAMA_VOLUME):/models curlimages/curl:latest \
	  -L -C - --retry 5 --retry-delay 5 -o /models/$(LLAMA_GGUF) \
	  "https://huggingface.co/$(LLAMA_HF_REPO)/resolve/main/$(LLAMA_GGUF)?download=true"
	@docker run --rm -v $(LLAMA_VOLUME):/models alpine ls -lh /models/$(LLAMA_GGUF)
	@echo "Expected ~4.9G. If it's smaller, the download was cut off — re-run 'make llama-pull' to resume."

.PHONY: up-gpu
up-gpu: env ## Build and start the stack with the NVIDIA GPU llama.cpp service
	$(COMPOSE) -f docker-compose.yml -f docker-compose.gpu.yml up --build -d
	@echo "Backend:  http://localhost:8000/docs"
	@echo "Frontend: http://localhost:5173"
	@echo "LLM:      http://localhost:8080/health"

.PHONY: llama-logs
llama-logs: ## Tail the llama.cpp inference server logs
	$(COMPOSE) logs -f llama

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

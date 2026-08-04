.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
PYTHON       ?= python3
UV           ?= uv
PKG          := prometheon
SRC_DIR      := src/$(PKG)
TESTS_DIR    := tests
NEURONS_DIR  := neurons
DOCKER       ?= docker
DOCKER_TAG   ?= dev

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_.-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------
.PHONY: install
install: ## Sync runtime and dev dependencies (uv).
	$(UV) sync --group dev

.PHONY: lock
lock: ## Regenerate uv.lock from pyproject.toml.
	$(UV) lock

.PHONY: refresh
refresh: ## Re-lock and re-sync (use after changing pyproject.toml).
	$(UV) lock
	$(UV) sync --group dev

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------
.PHONY: lint
lint: ## Run ruff lint.
	$(UV) run ruff check $(SRC_DIR) $(TESTS_DIR) $(NEURONS_DIR)

.PHONY: lint-fix
lint-fix: ## Run ruff lint with --fix.
	$(UV) run ruff check --fix $(SRC_DIR) $(TESTS_DIR) $(NEURONS_DIR)

.PHONY: format
format: ## Run ruff format.
	$(UV) run ruff format $(SRC_DIR) $(TESTS_DIR) $(NEURONS_DIR)

.PHONY: format-check
format-check: ## Verify ruff format would be a no-op.
	$(UV) run ruff format --check $(SRC_DIR) $(TESTS_DIR) $(NEURONS_DIR)

.PHONY: format-all
format-all: lint-fix format ## Run lint-fix then format. Convenience alias.

.PHONY: typecheck
typecheck: ## Run mypy on the package.
	$(UV) run mypy $(SRC_DIR)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
.PHONY: test
test: ## Run fast unit tests only.
	$(UV) run pytest -m "unit"

.PHONY: test-contract
test-contract: ## Run contract tests (shared platform/subnet fixtures).
	$(UV) run pytest -m "contract"

.PHONY: test-integration
test-integration: ## Run integration tests (mock platform, mock chain).
	$(UV) run pytest -m "integration"

.PHONY: test-localnet
test-localnet: ## Run localnet tests (requires running Bittensor localnet).
	$(UV) run pytest -m "localnet"

.PHONY: test-all
test-all: ## Run every test marker except localnet.
	$(UV) run pytest -m "unit or contract or integration"

.PHONY: cov
cov: ## Run unit tests with coverage reporting.
	$(UV) run pytest -m "unit" --cov=$(PKG) --cov-report=term-missing

# ---------------------------------------------------------------------------
# Aggregate quality gate
# ---------------------------------------------------------------------------
.PHONY: check
check: lint format-check typecheck test ## Run lint, format-check, typecheck, and unit tests.

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
.PHONY: docker-validator
docker-validator: ## Build the validator container image.
	$(DOCKER) build -f docker/Dockerfile.validator -t $(PKG)-validator:$(DOCKER_TAG) .

.PHONY: docker-up
docker-up: ## Bring up both validator processes (ingest + runner) via compose.
	$(DOCKER) compose -f docker/compose.yaml up --build -d

# There is no miner image on purpose: a Phase 1 miner runs no daemon. The
# reward path is Fan Group growth on the platform; the CLI is a one-time
# verify plus a status read.

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
.PHONY: clean
clean: ## Remove caches and build artefacts.
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name "*.py[cod]" -delete

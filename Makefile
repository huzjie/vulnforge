.PHONY: install install-full install-test test lint scan serve build clean doctor

PYTHON ?= python
PIP ?= pip

install: ## Install the base package in editable mode
	$(PIP) install -e .

install-full: ## Install with full dependencies (web API + LLM providers)
	$(PIP) install -e ".[full]"

install-test: ## Install with test dependencies
	$(PIP) install -e ".[test]"

doctor: ## Run environment/health checks
	vulnforge doctor

test: ## Run the test suite
	$(PYTHON) -m pytest

lint: ## Compile-check all Python sources
	$(PYTHON) -m compileall vulnforge

scan: ## Run vulnforge against the current repository
	vulnforge scan .

serve: ## Start the vulnforge API server
	vulnforge serve

build: ## Build the React console into web/dist
	cd web && npm install && npm run build

clean: ## Remove build artifacts and caches
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	rm -rf web/node_modules web/dist
	rm -rf results reports .corpus .crash .vf_cache

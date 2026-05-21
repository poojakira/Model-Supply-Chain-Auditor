.PHONY: help install dev lint format test test-cov type-check verify clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install package
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"

lint: ## Run linter
	ruff check src/ tests/

format: ## Format code
	ruff format src/ tests/

test: ## Run tests
	pytest tests/ -v

test-cov: ## Run tests with coverage
	pytest tests/ -v --cov=src --cov-report=term-missing

type-check: ## Run type checker
	mypy src/

verify: ## Run end-to-end verification
	python verify.py

clean: ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info .coverage .pytest_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

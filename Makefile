# Makefile
.PHONY: help install install-dev test lint format clean docker-build docker-run

help:
	@echo "Available commands:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo "  test         Run tests"
	@echo "  lint         Run linting"
	@echo "  format       Format code"
	@echo "  clean        Clean up generated files"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run in Docker container"

install:
	pip install -r requirements.txt
	playwright install chromium

install-dev:
	pip install -r requirements.txt
	pip install -e ".[dev]"
	playwright install chromium
	pre-commit install

test:
	pytest tests/ --cov=src --cov-report=html --cov-report=term

lint:
	flake8 src/
	mypy src/ --ignore-missing-imports
	bandit -r src/

format:
	black src/ tests/
	isort src/ tests/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docker-build:
	docker build -t email-security-analyzer .

docker-run:
	docker-compose up email-analyzer

docker-dev:
	docker-compose run --rm email-analyzer-dev
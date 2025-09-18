# Makefile for Judgement Security Testing Framework
.PHONY: help install install-dev clean test lint format check validate run setup docs

# Default target
help:
	@echo "Judgement Framework - Available Commands:"
	@echo ""
	@echo "📦 Installation:"
	@echo "  make install     - Install core dependencies"
	@echo "  make install-dev - Install with development dependencies"
	@echo "  make setup       - Run automated setup script"
	@echo ""
	@echo "🔧 Development:"
	@echo "  make test        - Run test suite"
	@echo "  make lint        - Run code linting"
	@echo "  make format      - Format code with black"
	@echo "  make check       - Run all code quality checks"
	@echo "  make validate    - Validate installation"
	@echo ""
	@echo "🚀 Usage:"
	@echo "  make run         - Start Judgement framework"
	@echo "  make clean       - Clean generated files"
	@echo "  make docs        - Generate documentation"
	@echo ""
	@echo "📊 Information:"
	@echo "  make version     - Show version information"
	@echo "  make status      - Show project status"

# Installation targets
install:
	@echo "📦 Installing core dependencies..."
	pip3 install -r requirements.txt
	@echo "✅ Core installation complete"

install-dev:
	@echo "📦 Installing development dependencies..."
	pip3 install -r requirements-dev.txt
	@echo "✅ Development installation complete"

setup:
	@echo "🚀 Running automated setup..."
	chmod +x setup.sh
	./setup.sh

# Development targets
test:
	@echo "🧪 Running test suite..."
	@if command -v pytest >/dev/null 2>&1; then \
		pytest -v --tb=short; \
	else \
		echo "⚠️  pytest not installed. Run 'make install-dev' first"; \
	fi

lint:
	@echo "🔍 Running code linting..."
	@if command -v flake8 >/dev/null 2>&1; then \
		flake8 Judgement.py --max-line-length=100 --ignore=E501,W503; \
	else \
		echo "⚠️  flake8 not installed. Run 'make install-dev' first"; \
	fi
	@if command -v bandit >/dev/null 2>&1; then \
		bandit -r Judgement.py -f txt -q; \
	else \
		echo "⚠️  bandit not installed. Install with: pip install bandit"; \
	fi

format:
	@echo "🎨 Formatting code..."
	@if command -v black >/dev/null 2>&1; then \
		black Judgement.py --line-length=100; \
	else \
		echo "⚠️  black not installed. Run 'make install-dev' first"; \
	fi

check: lint
	@echo "✅ Running all code quality checks..."
	@if command -v mypy >/dev/null 2>&1; then \
		mypy Judgement.py --ignore-missing-imports; \
	else \
		echo "⚠️  mypy not installed. Run 'make install-dev' first"; \
	fi

validate:
	@echo "🔍 Validating installation..."
	python3 validate.py

# Usage targets
run:
	@echo "🚀 Starting Judgement Framework..."
	python3 Judgement.py

clean:
	@echo "🧹 Cleaning generated files..."
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -f validation_report.json
	rm -f *.log
	@echo "✅ Cleanup complete"

docs:
	@echo "📚 Generating documentation..."
	@if command -v sphinx-build >/dev/null 2>&1; then \
		mkdir -p docs; \
		sphinx-quickstart docs --quiet --project="Judgement" --author="Security Team"; \
		echo "📖 Documentation structure created in docs/"; \
	else \
		echo "📋 Documentation available in:"; \
		echo "  - README.md (User guide)"; \
		echo "  - TECHNICAL_ANALYSIS.md (Technical docs)"; \
		echo "  - CHANGELOG.md (Version history)"; \
	fi

# Information targets
version:
	@echo "📊 Version Information:"
	python3 version.py

status:
	@echo "📈 Project Status:"
	@echo "Files:"
	@wc -l *.py *.md *.txt *.sh 2>/dev/null | tail -1
	@echo ""
	@echo "Main Script:"
	@wc -l Judgement.py
	@echo ""
	@echo "Dependencies:"
	@if [ -f requirements.txt ]; then wc -l requirements.txt; fi
	@if [ -f requirements-dev.txt ]; then wc -l requirements-dev.txt; fi

# Security targets
security-check:
	@echo "🛡️  Running security checks..."
	@if command -v bandit >/dev/null 2>&1; then \
		bandit -r . -x test_*.py -f json -o security_report.json; \
		echo "📋 Security report saved to security_report.json"; \
	else \
		echo "⚠️  bandit not installed. Install with: pip install bandit"; \
	fi

# Quick development workflow
dev: install-dev validate test lint
	@echo "🎯 Development environment ready!"

# Production deployment check
production-check: validate test security-check
	@echo "🚀 Production readiness check complete!"

# Git hooks setup (if using git)
hooks:
	@if [ -d .git ]; then \
		echo "🔗 Setting up git hooks..."; \
		echo "#!/bin/bash" > .git/hooks/pre-commit; \
		echo "make lint" >> .git/hooks/pre-commit; \
		chmod +x .git/hooks/pre-commit; \
		echo "✅ Pre-commit hook installed"; \
	else \
		echo "⚠️  Not a git repository"; \
	fi
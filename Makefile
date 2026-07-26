PYTHON ?= python3

.PHONY: build check lint test typecheck

lint:
	@$(PYTHON) -m ruff check src tests
	@$(PYTHON) -m ruff format --check src tests

typecheck:
	@MYPYPATH=src $(PYTHON) -m mypy --strict src tests

test:
	@PYTHONPATH=src $(PYTHON) -m pytest \
		--cov=password_policy_lab \
		--cov-branch \
		--cov-report=term-missing \
		-q

build:
	@$(PYTHON) -m build

check: lint typecheck test

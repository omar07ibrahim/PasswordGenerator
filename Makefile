PYTHON ?= python3

.PHONY: build check lint test typecheck

lint:
	@$(PYTHON) -m ruff check app.py src tests
	@$(PYTHON) -m ruff format --check app.py src tests

typecheck:
	@MYPYPATH=src $(PYTHON) -m mypy --strict app.py src tests

test:
	@PYTHONPATH=src $(PYTHON) -m pytest \
		--cov=password_policy_lab \
		--cov-branch \
		--cov-report=term-missing \
		-q

build:
	@$(PYTHON) -m build

check: lint typecheck test

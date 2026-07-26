PYTHON ?= python3
EVIDENCE_WORK ?= $(CURDIR)/.evidence-work
PLAYWRIGHT_BROWSERS_PATH ?= $(CURDIR)/.playwright-browsers
EVIDENCE_ENV = \
	PLAYWRIGHT_BROWSERS_PATH="$(PLAYWRIGHT_BROWSERS_PATH)" \
	LC_ALL=C.UTF-8 \
	MPLCONFIGDIR="$(EVIDENCE_WORK)/mplconfig" \
	MPLBACKEND=Agg \
	PYTHONHASHSEED=0 \
	PYTHONUTF8=1 \
	TZ=UTC \
	XDG_CACHE_HOME="$(EVIDENCE_WORK)/xdg" \
	TMPDIR="$(EVIDENCE_WORK)/tmp" \
	TMP="$(EVIDENCE_WORK)/tmp" \
	TEMP="$(EVIDENCE_WORK)/tmp"

.PHONY: \
	build check dependencies evidence evidence-browser evidence-check lint test \
	typecheck

lint:
	@$(PYTHON) -m ruff check app.py scripts src tests
	@$(PYTHON) -m ruff format --check app.py scripts src tests

typecheck:
	@MYPYPATH=src $(PYTHON) -m mypy --strict app.py scripts src tests

test:
	@PYTHONPATH=src $(PYTHON) -m pytest \
		--cov=password_policy_lab \
		--cov-branch \
		--cov-report=term-missing \
		-q

build:
	@$(PYTHON) -m build

dependencies:
	@$(PYTHON) -m pip check

evidence-browser:
	@mkdir -p "$(EVIDENCE_WORK)/tmp" "$(EVIDENCE_WORK)/xdg"
	@$(EVIDENCE_ENV) $(PYTHON) -m playwright install chromium

evidence:
	@mkdir -p "$(EVIDENCE_WORK)/mplconfig" "$(EVIDENCE_WORK)/tmp" \
		"$(EVIDENCE_WORK)/xdg"
	@$(EVIDENCE_ENV) PYTHONPATH=src $(PYTHON) scripts/generate_evidence.py

evidence-check:
	@mkdir -p "$(EVIDENCE_WORK)/mplconfig" "$(EVIDENCE_WORK)/tmp" \
		"$(EVIDENCE_WORK)/xdg"
	@$(EVIDENCE_ENV) PYTHONPATH=src $(PYTHON) scripts/check_evidence.py

check: lint typecheck test dependencies evidence-check

# osidb-mcp — local dev, CI parity, build, PyPI upload
#
# Defaults match .github/workflows/ci.yml (pip + editable install).
# Optional: `make sync` / `make test-uv` if you use uv (uv.lock present).

PYTHON       ?= python3
PIP          := $(PYTHON) -m pip
PYTEST_ARGS  ?=
TWINE        := $(PYTHON) -m twine

.PHONY: help install sync test livetest test-uv audit check build clean upload version brew

help:
	@echo "osidb-mcp — common targets"
	@echo "  make install   # pip install -e \".[dev]\" (same idea as CI)"
	@echo "  make sync      # uv sync --extra dev (requires uv)"
	@echo "  make test      # pytest (unit/offline tests under tests/ only)"
	@echo "  make livetest  # optional integration tests vs real OSIDB (-vv -s count lines; see live_tests/README.md)"
	@echo "  make test-uv   # uv run pytest (tests/ only)"
	@echo "  make audit     # pip-audit (current environment)"
	@echo "  make check     # test + audit"
	@echo "  make build     # sdist + wheel under dist/"
	@echo "  make clean     # remove build artifacts"
	@echo "  make upload    # twine check + upload dist/* (needs twine + credentials)"
	@echo "  make version   # print package version (no OSIDB needed)"

install:
	$(PIP) install -U pip
	$(PIP) install -e ".[dev]"

sync:
	uv sync --extra dev

test:
	$(PYTHON) -m pytest tests $(PYTEST_ARGS)

livetest:
	$(PYTHON) -m pytest live_tests -vv -s $(PYTEST_ARGS)

test-uv:
	uv run pytest tests $(PYTEST_ARGS)

audit:
	$(PYTHON) -m pip_audit

check: test audit

build:
	$(PIP) install -q build
	$(PYTHON) -m build

clean:
	rm -rf dist/ build/ .eggs/
	rm -rf src/*.egg-info *.egg-info
	rm -rf .pytest_cache

upload: build
	$(PIP) install -q twine
	$(TWINE) check dist/*
	$(TWINE) upload dist/*

version:
	@$(PYTHON) -m osidb_mcp --version


brew: ## Generate Homebrew formula (requires package on PyPI)
	@mkdir -p Formula
	@VERSION=$$(grep '^version' pyproject.toml | sed 's/.*"\(.*\)"/\1/') && \
	read -r URL SHA <<< "$$(curl -sfL "https://pypi.org/pypi/osidb-mcp/$$VERSION/json" | \
		python3 -c "import json,sys;d=json.load(sys.stdin);u=next(x for x in d['urls'] if x['filename'].endswith('.tar.gz'));print(u['url'], u['digests']['sha256'])")" || \
	{ echo "Error: osidb-mcp $$VERSION not found on PyPI. Run 'make upload' first." >&2; exit 1; } && \
	sed -e "s|@@URL@@|$$URL|g" -e "s|@@SHA256@@|$$SHA|g" \
		Formula/osidb-mcp.rb.in > Formula/osidb-mcp.rb && \
	echo "==> Formula/osidb-mcp.rb (version $$VERSION)" && \
	echo "    Install locally:  brew install --formula Formula/osidb-mcp.rb" && \
	echo "    For a tap: copy Formula/osidb-mcp.rb to your homebrew-tap repo"
	rsync -avz Formula/osidb-mcp.rb ../homebrew-osidb-mcp/Formula/osidb-mcp.rb

#!/bin/bash
# Local mirror of .github/workflows/commit.yaml (check-only; never modifies files).
set -euo pipefail
cd "$(dirname "$0")"

uv sync --locked --all-groups

# linters
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy --version
uv run --locked mypy -p napalm --config-file mypy.ini
uv audit --locked --preview-features audit-command

# std_tests
uv run --locked pytest --cov=napalm --cov-report term-missing -vs

# build_docs
uv run --locked make doctest

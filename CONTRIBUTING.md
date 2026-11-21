# Contributing to NAPALM

Thank you for your interest in contributing to NAPALM! This guide outlines the development setup and CI requirements so your contributions pass all checks.

## Prerequisites

This project uses [uv](https://github.com/astral-sh/uv) for dependency and environment management. Install it before getting started. **uv >= 0.13.4 is required** (enforced via
`required-version` in `pyproject.toml`); update with `uv self update`.

Always use `--locked` with `uv sync` / `uv run` so `uv.lock` is never modified
implicitly. Only run `uv lock` when deliberately changing dependencies. New package
releases are ignored for 7 days (`exclude-newer` cooldown) as supply-chain protection.

**Python versions supported:** 3.10, 3.11, 3.12, 3.13, 3.14

## Getting Started

1. **Fork and clone the repository:**

   ```bash
   git clone https://github.com/<your-username>/napalm.git
   cd napalm
   ```

2. **Install dependencies:**

   ```bash
   uv sync --locked --all-groups
   ```

## Running all checks

`tests.sh` runs the same checks as CI (check-only; it never modifies files):

```bash
./tests.sh
```

## Code Style & Linting

All code must pass the following checks before a pull request will be accepted. These run automatically in CI on every push and pull request.

### Ruff (linting + security)

```bash
uv run --locked ruff check .
```

This includes the flake8-bandit `S` security rules (ignored rules are listed in
`pyproject.toml`; `S` is disabled under `test/`). Mark confirmed false positives with
`# noqa: S###`.

### Ruff (formatting)

```bash
uv run --locked ruff format .
```

Locally this fixes files. CI runs `ruff format --check .` and fails if any file needs
reformatting.

### Mypy (type checking)

```bash
uv run --locked mypy --version
uv run --locked mypy -p napalm --config-file mypy.ini
```

### Dependency vulnerability audit

```bash
uv audit --locked --preview-features audit-command
```

Fails if any locked dependency has a known vulnerability.

## Running Tests

Tests are run with `pytest` and coverage reporting is enabled:

```bash
uv run --locked pytest --cov=napalm --cov-report term-missing -vs
```

Tests are executed in CI against the following matrix:

| Platform     | Python versions              |
|--------------|------------------------------|
| Ubuntu 24.04 | 3.10, 3.11, 3.12, 3.13, 3.14 |
| macOS 15     | 3.12, 3.13, 3.14              |

## Documentation

The documentation build (Sphinx HTML, warnings treated as errors) runs after the
standard test suite passes:

```bash
uv run --locked make doctest
```

## CI Pipeline Summary

The following jobs run automatically via GitHub Actions on every push and pull request:

| Job                | Description                                      |
|--------------------|--------------------------------------------------|
| `linters`          | Runs ruff (lint incl. `S` + format check), mypy, uv audit |
| `std_tests`        | Runs pytest on Ubuntu across all Python versions |
| `std_tests_macos`  | Runs pytest on macOS for Python 3.12–3.14        |
| `build_docs`       | Builds documentation (requires std_tests)        |

CI is check-only: it never modifies code and uses `--locked` everywhere. There is no
PyPI publishing from GitHub Actions.

## Pull Request Checklist

Before submitting a pull request, please ensure:

- [ ] `./tests.sh` passes
- [ ] Code passes `ruff check` (incl. `S` security rules) and `ruff format`
- [ ] Code passes `mypy` type checking
- [ ] All tests pass locally with `pytest`
- [ ] `uv audit` reports no known vulnerabilities
- [ ] New functionality includes appropriate tests
- [ ] Documentation is updated if necessary

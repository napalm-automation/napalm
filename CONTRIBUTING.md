# Contributing to NAPALM

Thank you for your interest in contributing to NAPALM! This guide outlines the development setup and CI requirements so your contributions pass all checks.

## Prerequisites

This project uses [uv](https://github.com/astral-sh/uv) for dependency and environment management. Install it before getting started.

**Python versions supported:** 3.10, 3.11, 3.12, 3.13, 3.14

## Getting Started

1. **Fork and clone the repository:**

   ```bash
   git clone https://github.com/<your-username>/napalm.git
   cd napalm
   ```

2. **Install dependencies:**

   ```bash
   uv sync --all-groups
   ```

## Code Style & Linting

All code must pass the following checks before a pull request will be accepted. These run automatically in CI on every push and pull request.

### Ruff (linting)

```bash
uv run --no-project ruff check .
```

### Ruff (formatting)

```bash
uv run --no-project ruff format .
```

### Mypy (type checking)

```bash
uv run --no-project mypy --version
uv run --no-project mypy -p napalm --config-file mypy.ini
```

> **Note:** If you are on Python 3.13, set `MYPYC_OPT_LEVEL=0` to avoid a known symbol crash:
> ```bash
> MYPYC_OPT_LEVEL=0 uv run --no-project mypy -p napalm --config-file mypy.ini
> ```

## Running Tests

Tests are run with `pytest` and coverage reporting is enabled:

```bash
uv run pytest --cov=napalm --cov-report term-missing -vs
```

Tests are executed in CI against the following matrix:

| Platform     | Python versions              |
|--------------|------------------------------|
| Ubuntu 24.04 | 3.10, 3.11, 3.12, 3.13, 3.14 |
| macOS 15     | 3.12, 3.13, 3.14              |

## Documentation

Documentation doctests are run after the standard test suite passes:

```bash
uv run make doctest
```

## CI Pipeline Summary

The following jobs run automatically via GitHub Actions on every push and pull request:

| Job                | Description                                      |
|--------------------|--------------------------------------------------|
| `linters`          | Runs ruff (lint + format) and mypy               |
| `std_tests`        | Runs pytest on Ubuntu across all Python versions |
| `std_tests_macos`  | Runs pytest on macOS for Python 3.12–3.14        |
| `build_docs`       | Runs documentation doctests (requires std_tests) |

## Pull Request Checklist

Before submitting a pull request, please ensure:

- [ ] Code passes `ruff check` and `ruff format`
- [ ] Code passes `mypy` type checking
- [ ] All tests pass locally with `pytest`
- [ ] New functionality includes appropriate tests
- [ ] Documentation is updated if necessary

# Contributing to RepoGuard

Thank you for your interest in contributing to RepoGuard! 

---

## Code of Conduct

All contributors and participants agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/<your-username>/repoguard.git
   cd repoguard
   ```

2. Create and activate a virtual environment (Python 3.11+):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

3. Install RepoGuard and development dependencies in editable mode:
   ```bash
   pip install -e ".[dev]"
   pip install -e examples/custom_plugin
   ```

---

## Running Quality Checks

Before submitting a pull request, ensure tests and linting pass cleanly:

```bash
# Run automated tests
pytest -v

# Run Ruff linter and formatter
ruff check .
ruff format --check .
```

---

## Pull Request Guidelines

1. Create a descriptive feature branch (`git checkout -b feature/my-new-analyzer`).
2. Include comprehensive unit tests for any new features or bug fixes.
3. Keep commits atomic and use conventional commit messages (e.g., `feat:`, `fix:`, `docs:`).
4. Update relevant documentation in `docs/` or `README.md`.

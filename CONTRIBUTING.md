# Contributing to Warden

We welcome contributions! This guide will help you get started.

## How to Contribute

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/patpadgett/warden.git
   cd warden
   ```

3. **Create a virtual environment** and install development dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e '.[dev]'
   ```

4. **Make your changes**.  Follow the project's coding style:
   - Use `ruff` formatting (line length 100, `py311`).
   - Add type hints where appropriate.
   - Update or add unit tests under `tests/`.
   - Ensure `pytest` passes (`pytest -q`).
   - Verify coverage is tracked (`pytest --cov=warden`); current baseline ~78% (fail-under 75).
   - Note: docstrings are kept concise and single; `ConfigManager` duplicate was cleaned.

5. **Run the test suite**:

   ```bash
   pytest
   ```

6. **Commit your changes** with a clear commit message.

7. **Push to your fork** and open a Pull Request against `main`.

## Pull Request Checklist

- [ ] Code builds (`python -m build` succeeds).
- [ ] All tests pass (`pytest -q`).
- [ ] New code has test coverage.
- [ ] Documentation is updated (docstrings, README, etc.).
- [ ] Linting passes (`ruff check .`).

## Coding Style

- Follow the existing code style (see `.ruff` configuration).
- Use `black`/`ruff` formatting.  The project uses `ruff` as the primary formatter.
- Write docstrings in Google style.

## Versioning

Versions come from git tags via setuptools-scm; do not edit a version string in
`pyproject.toml`. To cut a release, tag `main` with `vX.Y.Z` and push the tag.

If you encounter a bug or have a feature request, please open an issue on GitHub with:
- A clear description.
- Steps to reproduce (if applicable).
- Expected vs. actual behavior.

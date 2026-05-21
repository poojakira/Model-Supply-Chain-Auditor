# Contributing

## Development Setup

```bash
git clone https://github.com/poojakira/Model-Supply-Chain-Auditor.git
cd Model-Supply-Chain-Auditor
pip install -e ".[dev]"
pytest
```

## Code Style

- **Linter/formatter:** ruff (configured in pyproject.toml)
- **Type hints:** Required on all public functions
- **Line length:** 100 characters
- **Docstrings:** Required on all public modules, classes, and functions

Run checks:
```bash
ruff check src/ tests/
ruff format --check src/ tests/
```

## Pull Request Process

1. Branch from `main`
2. Write tests for new functionality
3. Ensure all tests pass: `pytest`
4. Ensure coverage does not decrease
5. Follow conventional commit format for commit messages
6. Open PR with description of changes

## Adding Detection Rules

To add a new dangerous module or callable:

1. Edit `rules.yaml` — add to appropriate severity bucket
2. Add a test case in `tests/test_expanded_scanner.py` that creates a pickle using the pattern
3. Verify the test passes

## Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ONNX format scanning
fix: handle malformed ZIP with empty entries
test: add parametrized tests for BUILD opcode
docs: update threat model with CVE-2026-XXXXX
ci: add Python 3.13 to test matrix
chore: update cryptography dependency to 45.0
```

## Testing

```bash
pytest                          # Run all tests
pytest --cov=src               # With coverage
pytest tests/test_signing.py   # Single file
pytest -k "test_zip"           # By name pattern
```

## Reporting Issues

- **Bugs:** Open a GitHub issue with reproduction steps
- **Security vulnerabilities:** See SECURITY.md
- **Feature requests:** Open a GitHub issue with use case description

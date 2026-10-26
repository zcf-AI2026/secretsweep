# Contributing

Thanks for taking a look. Small, focused pull requests are easiest to review.

## Development setup

```bash
git clone https://github.com/zcf-AI2026/secretsweep.git
cd secretsweep
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check src tests
pytest
```

Both must be clean. CI runs them on Python 3.11, 3.12 and 3.13.

## Adding a rule

Rules live in `src/secretsweep/rules/default.toml`. A new built-in rule needs:

1. A unique `id` and a `placeholder` name (uppercase, no spaces).
2. A pattern written as a TOML **literal** string (`'''…'''`) so backslashes survive.
3. A test in `tests/test_engine.py` that both matches a positive sample and does **not**
   match at least one realistic negative.
4. A row in the README table.

Keep rules narrow. A pattern that fires on ordinary prose is worse than no pattern:
users will reach for the allow-list and stop trusting the tool.

## Code style

- Standard library only in `src/` — this package must stay dependency-free.
- Line length 100, enforced by ruff.
- Public functions get a one-line docstring explaining *why*, not just *what*.

## Commits and releases

- Present-tense subject lines ("add ipv6 rule", not "added").
- Update `CHANGELOG.md` under `[Unreleased]` in the same PR.
- Maintainers tag releases as `vX.Y.Z`; the tag message becomes the release note.

## Reporting a bug

Please include: the command you ran, the relevant part of the config, expected vs.
actual behavior, and the Python version.

**Never paste a real credential, real IP address or customer data into an issue.**
Reproduce with the documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)
or the files in `examples/`.

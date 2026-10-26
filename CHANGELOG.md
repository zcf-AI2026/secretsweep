# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-10-26

First public release.

### Added

- `scan` — read-only report of everything that would be redacted, with masked values
  (`203***42`) so scan output can be shared safely.
- `apply` — replaces matches with meaningful placeholders (`⟨PRIVATE_IP⟩`,
  `⟨DB_URL⟩`, …), numbered per distinct value (`⟨PRIVATE_IP_2⟩`), stable across files,
  and idempotent on re-runs.
- `restore` — puts the original values back from the mapping file.
- `check` — exits `1` when anything is found, for CI and pre-commit.
- `init` / `rules` — starter config and live rule listing.
- Built-in rules for private keys, GitHub tokens, `sk-` keys, AWS access keys, JWTs,
  database URLs, private/public IPv4, mainland China phone numbers, emails and
  `$HOME` paths.
- `secretsweep.toml`: override any built-in rule by id, add your own, allow values
  explicitly, and change the placeholder format.
- Text-only file walking with noise-directory skipping, `--exclude` globs, `--ext`
  additions and a `--max-size` guard.
- Pre-commit hook definition and GitHub Actions workflow.

### Notes

- Zero runtime dependencies; requires Python 3.11+.
- The mapping file (`secretsweep.map.json`) contains the original values, is written
  with mode `600`, and is ignored by the bundled `.gitignore`.

[Unreleased]: https://github.com/zcf-AI2026/secretsweep/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zcf-AI2026/secretsweep/releases/tag/v0.1.0

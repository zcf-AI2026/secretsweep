# secretsweep

**Find and redact secrets, private IPs and personal data before a note or repo goes public.**

[![CI](https://github.com/zcf-AI2026/secretsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/zcf-AI2026/secretsweep/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/secretsweep.svg)](https://pypi.org/project/secretsweep/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://pypi.org/project/secretsweep/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

You wrote a nice set of notes, or a repo you are about to open source — and somewhere
in there is your production IP, an API key you forgot about, a phone number, a home
directory path. `secretsweep` finds them, replaces them with readable placeholders
(`⟨PRIVATE_IP⟩`), and keeps a **private mapping file** so you can put the real values
back whenever you need to.

Zero dependencies. Python 3.11+. One file at a time, no daemon, no network.

---

## Why not just use a secret scanner?

Scanners tell you *"line 42 has something"*. That is the right answer for a codebase
you must not change. It is the wrong answer for a document you want to **publish** —
you need the text to still read well, and you need the original values to survive
somewhere private.

`secretsweep` is built for that second case:

| | Scanner (`gitleaks`, `detect-secrets`, …) | `secretsweep` |
|---|---|---|
| Goal | block a commit | **publish a readable copy** |
| Output | finding list | finding list **+ redacted text** |
| Reversible | no | **yes, via a local mapping file** |
| Placeholders | — | meaningful (`⟨PRIVATE_IP⟩`, `⟨DB_URL⟩`) |
| Runs on | code | code **and prose / notes / docs** |

## Install

```bash
pipx install secretsweep      # recommended: isolated CLI
# or
pip install secretsweep
# or, from a clone
pip install -e ".[dev]"
```

## Quickstart

```bash
secretsweep scan  ~/notes            # what would change? (read-only)
secretsweep apply ~/notes            # replace in place, write secretsweep.map.json
secretsweep restore ~/notes          # put the originals back
secretsweep check ~/notes            # exit 1 if anything is found — for CI
```

Real output:

```text
$ secretsweep scan examples/
RULE          LOCATION                 VALUE
------------  -----------------------  --------
ipv4_public   examples/demo-note.md:3  203***42
ipv4_public   examples/demo-note.md:3  198***.7
ipv4_private  examples/demo-note.md:3  10.***40
phone_cn      examples/demo-note.md:4  138***00
email         examples/demo-note.md:4  ops***om
github_token  examples/demo-note.md:5  ghp***00
db_url        examples/demo-note.md:6  pos***pp

7 finding(s) in 1 file(s): ipv4_public=2, ipv4_private=1, phone_cn=1, email=1, github_token=1, db_url=1
```

`apply` turns that into:

```diff
-Production host: 203.0.113.42, jump box 198.51.100.7, lab 10.20.30.40.
+Production host: ⟨PUBLIC_IP⟩, jump box ⟨PUBLIC_IP_2⟩, lab ⟨PRIVATE_IP⟩.
```

Values are masked in reports (`203***42`) so you can share a scan result safely.
Use `-f json` for machine-readable output.

## Built-in rules

| id | catches | placeholder |
|---|---|---|
| `private_key` | PEM / OpenSSH private key blocks | `⟨PRIVATE_KEY⟩` |
| `github_token` | `ghp_…`, `github_pat_…` | `⟨GITHUB_TOKEN⟩` |
| `openai_key` | `sk-…` style keys | `⟨API_KEY⟩` |
| `aws_access_key` | `AKIA…` | `⟨AWS_ACCESS_KEY⟩` |
| `jwt` | JSON Web Tokens | `⟨JWT⟩` |
| `db_url` | `postgres://`, `mysql://`, `redis://`, … | `⟨DB_URL⟩` |
| `ipv4_private` | RFC1918, CGNAT, link-local | `⟨PRIVATE_IP⟩` |
| `ipv4_public` | any other IPv4 | `⟨PUBLIC_IP⟩` |
| `phone_cn` | mainland China mobile numbers | `⟨PHONE⟩` |
| `email` | email addresses | `⟨EMAIL⟩` |
| `home_macos` / `home_linux` | `/Users/<name>`, `/home/<name>` | `⟨HOME_DIR⟩` |

`secretsweep rules` prints the live list.

## Configuration

Drop a `secretsweep.toml` next to your project (`secretsweep init` writes a starter):

```toml
[settings]
allow = ["example.com", "192.0.2.10"]        # exact values to ignore
placeholder_format = "⟨{name}⟩"              # or "<<{name}>>", "[{name}]", …

# Re-use a built-in id to override it…
[[rule]]
id = "ipv4_public"
pattern = '''\b(?:\d{1,3}\.){3}\d{1,3}\b'''
placeholder = "IP"
ignore_case = false

# …or add your own
[[rule]]
id = "internal_host"
pattern = '''\b[a-z0-9-]+\.corp\.example\b'''
placeholder = "INTERNAL_HOST"
description = "Internal hostname"
```

Then: `secretsweep scan ~/notes -c secretsweep.toml`

## Use it as a pre-commit hook

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/zcf-AI2026/secretsweep
    rev: v0.1.0
    hooks:
      - id: secretsweep
```

The hook runs `secretsweep check` and **fails the commit** when something looks
sensitive — no files are modified.

## Use it in CI

```yaml
- name: Ensure nothing sensitive ships
  run: |
    pipx install secretsweep
    secretsweep check . --exclude "tests/fixtures/*"
```

## How it works

1. Only text files with known extensions are touched; binaries, `.git`, `node_modules`
   and friends are skipped (change with `--ext`, `--exclude`).
2. All rules run, matches are de-overlapped (earliest wins, longest wins on a tie), so
   a connection string is redacted as one unit rather than mangled piece by piece.
3. Placeholders are assigned **in document order** — the first distinct value gets the
   bare name, the next `⟨PRIVATE_IP_2⟩`, and so on. The same value keeps the same
   placeholder across every file.
4. The value ↔ placeholder pairs go into `secretsweep.map.json` (mode `600`). That file
   is what makes `restore` possible — **it contains the originals, so keep it out of git**.
5. Re-running `apply` is a no-op: placeholders don't match the patterns.

## Safety notes

- **The mapping file is as sensitive as the data.** Add `secretsweep.map.json` to
  `.gitignore` (the bundled one does), keep it on your machine, delete it when done.
- Run `scan` first, or `apply --dry-run`, to see the blast radius.
- Redaction is textual and rule-based. It cannot know that "Project Falcon" is a
  codename — add your own rules for business-specific terms.
- Commit your work before sweeping. `git diff` is your undo button.

## Limitations / roadmap

- Regex only — no entropy heuristics or ML detection yet.
- Line-based context is not used for decisions.
- Planned: `--diff` mode (sweep only staged changes), YAML rule packs, `git filter-repo`
  helper for scrubbing history, IPv6, and a `--report html` output.

## Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Please never paste real credentials into an issue; use the sample values from
`examples/`.

## License

MIT — see [LICENSE](LICENSE).

"""The scan / redact / restore engine.

Everything here is pure standard library on purpose: the tool has to run on a
locked-down laptop with no virtualenv to spare.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .rules import Config, Rule

#: Files we are willing to touch. Anything else (images, archives, binaries) is
#: skipped — rewriting them would corrupt the file.
TEXT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".rst", ".org", ".tex",
    ".json", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".go", ".rs", ".java", ".kt", ".rb", ".php", ".cs", ".swift",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat",
    ".sql", ".csv", ".tsv", ".html", ".htm", ".css", ".scss", ".xml", ".log",
}

#: Directories that never contain source-of-truth text.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".next", ".turbo", "target", "vendor",
    ".obsidian", ".trash", ".idea", ".vscode",
}

DEFAULT_MAX_BYTES = 2 * 1024 * 1024


@dataclass
class Hit:
    """One match, positioned for a human to act on."""

    path: str
    line: int
    rule_id: str
    value: str

    def masked(self, keep: int = 3) -> str:
        """A short, non-reversible preview of the matched value."""
        if len(self.value) <= keep * 2:
            return self.value[:1] + "***"
        return f"{self.value[:keep]}***{self.value[-2:]}"


class PlaceholderMap:
    """Value -> placeholder, persisted so a later ``restore`` can reverse it."""

    def __init__(self, config: Config, entries: list[dict] | None = None) -> None:
        self.config = config
        self.entries: list[dict] = list(entries or [])
        self._by_key = {(e["rule"], e["value"]): e["placeholder"] for e in self.entries}
        self._used = {e["placeholder"] for e in self.entries}

    def get(self, rule_id: str, base_name: str, value: str) -> str:
        key = (rule_id, value)
        if key in self._by_key:
            return self._by_key[key]
        n = 1
        while True:
            candidate = self.config.render(base_name if n == 1 else f"{base_name}_{n}")
            if candidate not in self._used:
                break
            n += 1
        self._used.add(candidate)
        self._by_key[key] = candidate
        self.entries.append({"rule": rule_id, "value": value, "placeholder": candidate})
        return candidate

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "tool": "secretsweep",
            "version": 1,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "entries": self.entries,
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        try:
            os.chmod(path, 0o600)  # it holds the originals — keep it private
        except OSError:  # pragma: no cover - exotic filesystems
            pass

    @classmethod
    def load(cls, path: Path, config: Config) -> PlaceholderMap:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "entries" not in data:
            raise ValueError(f"{path} is not a secretsweep mapping file")
        return cls(config, data["entries"])


def read_text(path: Path) -> str:
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as fh:
        return fh.read()


def write_text(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as fh:
        fh.write(text)


def _is_excluded(path: str, patterns: Iterable[str]) -> bool:
    name = os.path.basename(path)
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(name, p) for p in patterns)


def iter_files(
    paths: Iterable[str],
    extensions: set[str] | None = None,
    excludes: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Iterator[Path]:
    """Yield the files worth reading, skipping binaries and noise directories."""
    exts = extensions or TEXT_EXTENSIONS
    patterns = list(excludes)
    for raw in paths:
        target = Path(raw)
        if target.is_file():
            yield target
            continue
        for root, dirs, files in os.walk(target):
            dirs[:] = sorted(
                d for d in dirs
                if d not in SKIP_DIRS and not _is_excluded(os.path.join(root, d), patterns)
            )
            for name in sorted(files):
                fp = Path(root) / name
                if fp.suffix.lower() not in exts:
                    continue
                if _is_excluded(str(fp), patterns):
                    continue
                try:
                    if fp.is_symlink() or fp.stat().st_size > max_bytes:
                        continue
                except OSError:
                    continue
                yield fp


class Sweeper:
    """Compiled rules + the matching logic shared by every mode."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._allow = set(config.allow)
        self._compiled: list[tuple[Rule, re.Pattern[str]]] = [
            (rule, re.compile(rule.pattern, re.IGNORECASE if rule.ignore_case else 0))
            for rule in config.rules
        ]

    def positions(self, text: str) -> list[tuple[int, int, Rule, str]]:
        """Non-overlapping matches, earliest first, longest wins on a tie."""
        found: list[tuple[int, int, Rule, str]] = []
        for rule, rx in self._compiled:
            for match in rx.finditer(text):
                value = match.group(0)
                if not value or value in self._allow:
                    continue
                found.append((match.start(), match.end(), rule, value))
        found.sort(key=lambda item: (item[0], -(item[1] - item[0])))
        chosen: list[tuple[int, int, Rule, str]] = []
        last_end = -1
        for start, end, rule, value in found:
            if start >= last_end:
                chosen.append((start, end, rule, value))
                last_end = end
        return chosen

    def scan_text(self, text: str, path: str = "<text>") -> list[Hit]:
        hits: list[Hit] = []
        for start, _end, rule, value in self.positions(text):
            hits.append(Hit(path=path, line=text.count("\n", 0, start) + 1,
                            rule_id=rule.id, value=value))
        return hits

    def redact_text(self, text: str, pmap: PlaceholderMap) -> tuple[str, int]:
        chosen = self.positions(text)
        # Numbering follows document order (first sighting gets the bare name),
        # so resolve placeholders before touching the text, then rewrite from
        # the end backwards to keep the offsets valid.
        planned = [
            (start, end, pmap.get(rule.id, rule.placeholder, value))
            for start, end, rule, value in chosen
        ]
        for start, end, placeholder in reversed(planned):
            text = text[:start] + placeholder + text[end:]
        return text, len(planned)


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------

def scan(
    paths: Iterable[str],
    sweeper: Sweeper,
    extensions: set[str] | None = None,
    excludes: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> list[Hit]:
    hits: list[Hit] = []
    for path in iter_files(paths, extensions, excludes, max_bytes):
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        hits.extend(sweeper.scan_text(text, str(path)))
    return hits


def redact(
    paths: Iterable[str],
    sweeper: Sweeper,
    pmap: PlaceholderMap,
    extensions: set[str] | None = None,
    excludes: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Replace matches in place. Returns ``(files_changed, replacements)``."""
    changed = replacements = 0
    for path in iter_files(paths, extensions, excludes, max_bytes):
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        new_text, count = sweeper.redact_text(text, pmap)
        if count == 0:
            continue
        changed += 1
        replacements += count
        if not dry_run:
            write_text(path, new_text)
    return changed, replacements


def restore(
    paths: Iterable[str],
    pmap: PlaceholderMap,
    extensions: set[str] | None = None,
    excludes: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Undo :func:`redact` using the same mapping file."""
    pairs = sorted(((e["placeholder"], e["value"]) for e in pmap.entries),
                   key=lambda kv: len(kv[0]), reverse=True)
    changed = replacements = 0
    if not pairs:
        return 0, 0
    for path in iter_files(paths, extensions, excludes, max_bytes):
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        count = 0
        for placeholder, value in pairs:
            n = text.count(placeholder)
            if n:
                text = text.replace(placeholder, value)
                count += n
        if count == 0:
            continue
        changed += 1
        replacements += count
        if not dry_run:
            write_text(path, text)
    return changed, replacements

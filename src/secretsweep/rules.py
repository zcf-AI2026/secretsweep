"""Rule loading: built-in rules plus user overrides from ``secretsweep.toml``.

A rule is deliberately dumb: a regular expression, a placeholder name, and a
one-line description. Everything smart lives in :mod:`secretsweep.engine`.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

BUILTIN_RULES = Path(__file__).with_name("rules") / "default.toml"

DEFAULT_PLACEHOLDER_FORMAT = "⟨{name}⟩"

ALLOWED_RULE_KEYS = {"id", "pattern", "placeholder", "description", "ignore_case"}


class ConfigError(Exception):
    """Raised when a config file cannot be understood."""


@dataclass(frozen=True)
class Rule:
    """One detection rule."""

    id: str
    pattern: str
    placeholder: str
    description: str = ""
    ignore_case: bool = False

    def describe(self) -> str:
        return self.description or self.id


@dataclass
class Config:
    """Everything needed to run: rules, allow-list, output formatting."""

    rules: list[Rule]
    allow: list[str]
    placeholder_format: str = DEFAULT_PLACEHOLDER_FORMAT

    def render(self, name: str) -> str:
        return self.placeholder_format.format(name=name)


def _rule_from(entry: dict, origin: str) -> Rule:
    unknown = set(entry) - ALLOWED_RULE_KEYS
    if unknown:
        raise ConfigError(f"{origin}: unknown key(s) in [[rule]]: {', '.join(sorted(unknown))}")
    missing = {"id", "pattern", "placeholder"} - set(entry)
    if missing:
        raise ConfigError(f"{origin}: [[rule]] is missing: {', '.join(sorted(missing))}")
    try:
        return Rule(
            id=str(entry["id"]),
            pattern=str(entry["pattern"]),
            placeholder=str(entry["placeholder"]),
            description=str(entry.get("description", "")),
            ignore_case=bool(entry.get("ignore_case", False)),
        )
    except KeyError as exc:  # pragma: no cover - guarded by the check above
        raise ConfigError(f"{origin}: bad rule entry ({exc})") from exc


def _read_ruleset(path: Path) -> tuple[list[Rule], dict]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"rules file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML ({exc})") from exc
    rules = [_rule_from(entry, str(path)) for entry in data.get("rule", [])]
    return rules, data.get("settings", {})


def load_config(config_path: Path | None = None) -> Config:
    """Load built-in rules and merge an optional user config on top.

    Matching on ``id`` replaces a built-in rule; a new ``id`` appends. That
    keeps user configs short: you only write the rules you want to change.
    """
    rules, settings = _read_ruleset(BUILTIN_RULES)
    allow = list(settings.get("allow", []))
    fmt = str(settings.get("placeholder_format", DEFAULT_PLACEHOLDER_FORMAT))

    if config_path is not None:
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"config file not found: {path}")
        user_rules, user_settings = _read_ruleset(path)
        allow.extend(str(v) for v in user_settings.get("allow", []))
        fmt = str(user_settings.get("placeholder_format", fmt))
        index = {rule.id: i for i, rule in enumerate(rules)}
        for rule in user_rules:
            if rule.id in index:
                rules[index[rule.id]] = rule
            else:
                index[rule.id] = len(rules)
                rules.append(rule)

    return Config(rules=rules, allow=allow, placeholder_format=fmt)


STARTER_CONFIG = """\
# secretsweep configuration — https://github.com/secretsweep/secretsweep
#
# Rules with an existing id override the built-in one; new ids are appended.
# Run `secretsweep rules` to list the built-ins.

[settings]
# Values listed here are never reported or replaced (exact string match).
allow = ["example.com", "192.0.2.10"]
# placeholder_format = "⟨{name}⟩"

# [[rule]]
# id = "internal_hostname"
# pattern = '''\\b[a-z0-9-]+\\.corp\\.example\\b'''
# placeholder = "INTERNAL_HOST"
# description = "Internal hostname"
"""


def write_starter_config(path: Path) -> None:
    path.write_text(STARTER_CONFIG, encoding="utf-8")

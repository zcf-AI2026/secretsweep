"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .engine import (
    DEFAULT_MAX_BYTES,
    PlaceholderMap,
    Sweeper,
    redact,
    restore,
    scan,
)
from .rules import ConfigError, load_config, write_starter_config


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="*", default=["."],
                        help="files or directories to inspect (default: .)")
    parser.add_argument("-c", "--config", type=Path, default=None,
                        help="extra rules / allow-list (secretsweep.toml)")
    parser.add_argument("-x", "--exclude", action="append", default=[], metavar="GLOB",
                        help="skip paths matching this glob (repeatable)")
    parser.add_argument("-e", "--ext", action="append", default=[], metavar=".EXT",
                        help="treat this extension as text (repeatable)")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_BYTES // 1024,
                        metavar="KB", help="skip files larger than this (default: 2048)")
    parser.add_argument("-f", "--format", choices=["table", "json"], default="table",
                        help="output format (default: table)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretsweep",
        description="Find and redact secrets or private addresses before a repo goes public.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_scan = sub.add_parser("scan", help="report what would be redacted (read-only)")
    _add_common(p_scan)

    p_check = sub.add_parser("check", help="like scan, but exit 1 when anything is found (CI)")
    _add_common(p_check)

    p_apply = sub.add_parser("apply", help="replace matches with placeholders, in place")
    _add_common(p_apply)
    p_apply.add_argument("-m", "--map", type=Path, default=Path("secretsweep.map.json"),
                         help="where to write the value mapping (default: secretsweep.map.json)")
    p_apply.add_argument("--dry-run", action="store_true", help="show what would change")

    p_restore = sub.add_parser("restore", help="put the original values back")
    _add_common(p_restore)
    p_restore.add_argument("-m", "--map", type=Path, default=Path("secretsweep.map.json"),
                           help="mapping file written by apply")
    p_restore.add_argument("--dry-run", action="store_true", help="show what would change")

    p_init = sub.add_parser("init", help="write a starter secretsweep.toml")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing file")

    p_rules = sub.add_parser("rules", help="list the active rules")
    p_rules.add_argument("-c", "--config", type=Path, default=None)
    p_rules.add_argument("-f", "--format", choices=["table", "json"], default="table")

    return parser


def _sweeper(args: argparse.Namespace) -> tuple[Sweeper, set[str] | None]:
    config = load_config(args.config)
    extensions = {e if e.startswith(".") else f".{e}" for e in args.ext} or None
    return Sweeper(config), extensions


def _print_table(hits) -> None:
    if not hits:
        return
    rows = [(h.rule_id, f"{h.path}:{h.line}", h.masked()) for h in hits]
    widths = [max(len(r[i]) for r in rows + [("RULE", "LOCATION", "VALUE")]) for i in range(3)]
    header = ("RULE", "LOCATION", "VALUE")
    print(f"{header[0]:<{widths[0]}}  {header[1]:<{widths[1]}}  {header[2]}")
    print(f"{'-' * widths[0]}  {'-' * widths[1]}  {'-' * widths[2]}")
    for rule, location, value in rows:
        print(f"{rule:<{widths[0]}}  {location:<{widths[1]}}  {value}")


def _emit(hits, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps([h.__dict__ for h in hits], ensure_ascii=False, indent=2))
        return
    _print_table(hits)


def _summary(hits) -> None:
    if not hits:
        print("No findings.")
        return
    by_rule: dict[str, int] = {}
    for hit in hits:
        by_rule[hit.rule_id] = by_rule.get(hit.rule_id, 0) + 1
    files = len({h.path for h in hits})
    detail = ", ".join(f"{k}={v}" for k, v in sorted(by_rule.items(), key=lambda kv: -kv[1]))
    print(f"\n{len(hits)} finding(s) in {files} file(s): {detail}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "init":
        target = Path("secretsweep.toml")
        if target.exists() and not args.force:
            print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
            return 2
        write_starter_config(target)
        print(f"wrote {target}")
        return 0

    if args.command == "rules":
        config = load_config(args.config)
        if args.format == "json":
            print(json.dumps([r.__dict__ for r in config.rules], ensure_ascii=False, indent=2))
            return 0
        for rule in config.rules:
            print(f"{rule.id:<16} {rule.placeholder:<16} {rule.describe()}")
        return 0

    try:
        sweeper, extensions = _sweeper(args)
    except ConfigError as exc:
        print(f"secretsweep: {exc}", file=sys.stderr)
        return 2

    max_bytes = max(1, args.max_size) * 1024
    excludes = list(args.exclude)
    map_path = getattr(args, "map", None)
    if map_path is not None:
        # The mapping file holds the originals — sweeping or restoring it would
        # corrupt the very thing we need for the reverse operation.
        excludes += [str(map_path), map_path.name]
    common = dict(extensions=extensions, excludes=excludes, max_bytes=max_bytes)

    if args.command in ("scan", "check"):
        hits = scan(args.paths or ["."], sweeper, **common)
        if args.command == "check":
            if hits:
                _emit(hits, "table")
                _summary(hits)
                print("\nFail: remove or allow these values before publishing.", file=sys.stderr)
                return 1
            print("Clean.")
            return 0
        _emit(hits, args.format)
        if args.format == "table":
            _summary(hits)
        return 0

    if args.command == "apply":
        pmap = PlaceholderMap.load(args.map, sweeper.config) if args.map.exists() else \
            PlaceholderMap(sweeper.config)
        changed, count = redact(args.paths or ["."], sweeper, pmap, dry_run=args.dry_run, **common)
        pmap.save(args.map)
        verb = "would replace" if args.dry_run else "replaced"
        print(f"{verb} {count} occurrence(s) in {changed} file(s); mapping: {args.map}")
        print("Keep that file private — it holds the original values.")
        return 0

    if args.command == "restore":
        if not args.map.exists():
            print(f"secretsweep: mapping file not found: {args.map}", file=sys.stderr)
            return 2
        pmap = PlaceholderMap.load(args.map, sweeper.config)
        changed, count = restore(args.paths or ["."], pmap, dry_run=args.dry_run, **common)
        verb = "would restore" if args.dry_run else "restored"
        print(f"{verb} {count} value(s) in {changed} file(s)")
        return 0

    return 2  # pragma: no cover - argparse rejects unknown commands


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

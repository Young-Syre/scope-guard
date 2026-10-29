"""The ``scope-guard`` command line.

Four commands:

``check``
    one target, one verdict, and the rule that decided it.
``batch``
    a list of targets in, a verdict per target out, for filtering a recon
    list before anything touches it.
``lint``
    static checks on the scope file itself.
``init``
    write a commented scope file to start from.

Exit codes are documented in :data:`USAGE_EXIT` and in the README; they are
the interface, so they do not change casually.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

from . import __version__
from .decide import IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, Decision, decide
from .errors import ScopeFileError, ScopeGuardError, TargetError
from .lint import DEFAULT_MAX_AGE_DAYS, lint_scope
from .scope import Scope, load_scope
from .targets import TARGET_KINDS, parse_target
from .templates import render_template

__all__ = ["main", "build_parser", "USAGE_EXIT"]

#: Exit code for a usage error, an unreadable scope file, or an unparseable
#: target. Kept distinct from the three verdict codes so that a broken
#: invocation can never be mistaken for an in-scope answer.
USAGE_EXIT = 3

#: Default scope file, overridable with --scope or SCOPE_GUARD_SCOPE.
DEFAULT_SCOPE_FILE = "scope.toml"
SCOPE_ENV_VAR = "SCOPE_GUARD_SCOPE"

_VERDICT_FILTERS = {
    "in": IN_SCOPE,
    "in-scope": IN_SCOPE,
    "out": OUT_OF_SCOPE,
    "out-of-scope": OUT_OF_SCOPE,
    "unknown": UNKNOWN,
}

_EPILOG = f"""exit codes:
  0  in-scope
  1  out-of-scope
  2  unknown (no entry decided it, or entries of equal weight disagreed)
  {USAGE_EXIT}  usage error, unreadable scope file, or unparseable target

scope-guard makes no network requests and touches no target. It decides from
the scope file you give it and nothing else.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scope-guard",
        description=(
            "Decide whether a target is in scope, mechanically and auditably, "
            "from a declarative scope file. Offline: no network requests, no "
            "DNS resolution, no contact with the target."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"scope-guard {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    check = subparsers.add_parser(
        "check",
        help="decide one target",
        description="Decide one target and name the rule that decided it.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check.add_argument("target", help="a host, URL, IP, android:pkg, ios:bundle or repo:url")
    _add_scope_argument(check)
    check.add_argument(
        "--type",
        dest="kind",
        choices=TARGET_KINDS,
        help="force how the target is interpreted instead of detecting it",
    )
    check.add_argument(
        "--explain",
        action="store_true",
        help="print the decision tree: every entry that matched, and why one won",
    )
    check.add_argument("--json", action="store_true", help="emit the decision as JSON")
    check.add_argument(
        "--quiet",
        action="store_true",
        help="print nothing; use the exit code alone",
    )
    check.set_defaults(handler=_cmd_check)

    batch = subparsers.add_parser(
        "batch",
        help="decide a list of targets",
        description=(
            "Decide a list of targets, one per line, from a file or stdin. "
            "Blank lines and lines starting with '#' are ignored."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    batch.add_argument(
        "targets",
        nargs="?",
        default="-",
        help="file of targets, or '-' for stdin (the default)",
    )
    _add_scope_argument(batch)
    batch.add_argument(
        "--type",
        dest="kind",
        choices=TARGET_KINDS,
        help="force how every target is interpreted",
    )
    batch.add_argument(
        "--format",
        choices=("csv", "json", "plain"),
        default="csv",
        help="csv (default), json, or plain for just the target strings",
    )
    batch.add_argument(
        "--only",
        metavar="VERDICTS",
        help=(
            "comma-separated verdicts to keep: in, out, unknown. "
            "'--only in --format plain' is the recon-pipeline filter"
        ),
    )
    batch.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write to FILE instead of stdout",
    )
    batch.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any target is not in-scope, for use as a CI gate",
    )
    batch.set_defaults(handler=_cmd_batch)

    lint = subparsers.add_parser(
        "lint",
        help="check the scope file for authoring mistakes",
        description=(
            "Run static checks on a scope file: overlapping entries, exclusions "
            "that can never fire, inclusions an exclusion has swallowed, missing "
            "apex domains, and a stale last_verified date."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lint.add_argument(
        "scope_file",
        nargs="?",
        help="the scope file to lint (defaults to --scope, $SCOPE_GUARD_SCOPE, ./scope.toml)",
    )
    _add_scope_argument(lint)
    lint.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        metavar="N",
        help=f"how old last_verified may be before SG006 fires (default {DEFAULT_MAX_AGE_DAYS})",
    )
    lint.add_argument("--json", action="store_true", help="emit findings as JSON")
    lint.add_argument(
        "--strict",
        action="store_true",
        help="fail on warnings as well as errors",
    )
    lint.set_defaults(handler=_cmd_lint)

    init = subparsers.add_parser(
        "init",
        help="write a commented example scope file",
        description="Write a commented scope file to start from.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_SCOPE_FILE,
        help=f"where to write it, or '-' for stdout (default {DEFAULT_SCOPE_FILE})",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing file",
    )
    init.set_defaults(handler=_cmd_init)

    return parser


def _add_scope_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scope",
        metavar="FILE",
        help=(
            f"the scope file (default: ${SCOPE_ENV_VAR}, else ./{DEFAULT_SCOPE_FILE})"
        ),
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the exit code rather than calling ``sys.exit``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "handler", None) is None:
        parser.print_help()
        return USAGE_EXIT
    try:
        return args.handler(args)
    except ScopeFileError as exc:
        print(f"scope-guard: scope file error: {exc}", file=sys.stderr)
        return USAGE_EXIT
    except TargetError as exc:
        print(f"scope-guard: {exc}", file=sys.stderr)
        return USAGE_EXIT
    except ScopeGuardError as exc:  # pragma: no cover - defensive
        print(f"scope-guard: {exc}", file=sys.stderr)
        return USAGE_EXIT
    except BrokenPipeError:  # pragma: no cover - `| head` in a pipeline
        return 0


# ----------------------------------------------------------------- scope files


def _resolve_scope_path(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "scope", None) or getattr(args, "scope_file", None)
    if getattr(args, "scope_file", None) and getattr(args, "scope", None):
        raise ScopeFileError(
            "give the scope file either positionally or with --scope, not both"
        )
    if explicit:
        return Path(explicit)
    from_env = os.environ.get(SCOPE_ENV_VAR)
    if from_env:
        return Path(from_env)
    default = Path(DEFAULT_SCOPE_FILE)
    if default.exists():
        return default
    raise ScopeFileError(
        f"no scope file given and ./{DEFAULT_SCOPE_FILE} does not exist; pass "
        f"--scope FILE or set ${SCOPE_ENV_VAR}. Run 'scope-guard init' to create one"
    )


def _load(args: argparse.Namespace) -> Scope:
    return load_scope(_resolve_scope_path(args))


# ----------------------------------------------------------------------- check


def _cmd_check(args: argparse.Namespace) -> int:
    scope = _load(args)
    target = parse_target(args.target, kind=args.kind)
    decision = decide(scope, target)

    if args.quiet:
        return decision.exit_code
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
        return decision.exit_code

    print(_render_decision(decision, explain=args.explain))
    return decision.exit_code


def _render_decision(decision: Decision, *, explain: bool) -> str:
    lines = [f"{decision.verdict.upper()}  {decision.target.raw}"]
    lines.append(f"  reason: {decision.reason}")
    for rule in decision.deciding:
        lines.append(f"  rule:   {rule.label}")
        lines.append(f"          normalised as {rule.describe_normalised()}")
        if rule.notes:
            lines.append(f"          note: {rule.notes}")
    if decision.max_severity:
        lines.append(f"  capped: max severity {decision.max_severity}")
    for note in decision.notes:
        lines.append(f"  note:   {note}")
    if explain:
        lines.append("  decision tree:")
        lines.extend(f"    {line}" for line in decision.trace)
        other = [rule for rule in decision.matched if rule not in decision.deciding]
        if other:
            lines.append("    entries that matched but did not decide:")
            lines.extend(f"      - {rule.label}" for rule in other)
    return "\n".join(lines)


# ----------------------------------------------------------------------- batch

_CSV_COLUMNS = (
    "target",
    "verdict",
    "exit_code",
    "deciding_rule",
    "rule_type",
    "rule_value",
    "max_severity",
    "reason",
)


def _cmd_batch(args: argparse.Namespace) -> int:
    scope = _load(args)
    wanted = _parse_only(args.only)

    rows: list[dict[str, object]] = []
    kept: list[str] = []
    payload: list[dict[str, object]] = []
    saw_non_in_scope = False

    for raw in _read_targets(args.targets):
        try:
            target = parse_target(raw, kind=args.kind)
        except TargetError as exc:
            row = {
                "target": raw,
                "verdict": "error",
                "exit_code": USAGE_EXIT,
                "deciding_rule": "",
                "rule_type": "",
                "rule_value": "",
                "max_severity": "",
                "reason": str(exc),
            }
            saw_non_in_scope = True
            if wanted is None:
                rows.append(row)
                payload.append(dict(row))
            continue

        decision = decide(scope, target)
        if decision.verdict != IN_SCOPE:
            saw_non_in_scope = True
        if wanted is not None and decision.verdict not in wanted:
            continue

        deciding = decision.deciding[0] if decision.deciding else None
        rows.append(
            {
                "target": raw,
                "verdict": decision.verdict,
                "exit_code": decision.exit_code,
                "deciding_rule": deciding.label if deciding else "",
                "rule_type": deciding.type if deciding else "",
                "rule_value": deciding.value if deciding else "",
                "max_severity": decision.max_severity or "",
                "reason": decision.reason,
            }
        )
        payload.append(decision.to_dict())
        kept.append(raw)

    stream = open(args.output, "w", encoding="utf-8", newline="") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        elif args.format == "plain":
            for line in kept:
                stream.write(f"{line}\n")
        else:
            writer = csv.DictWriter(stream, fieldnames=list(_CSV_COLUMNS))
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
    finally:
        if args.output:
            stream.close()

    if args.strict and saw_non_in_scope:
        return 1
    return 0


def _parse_only(value: str | None) -> set[str] | None:
    if not value:
        return None
    wanted: set[str] = set()
    for part in value.split(","):
        key = part.strip().lower()
        if not key:
            continue
        if key not in _VERDICT_FILTERS:
            raise ScopeFileError(
                f"--only: unknown verdict {part.strip()!r}; expected one or more of "
                "in, out, unknown"
            )
        wanted.add(_VERDICT_FILTERS[key])
    if not wanted:
        raise ScopeFileError("--only: no verdicts given")
    return wanted


def _read_targets(source: str) -> list[str]:
    if source == "-":
        text = sys.stdin.read()
    else:
        path = Path(source)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ScopeFileError(f"cannot read target list {path}: {exc.strerror}") from exc
    targets = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        targets.append(stripped)
    return targets


# ------------------------------------------------------------------------ lint


def _cmd_lint(args: argparse.Namespace) -> int:
    path = _resolve_scope_path(args)
    scope = load_scope(path)
    if args.max_age_days < 0:
        raise ScopeFileError("--max-age-days must not be negative")
    report = lint_scope(scope, max_age_days=args.max_age_days)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"{path}: {len(scope)} entries ({len(scope.in_scope)} in, {len(scope.out_of_scope)} out)")
        for finding in report.findings:
            print(finding.render())
        verdict = "clean" if not report.findings else "see findings above"
        print(
            f"{report.errors} error(s), {report.warnings} warning(s), "
            f"{report.infos} info -- {verdict}"
        )
    return 0 if report.ok(strict=args.strict) else 1


# ------------------------------------------------------------------------ init


def _cmd_init(args: argparse.Namespace) -> int:
    if args.path == "-":
        sys.stdout.write(render_template())
        return 0
    path = Path(args.path)
    if path.exists() and not args.force:
        raise ScopeFileError(f"{path} already exists; pass --force to overwrite it")
    try:
        path.write_text(render_template(path.name), encoding="utf-8")
    except OSError as exc:
        raise ScopeFileError(f"cannot write {path}: {exc.strerror}") from exc
    print(f"wrote {path}")
    print(f"next: edit it, then run 'scope-guard lint {path}'")
    return 0


def run() -> None:  # pragma: no cover - console_scripts shim
    sys.exit(main())

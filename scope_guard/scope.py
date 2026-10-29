"""Loading and validating a scope file.

The scope file is the authorisation record: it is what you believe you are
allowed to test, written down in a form a machine can check. Everything in
this module errs towards refusing to load a file it does not fully
understand, because a scope file that is quietly misread is worse than no
scope file at all.
"""

from __future__ import annotations

import datetime as _datetime
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ScopeFileError
from .rules import SIDE_IN, SIDE_OUT, Rule, build_rule

__all__ = ["Program", "RuleSettings", "Scope", "load_scope", "parse_scope", "UNLISTED_CHOICES"]

#: Legal values for ``[rules].unlisted_is``.
UNLISTED_CHOICES = ("out", "unknown")

_TOP_LEVEL_KEYS = {"program", "rules", "in_scope", "out_of_scope"}

_PROGRAM_ALIASES = {
    "policy-url": "policy_url",
    "last-verified": "last_verified",
    "last-verified-date": "last_verified",
    "last_verified_date": "last_verified",
}
_PROGRAM_KEYS = {"name", "platform", "policy_url", "last_verified", "notes"}


@dataclass(frozen=True)
class Program:
    """The ``[program]`` block: which programme this scope file describes."""

    name: str | None = None
    platform: str | None = None
    policy_url: str | None = None
    last_verified: _datetime.date | None = None
    notes: str | None = None

    def age_in_days(self, today: _datetime.date | None = None) -> int | None:
        """How long since the scope was last checked against the policy page."""
        if self.last_verified is None:
            return None
        reference = today or _datetime.date.today()
        return (reference - self.last_verified).days


@dataclass(frozen=True)
class RuleSettings:
    """The ``[rules]`` block: how the entries combine.

    ``exclusions_win``
        When true (the default, and the only safe default), a matching
        ``out_of_scope`` entry decides the verdict no matter how general it
        is. An exclusion is a prohibition, and a prohibition that can be
        outvoted by a more specific permission is not a prohibition.

    ``unlisted_is``
        What a target matching nothing means. ``"out"`` models a
        primacy-of-rules programme: if it is not listed, you may not touch
        it. ``"unknown"`` models a primacy-of-impact programme, where
        anything the organisation owns may be in scope and an unlisted asset
        is a question for the programme, not a yes and not a no.
    """

    exclusions_win: bool = True
    unlisted_is: str = "out"


@dataclass(frozen=True)
class Scope:
    """A fully parsed scope file."""

    program: Program
    settings: RuleSettings
    in_scope: tuple[Rule, ...] = ()
    out_of_scope: tuple[Rule, ...] = ()
    path: Path | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def all_rules(self) -> tuple[Rule, ...]:
        return self.in_scope + self.out_of_scope

    def __len__(self) -> int:
        return len(self.in_scope) + len(self.out_of_scope)


def load_scope(path: str | Path) -> Scope:
    """Read and parse a scope file from disk."""
    file_path = Path(path)
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise ScopeFileError(f"cannot read scope file {file_path}: {exc.strerror}") from exc
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ScopeFileError(f"{file_path} is not valid UTF-8: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ScopeFileError(f"{file_path} is not valid TOML: {exc}") from exc
    return _build(parsed, path=file_path)


def parse_scope(text: str, *, path: Path | None = None) -> Scope:
    """Parse a scope file already held in memory. Used by the tests."""
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ScopeFileError(f"not valid TOML: {exc}") from exc
    return _build(parsed, path=path)


def _build(parsed: dict[str, object], *, path: Path | None) -> Scope:
    unknown = set(parsed) - _TOP_LEVEL_KEYS
    if unknown:
        raise ScopeFileError(
            f"unknown top-level key(s) {', '.join(sorted(unknown))}; expected "
            f"{', '.join(sorted(_TOP_LEVEL_KEYS))}"
        )

    program = _build_program(parsed.get("program"))
    settings = _build_settings(parsed.get("rules"))

    in_scope = _build_side(parsed.get("in_scope"), SIDE_IN, path)
    out_of_scope = _build_side(parsed.get("out_of_scope"), SIDE_OUT, path)

    if not in_scope and not out_of_scope:
        raise ScopeFileError(
            "scope file declares no entries; at least one [[in_scope]] entry is "
            "needed for a verdict to mean anything"
        )

    return Scope(
        program=program,
        settings=settings,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        path=path,
    )


def _build_program(block: object) -> Program:
    if block is None:
        return Program()
    if not isinstance(block, dict):
        raise ScopeFileError("[program] must be a table")

    values: dict[str, object] = {}
    for key, value in block.items():
        canonical = _PROGRAM_ALIASES.get(key, key)
        if canonical not in _PROGRAM_KEYS:
            raise ScopeFileError(
                f"[program]: unknown key {key!r}; expected "
                f"{', '.join(sorted(_PROGRAM_KEYS))}"
            )
        if canonical in values:
            raise ScopeFileError(f"[program]: {canonical!r} given more than once")
        values[canonical] = value

    last_verified = _coerce_date(values.pop("last_verified", None))
    for key, value in values.items():
        if not isinstance(value, str):
            raise ScopeFileError(f"[program].{key} must be a string")
    return Program(last_verified=last_verified, **values)  # type: ignore[arg-type]


def _coerce_date(value: object) -> _datetime.date | None:
    """Accept a TOML date, a TOML datetime, or an ISO-8601 string."""
    if value is None:
        return None
    if isinstance(value, _datetime.datetime):
        return value.date()
    if isinstance(value, _datetime.date):
        return value
    if isinstance(value, str):
        try:
            return _datetime.date.fromisoformat(value.strip()[:10])
        except ValueError as exc:
            raise ScopeFileError(
                f"[program].last_verified {value!r} is not an ISO-8601 date "
                "(expected e.g. 2026-10-29)"
            ) from exc
    raise ScopeFileError("[program].last_verified must be a date or an ISO-8601 string")


def _build_settings(block: object) -> RuleSettings:
    if block is None:
        return RuleSettings()
    if not isinstance(block, dict):
        raise ScopeFileError("[rules] must be a table")
    unknown = set(block) - {"exclusions_win", "unlisted_is"}
    if unknown:
        raise ScopeFileError(
            f"[rules]: unknown key(s) {', '.join(sorted(unknown))}; expected "
            "exclusions_win, unlisted_is"
        )

    exclusions_win = block.get("exclusions_win", True)
    if not isinstance(exclusions_win, bool):
        raise ScopeFileError("[rules].exclusions_win must be true or false")

    unlisted_is = block.get("unlisted_is", "out")
    if not isinstance(unlisted_is, str) or unlisted_is.strip().lower() not in UNLISTED_CHOICES:
        raise ScopeFileError(
            f"[rules].unlisted_is must be one of {', '.join(UNLISTED_CHOICES)}"
        )
    return RuleSettings(
        exclusions_win=exclusions_win,
        unlisted_is=unlisted_is.strip().lower(),
    )


def _build_side(block: object, side: str, path: Path | None) -> tuple[Rule, ...]:
    table = "in_scope" if side == SIDE_IN else "out_of_scope"
    if block is None:
        return ()
    if not isinstance(block, list):
        raise ScopeFileError(f"[[{table}]] must be an array of tables")
    rules = []
    source = str(path) if path is not None else "<memory>"
    for index, entry in enumerate(block):
        if not isinstance(entry, dict):
            raise ScopeFileError(f"[[{table}]][{index}] must be a table")
        rules.append(build_rule(side=side, index=index, entry=entry, source=source))
    return tuple(rules)

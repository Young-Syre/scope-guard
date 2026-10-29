"""Static checks on a scope file.

``lint`` is the half of scope-guard that looks at your authorisation record
rather than at a target. A scope file can be perfectly valid TOML and still
not say what its author believed it said: a wildcard that quietly excludes
the apex, an exclusion that no inclusion can ever reach, an inclusion that an
exclusion has already swallowed, a date from four months ago.

Every check is listed in the README with the same identifier used here.
"""

from __future__ import annotations

import datetime as _datetime
from dataclasses import dataclass, field

from .rules import SIDE_IN, SIDE_OUT, Rule, intersects, subsumes, wildcard_matches
from .scope import Scope

__all__ = [
    "Finding",
    "LintReport",
    "lint_scope",
    "CHECKS",
    "ERROR",
    "WARNING",
    "INFO",
    "DEFAULT_MAX_AGE_DAYS",
]

ERROR = "error"
WARNING = "warning"
INFO = "info"

_SEVERITY_ORDER = {ERROR: 0, WARNING: 1, INFO: 2}

#: How old a ``last_verified`` date may be before SG006 fires.
DEFAULT_MAX_AGE_DAYS = 90

#: Every check, in the order the README documents them.
CHECKS: dict[str, str] = {
    "SG001": (
        "an entry is fully covered by another entry on the same side, or pins a "
        "scheme/port that the broader entry undercuts"
    ),
    "SG002": "an out_of_scope entry that no in_scope entry can ever reach",
    "SG003": (
        "a wildcard entry subsumes a sibling entry on the same side, or undercuts "
        "a scheme/port that sibling pins"
    ),
    "SG004": "a wildcard entry whose apex domain is not listed anywhere",
    "SG005": "an in_scope CIDR that contains a host listed out_of_scope",
    "SG006": "[program].last_verified is missing, stale, or in the future",
    "SG007": "the same entry is listed twice on the same side",
    "SG008": "the same entry is listed both in_scope and out_of_scope",
    "SG009": "[program] metadata needed to audit this file is missing",
    "SG010": "an in_scope entry that an out_of_scope entry has swallowed",
}


@dataclass(frozen=True)
class Finding:
    """One lint result."""

    check: str
    severity: str
    message: str
    rules: tuple[Rule, ...] = ()

    @property
    def description(self) -> str:
        return CHECKS[self.check]

    def to_dict(self) -> dict[str, object]:
        return {
            "check": self.check,
            "severity": self.severity,
            "description": self.description,
            "message": self.message,
            "entries": [rule.label for rule in self.rules],
        }

    def render(self) -> str:
        return f"{self.severity.upper():7} {self.check}  {self.message}"


@dataclass(frozen=True)
class LintReport:
    """The result of linting one scope file."""

    scope: Scope
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    max_age_days: int = DEFAULT_MAX_AGE_DAYS

    def count(self, severity: str) -> int:
        return sum(1 for finding in self.findings if finding.severity == severity)

    @property
    def errors(self) -> int:
        return self.count(ERROR)

    @property
    def warnings(self) -> int:
        return self.count(WARNING)

    @property
    def infos(self) -> int:
        return self.count(INFO)

    def ok(self, *, strict: bool = False) -> bool:
        """True when the file passes. ``strict`` also fails on warnings."""
        if self.errors:
            return False
        return not (strict and self.warnings)

    def to_dict(self) -> dict[str, object]:
        return {
            "scope_file": str(self.scope.path) if self.scope.path else None,
            "program": self.scope.program.name,
            "entries": len(self.scope),
            "max_age_days": self.max_age_days,
            "counts": {
                ERROR: self.errors,
                WARNING: self.warnings,
                INFO: self.infos,
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


def lint_scope(
    scope: Scope,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    today: _datetime.date | None = None,
) -> LintReport:
    """Run every check against ``scope``."""
    findings: list[Finding] = []
    findings += _check_program_metadata(scope)
    findings += _check_last_verified(scope, max_age_days, today)
    findings += _check_duplicates_and_contradictions(scope)
    findings += _check_same_side_subsumption(scope)
    findings += _check_missing_apex(scope)
    findings += _check_dead_exclusions(scope)
    findings += _check_cidr_contains_excluded(scope)
    findings += _check_unreachable_inclusions(scope)
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.check))
    return LintReport(scope=scope, findings=tuple(findings), max_age_days=max_age_days)


# ----------------------------------------------------------------- SG006/SG009


def _check_program_metadata(scope: Scope) -> list[Finding]:
    program = scope.program
    findings: list[Finding] = []
    missing_info = [
        name for name, value in (("name", program.name), ("platform", program.platform))
        if not value
    ]
    if missing_info:
        findings.append(
            Finding(
                "SG009",
                INFO,
                f"[program] is missing {', '.join(missing_info)}; a scope file "
                "without a programme name is hard to tell apart from another one",
            )
        )
    if not program.policy_url:
        findings.append(
            Finding(
                "SG009",
                WARNING,
                "[program].policy_url is not set; there is no recorded source for "
                "these entries, so nobody can re-verify them against the policy",
            )
        )
    return findings


def _check_last_verified(
    scope: Scope, max_age_days: int, today: _datetime.date | None
) -> list[Finding]:
    program = scope.program
    if program.last_verified is None:
        return [
            Finding(
                "SG006",
                WARNING,
                "[program].last_verified is not set, so staleness cannot be "
                "checked; scope changes without notice, and an unchecked scope "
                "file is a liability",
            )
        ]
    reference = today or _datetime.date.today()
    age = (reference - program.last_verified).days
    if age < 0:
        return [
            Finding(
                "SG006",
                ERROR,
                f"[program].last_verified is {program.last_verified.isoformat()}, "
                f"which is {-age} day(s) in the future",
            )
        ]
    if age > max_age_days:
        return [
            Finding(
                "SG006",
                WARNING,
                f"[program].last_verified is {program.last_verified.isoformat()}, "
                f"{age} days ago (limit {max_age_days}); re-read the policy page "
                "and update the date before relying on this file",
            )
        ]
    return []


# ----------------------------------------------------------------- SG007/SG008


def _check_duplicates_and_contradictions(scope: Scope) -> list[Finding]:
    findings: list[Finding] = []

    for side, rules in ((SIDE_IN, scope.in_scope), (SIDE_OUT, scope.out_of_scope)):
        seen: dict[tuple[str, str], Rule] = {}
        for rule in rules:
            key = (rule.type, rule.describe_normalised())
            first = seen.get(key)
            if first is None:
                seen[key] = rule
                continue
            findings.append(
                Finding(
                    "SG007",
                    WARNING,
                    f"{rule.label} repeats {first.label}; they normalise to the "
                    f"same entry ({rule.describe_normalised()})",
                    (first, rule),
                )
            )

    for in_rule in scope.in_scope:
        for out_rule in scope.out_of_scope:
            if in_rule.type != out_rule.type:
                continue
            if in_rule.describe_normalised() != out_rule.describe_normalised():
                continue
            findings.append(
                Finding(
                    "SG008",
                    ERROR,
                    f"{in_rule.label} and {out_rule.label} are the same entry on "
                    "both sides; the exclusion wins and the inclusion is dead "
                    "(delete whichever one you did not mean)",
                    (in_rule, out_rule),
                )
            )
    return findings


# ----------------------------------------------------------------- SG001/SG003


def _adds_information(rule: Rule) -> bool:
    """True when a redundant entry still carries something worth keeping."""
    return bool(rule.max_severity or rule.notes)


def _void_pins(outer: Rule, inner: Rule) -> tuple[str, ...]:
    """Scheme or port constraints on ``inner`` that ``outer`` renders useless.

    Writing ``https://app.example.com`` in scope next to ``*.example.com``
    reads like "https only". It is not: the wildcard covers that host on
    every scheme, so the https in the URL constrains nothing. This is a
    quiet way to believe you have authorisation narrower than you wrote,
    which is worth a warning rather than a shrug.
    """
    void: list[str] = []
    if inner.scheme is not None and outer.scheme is None:
        void.append(f"the {inner.scheme} scheme")
    if inner.port is not None and outer.port is None:
        void.append(f"port {inner.port}")
    return tuple(void)


def _join(parts: tuple[str, ...]) -> str:
    return parts[0] if len(parts) == 1 else " and ".join(parts)


def _check_same_side_subsumption(scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    for side, rules in ((SIDE_IN, scope.in_scope), (SIDE_OUT, scope.out_of_scope)):
        for outer in rules:
            for inner in rules:
                if outer is inner:
                    continue
                if not subsumes(outer, inner):
                    continue
                if subsumes(inner, outer) and outer.index > inner.index:
                    # Mutually subsuming entries are duplicates; SG007 has them.
                    continue
                if subsumes(inner, outer):
                    continue
                check = "SG003" if outer.type == "wildcard" else "SG001"
                void = _void_pins(outer, inner)
                if void:
                    findings.append(
                        Finding(
                            check,
                            WARNING,
                            f"{inner.label} pins {_join(void)}, but {outer.label} "
                            f"covers the same host without pinning "
                            f"{'it' if len(void) == 1 else 'them'}, so the pin "
                            "restricts nothing: the broader entry still decides "
                            "every other case. Narrow the broader entry, or drop "
                            "the pin and say what you mean with an out_of_scope "
                            "entry",
                            (outer, inner),
                        )
                    )
                    continue
                informative = _adds_information(inner)
                severity = INFO if informative else WARNING
                tail = (
                    "it is kept for its own max_severity/notes, which do apply "
                    "because it is the more specific entry"
                    if informative
                    else "it can be deleted without changing any verdict"
                )
                findings.append(
                    Finding(
                        check,
                        severity,
                        f"{inner.label} is already covered by {outer.label} "
                        f"({outer.describe_normalised()} covers "
                        f"{inner.describe_normalised()}); {tail}",
                        (outer, inner),
                    )
                )
    return findings


# ----------------------------------------------------------------------- SG004


def _check_missing_apex(scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    for rules in (scope.in_scope, scope.out_of_scope):
        for rule in rules:
            if rule.type != "wildcard":
                continue
            base = rule.wildcard_base or ""
            if _apex_is_addressed(scope, base, rule.side):
                continue
            side_word = "in scope" if rule.side == SIDE_IN else "out of scope"
            findings.append(
                Finding(
                    "SG004",
                    WARNING,
                    f"{rule.label} does not cover its own apex {base!r}: "
                    f"'*.{base}' matches subdomains only. If {base} is "
                    f"{side_word}, list it as a separate entry of "
                    f"type = \"domain\"",
                    (rule,),
                )
            )
    return findings


def _apex_is_addressed(scope: Scope, base: str, side: str) -> bool:
    """True when the apex of a wildcard has been dealt with deliberately.

    An exact ``domain`` entry for the apex counts on *either* side: listing
    ``*.example.com`` in scope and ``example.com`` out of scope is a coherent
    statement ("subdomains yes, the apex no"), not an oversight.

    A covering wildcard only counts on the *same* side. An out-of-scope
    ``*.sandbox.example.com`` is not made coherent by an in-scope
    ``*.example.com`` covering ``sandbox.example.com`` -- that combination is
    precisely the gap this check exists to find.
    """
    for rule in scope.all_rules:
        if rule.path is not None:
            continue
        if rule.is_exact_host and rule.host == base:
            return True
        if (
            rule.side == side
            and rule.is_wildcard_host
            and wildcard_matches(rule.wildcard_base or "", base)
        ):
            return True
    return False


# ----------------------------------------------------------------------- SG002


def _check_dead_exclusions(scope: Scope) -> list[Finding]:
    """An exclusion nothing can reach.

    This only fires when ``unlisted_is = "out"``. Under
    ``unlisted_is = "unknown"`` a non-intersecting exclusion is not dead at
    all: it is the thing that turns an ``unknown`` into a definite
    ``out-of-scope``, which is exactly what you want on a primacy-of-impact
    programme.
    """
    if scope.settings.unlisted_is != "out":
        return []

    findings: list[Finding] = []
    for out_rule in scope.out_of_scope:
        if any(intersects(out_rule, in_rule) for in_rule in scope.in_scope):
            continue
        comparable = [
            in_rule
            for in_rule in scope.in_scope
            if in_rule.resolution_group == out_rule.resolution_group
        ]
        if comparable:
            severity = WARNING
            detail = (
                "no in_scope entry overlaps it, so every target it would catch is "
                "already out of scope by default"
            )
        else:
            severity = INFO
            detail = (
                "nothing in_scope is of a comparable kind, so it can never fire; "
                "harmless if it is there to document a boundary, but it is not "
                "enforcing anything"
            )
        if out_rule.resolution_group == "address" and not comparable:
            detail += (
                ". Note that address entries and hostname entries never overlap "
                "here, because scope-guard does not resolve names"
            )
        findings.append(
            Finding("SG002", severity, f"{out_rule.label} can never fire: {detail}", (out_rule,))
        )
    return findings


# ----------------------------------------------------------------------- SG005


def _check_cidr_contains_excluded(scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    for in_rule in scope.in_scope:
        if in_rule.type != "cidr":
            continue
        for out_rule in scope.out_of_scope:
            if out_rule.type not in ("ip", "cidr"):
                continue
            if not subsumes(in_rule, out_rule):
                continue
            if scope.settings.exclusions_win:
                findings.append(
                    Finding(
                        "SG005",
                        INFO,
                        f"{in_rule.label} contains {out_rule.label}; the exclusion "
                        "wins because exclusions_win is true, so the carve-out "
                        "works as written",
                        (in_rule, out_rule),
                    )
                )
                continue
            if out_rule.specificity() > in_rule.specificity():
                findings.append(
                    Finding(
                        "SG005",
                        INFO,
                        f"{in_rule.label} contains {out_rule.label}; with "
                        "exclusions_win = false the exclusion still wins here "
                        "because it is the more specific entry",
                        (in_rule, out_rule),
                    )
                )
            else:
                findings.append(
                    Finding(
                        "SG005",
                        WARNING,
                        f"{in_rule.label} contains {out_rule.label}, but "
                        "exclusions_win = false and the inclusion is at least as "
                        "specific, so the carve-out loses and those addresses "
                        "come back in scope. Set exclusions_win = true",
                        (in_rule, out_rule),
                    )
                )
    return findings


# ----------------------------------------------------------------------- SG010


def _check_unreachable_inclusions(scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    for in_rule in scope.in_scope:
        for out_rule in scope.out_of_scope:
            if not subsumes(out_rule, in_rule):
                continue
            if (
                in_rule.type == out_rule.type
                and in_rule.describe_normalised() == out_rule.describe_normalised()
            ):
                # An identical entry on both sides; SG008 already reports it.
                continue
            if scope.settings.exclusions_win:
                findings.append(
                    Finding(
                        "SG010",
                        ERROR,
                        f"{in_rule.label} is entirely inside {out_rule.label} "
                        f"({out_rule.describe_normalised()} covers "
                        f"{in_rule.describe_normalised()}); with exclusions_win = "
                        "true it can never return in-scope. Narrow the exclusion "
                        "or drop the inclusion",
                        (out_rule, in_rule),
                    )
                )
            elif out_rule.specificity() >= in_rule.specificity():
                findings.append(
                    Finding(
                        "SG010",
                        WARNING,
                        f"{in_rule.label} is entirely inside {out_rule.label} and "
                        "the exclusion is at least as specific, so the inclusion "
                        "can never return in-scope",
                        (out_rule, in_rule),
                    )
                )
    return findings

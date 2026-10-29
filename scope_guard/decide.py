"""The decision: in-scope, out-of-scope, or unknown -- and which rule said so.

Precedence, in the order it is applied:

1. **Nothing matched.** The verdict comes from ``[rules].unlisted_is``:
   ``out`` for a primacy-of-rules programme, ``unknown`` for a
   primacy-of-impact one.
2. **An exclusion matched, and ``exclusions_win`` is true** (the default).
   Out of scope. The most specific matching exclusion is named. Specificity
   does not rescue an inclusion here, by design.
3. **Otherwise the most specific match wins.** Specificity is host precision
   first, then path depth, then how many of scheme and port are pinned.
4. **Equal specificity, opposite verdicts.** ``unknown``, with both entries
   named. The tool does not guess; that is the question to put to the
   programme.

Nothing in this path performs I/O other than having read the scope file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .rules import SIDE_IN, SIDE_OUT, Rule, host_only_rule, intersects
from .scope import Scope
from .targets import Target

__all__ = [
    "Decision",
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "UNKNOWN",
    "EXIT_CODES",
    "decide",
]

IN_SCOPE = "in-scope"
OUT_OF_SCOPE = "out-of-scope"
UNKNOWN = "unknown"

#: The process exit code for each verdict.
EXIT_CODES = {IN_SCOPE: 0, OUT_OF_SCOPE: 1, UNKNOWN: 2}


@dataclass(frozen=True)
class Decision:
    """A verdict, the rule that produced it, and how it was reached."""

    target: Target
    verdict: str
    reason: str
    deciding: tuple[Rule, ...] = ()
    matched: tuple[Rule, ...] = ()
    max_severity: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)
    trace: tuple[str, ...] = field(default_factory=tuple)

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.verdict]

    @property
    def allowed(self) -> bool:
        """True only for an in-scope verdict. ``unknown`` is not permission."""
        return self.verdict == IN_SCOPE

    def to_dict(self) -> dict[str, object]:
        """A JSON-ready view of the decision."""
        return {
            "target": self.target.raw,
            "normalised_target": self.target.describe(),
            "target_kind": self.target.kind,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "reason": self.reason,
            "max_severity": self.max_severity,
            "deciding_rules": [_rule_dict(rule) for rule in self.deciding],
            "matched_rules": [_rule_dict(rule) for rule in self.matched],
            "notes": list(self.notes),
            "trace": list(self.trace),
        }


def _rule_dict(rule: Rule) -> dict[str, object]:
    return {
        "side": "in_scope" if rule.side == SIDE_IN else "out_of_scope",
        "index": rule.index,
        "type": rule.type,
        "value": rule.value,
        "normalised": rule.describe_normalised(),
        "specificity": list(rule.specificity()),
        "max_severity": rule.max_severity,
        "notes": rule.notes,
    }


def decide(scope: Scope, target: Target) -> Decision:
    """Return the scope verdict for ``target`` under ``scope``."""
    trace: list[str] = [
        f"target: {target.raw}",
        f"normalised: {target.describe()}  (kind: {target.kind})",
        (
            f"settings: exclusions_win={str(scope.settings.exclusions_win).lower()}, "
            f"unlisted_is={scope.settings.unlisted_is}"
        ),
    ]

    matched = tuple(rule for rule in scope.all_rules if rule.matches(target))
    notes = list(target.notes) + _unevaluated_notes(scope, target, matched)

    if matched:
        trace.append(f"matched {len(matched)} entr{'y' if len(matched) == 1 else 'ies'}:")
        for rule in sorted(matched, key=lambda r: r.specificity(), reverse=True):
            trace.append(
                f"  - {rule.label} -> {rule.describe_normalised()} "
                f"[specificity {rule.specificity()}]"
            )
    else:
        trace.append("matched 0 entries")

    if not matched:
        return _unmatched(scope, target, trace, notes)

    exclusions = tuple(rule for rule in matched if rule.side == SIDE_OUT)
    if scope.settings.exclusions_win and exclusions:
        deciding = _most_specific(exclusions)
        trace.append(
            "exclusions_win is true and at least one out_of_scope entry matched, "
            "so the exclusion decides regardless of specificity"
        )
        return Decision(
            target=target,
            verdict=OUT_OF_SCOPE,
            reason=_reason("excluded by", deciding),
            deciding=deciding,
            matched=matched,
            notes=tuple(notes),
            trace=tuple(trace),
        )

    best = max(rule.specificity() for rule in matched)
    top = tuple(rule for rule in matched if rule.specificity() == best)
    trace.append(f"most specific matching entries have specificity {best}")
    sides = {rule.side for rule in top}

    if len(sides) == 1:
        side = next(iter(sides))
        if side == SIDE_IN:
            # An in-scope verdict has to rest on something the target actually
            # said. If every matching inclusion pinned a scheme or a port that
            # the target left out, the entry was matched by relaxing its own
            # constraint, and calling that authorised is the one mistake this
            # tool exists to prevent.
            inclusions = tuple(rule for rule in matched if rule.side == SIDE_IN)
            unrelaxed = tuple(
                rule for rule in inclusions if not rule.relaxed_for(target)
            )
            if unrelaxed and not any(rule in unrelaxed for rule in top):
                # The most specific inclusions were all matched by relaxation,
                # but a broader one covers the target as written. That broader
                # entry is what authorises it, so it is what gets named -- and
                # its severity ceiling is the one that applies, because a cap
                # cannot be inherited from an entry that does not authorise.
                deciding = _most_specific(unrelaxed)
                trace.append(
                    "the most specific inclusions were matched by relaxing a "
                    "constraint the target did not state; the verdict falls to "
                    "the most specific inclusion that covers it as written"
                )
                return Decision(
                    target=target,
                    verdict=IN_SCOPE,
                    reason=_reason("included by", deciding),
                    deciding=deciding,
                    matched=matched,
                    max_severity=_tightest_severity(deciding),
                    notes=tuple(notes),
                    trace=tuple(trace),
                )
            if not unrelaxed:
                seen = {
                    constraint
                    for rule in inclusions
                    for constraint in rule.relaxed_for(target)
                }
                # URL order, not alphabetical: "a scheme and port" reads.
                relaxed = [name for name in ("scheme", "port") if name in seen]
                joined = " and ".join(relaxed)
                trace.append(
                    f"every matching inclusion pinned a {joined} the target did "
                    "not supply, so no entry authorises it as written"
                )
                return Decision(
                    target=target,
                    verdict=UNKNOWN,
                    reason=(
                        f"every matching in_scope entry pins a {joined} that the "
                        "target does not state, so the match rests on relaxing "
                        f"the entry's own constraint: "
                        + "; ".join(rule.label for rule in top)
                        + f". Re-check with an explicit {joined}."
                    ),
                    deciding=top,
                    matched=matched,
                    notes=tuple(notes),
                    trace=tuple(trace),
                )
            severity = _tightest_severity(top)
            return Decision(
                target=target,
                verdict=IN_SCOPE,
                reason=_reason("included by", top),
                deciding=top,
                matched=matched,
                max_severity=severity,
                notes=tuple(notes),
                trace=tuple(trace),
            )
        return Decision(
            target=target,
            verdict=OUT_OF_SCOPE,
            reason=_reason("excluded by", top),
            deciding=top,
            matched=matched,
            notes=tuple(notes),
            trace=tuple(trace),
        )

    trace.append(
        "entries of equal specificity disagree and exclusions_win is false, "
        "so no verdict can be derived"
    )
    return Decision(
        target=target,
        verdict=UNKNOWN,
        reason=(
            "entries of equal specificity disagree: "
            + "; ".join(rule.label for rule in top)
        ),
        deciding=top,
        matched=matched,
        notes=tuple(notes),
        trace=tuple(trace),
    )


def _unmatched(
    scope: Scope, target: Target, trace: list[str], notes: list[str]
) -> Decision:
    if scope.settings.unlisted_is == "out":
        trace.append("unlisted_is = \"out\": an unlisted target is out of scope")
        return Decision(
            target=target,
            verdict=OUT_OF_SCOPE,
            reason=(
                "no entry matched, and unlisted_is = \"out\" (primacy of rules): "
                "anything not listed is out of scope"
            ),
            matched=(),
            notes=tuple(notes),
            trace=tuple(trace),
        )
    trace.append("unlisted_is = \"unknown\": an unlisted target needs a human decision")
    return Decision(
        target=target,
        verdict=UNKNOWN,
        reason=(
            "no entry matched, and unlisted_is = \"unknown\" (primacy of impact): "
            "ask the programme before testing"
        ),
        matched=(),
        notes=tuple(notes),
        trace=tuple(trace),
    )


def _most_specific(rules: tuple[Rule, ...]) -> tuple[Rule, ...]:
    best = max(rule.specificity() for rule in rules)
    return tuple(rule for rule in rules if rule.specificity() == best)


def _reason(verb: str, rules: tuple[Rule, ...]) -> str:
    return f"{verb} " + "; ".join(rule.label for rule in rules)


def _tightest_severity(rules: tuple[Rule, ...]) -> str | None:
    """Report a severity cap when the deciding in-scope entries carry one.

    With several deciding entries, the lowest cap is reported, because the
    tightest stated limit is the one you have to respect. Entries without a
    cap are not treated as uncapped overrides of entries with one.
    """
    severities = [rule.max_severity for rule in rules if rule.max_severity]
    if not severities:
        return None
    order = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    return min(severities, key=lambda s: (order.get(s.strip().lower(), 99), s))


def _unevaluated_notes(scope: Scope, target: Target, matched: tuple[Rule, ...]) -> list[str]:
    """Say plainly which entries could not be considered, and why.

    These are the honest edges of an offline check. A verdict that silently
    ignored half the scope file would be worse than no verdict.
    """
    notes: list[str] = []

    if target.kind == "host" and not matched:
        # Only worth saying when nothing matched: if a hostname entry already
        # decided the target, the address entries were never going to be
        # relevant and the note would be noise on every single check.
        address_rules = [rule for rule in scope.all_rules if rule.type in ("ip", "cidr")]
        if address_rules:
            count = len(address_rules)
            notes.append(
                f"{count} address-based entr{'y' if count == 1 else 'ies'} (ip/cidr) "
                f"{'was' if count == 1 else 'were'} not evaluated: the target is a "
                "hostname, and scope-guard performs no DNS resolution. Resolve it "
                "yourself and re-check the address if an address range matters here."
            )

    if target.path is None:
        host_only = host_only_rule(target)
        relevant = [
            rule
            for rule in scope.all_rules
            if rule.constrains_path() and intersects(rule, host_only)
        ]
        if relevant:
            count = len(relevant)
            notes.append(
                f"{count} path-scoped entr{'y' if count == 1 else 'ies'} for this "
                f"host {'was' if count == 1 else 'were'} not evaluated: the target "
                "has no path component. The verdict is for the host, not for every "
                "path on it."
            )

    if target.scheme is None:
        scheme_rules = [rule for rule in matched if rule.scheme is not None]
        if scheme_rules:
            notes.append(
                "the target was given without a scheme, so scheme-constrained "
                "entries were matched as if any scheme were acceptable"
            )

    if target.effective_port is None:
        port_rules = [rule for rule in matched if rule.port is not None]
        if port_rules:
            notes.append(
                "the target was given without a port, and without a scheme to "
                "imply one, so port-constrained entries were matched as if any "
                "port were acceptable"
            )

    return notes

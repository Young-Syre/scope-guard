"""scope-guard: an offline, auditable in-scope / out-of-scope decision.

Given a declarative scope file and a target, scope-guard answers in-scope,
out-of-scope or unknown, and names the exact entry that decided it.

It makes no network requests. It does not resolve DNS, fetch a policy page,
or contact the target in any way. Every verdict comes from the scope file you
wrote and nothing else -- which is what makes the verdict something you can
show to someone afterwards.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "David Nichols"
__license__ = "MIT"

from .decide import IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, Decision, decide
from .errors import ScopeFileError, ScopeGuardError, TargetError
from .lint import Finding, LintReport, lint_scope
from .rules import Rule
from .scope import Program, RuleSettings, Scope, load_scope, parse_scope
from .targets import Target, parse_target

__all__ = [
    "__version__",
    "Decision",
    "Finding",
    "LintReport",
    "Program",
    "Rule",
    "RuleSettings",
    "Scope",
    "ScopeFileError",
    "ScopeGuardError",
    "Target",
    "TargetError",
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "UNKNOWN",
    "decide",
    "lint_scope",
    "load_scope",
    "parse_scope",
    "parse_target",
]

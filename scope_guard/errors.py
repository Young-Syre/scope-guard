"""Exceptions raised by scope-guard."""

from __future__ import annotations


class ScopeGuardError(Exception):
    """Base class for every error scope-guard raises deliberately."""


class ScopeFileError(ScopeGuardError):
    """The scope file is missing, unreadable, or structurally invalid.

    Raised for problems that make the file unsafe to act on: an unknown entry
    ``type``, a wildcard written in an unsupported form, a malformed CIDR, and
    so on. scope-guard never guesses past one of these, because a scope file
    that does not mean what its author thinks it means is the failure mode the
    tool exists to prevent.
    """


class TargetError(ScopeGuardError):
    """The target could not be parsed into something that can be matched."""

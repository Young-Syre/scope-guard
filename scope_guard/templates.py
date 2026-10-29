"""The commented scope file that ``scope-guard init`` writes."""

from __future__ import annotations

import datetime as _datetime

__all__ = ["render_template"]

_TEMPLATE = '''# scope-guard scope file
#
# This file is an authorisation record. It is your written answer to the
# question "what am I allowed to touch?", in a form a machine can check.
# Transcribe it from the programme's policy page by hand, and update
# last_verified every time you re-read that page.
#
# Verify with:  scope-guard lint {filename}
# Check one target:  scope-guard check https://api.example.com/v1 --scope {filename} --explain

[program]
name = "Example Programme"
platform = "self-hosted"            # hackerone / bugcrowd / intigriti / self-hosted / ...
policy_url = "https://example.com/.well-known/security.txt"
last_verified = {today}            # the day you last read the policy page yourself

[rules]
# An exclusion must always beat an inclusion. Leave this true unless you have
# a specific reason and have read the matching-semantics section of the README.
exclusions_win = true

# What a target that matches nothing means.
#   "out"     - primacy of rules: if it is not listed, it is not in scope.
#   "unknown" - primacy of impact: anything the organisation owns may count,
#               so an unlisted asset is a question for the programme.
unlisted_is = "out"

# ---------------------------------------------------------------------------
# In scope
# ---------------------------------------------------------------------------
# Entry types: domain | wildcard | ip | cidr | url | path
#              android-package | ios-bundle | repo
#
# Note the asymmetry that catches people out: "*.example.com" matches
# a.example.com and a.b.example.com but NOT the apex example.com. If the apex
# is in scope, list it separately -- as it is here.

[[in_scope]]
type = "wildcard"
value = "*.example.com"
notes = "Main production estate."

[[in_scope]]
type = "domain"
value = "example.com"
notes = "The apex is not covered by the wildcard above; it needs its own entry."

[[in_scope]]
type = "path"
value = "api.example.com/v1"
max_severity = "high"
notes = "A prefix match on whole segments: /v1 covers /v1/users but not /v1foo."
# Use type = "url" instead when you need to pin a scheme or a port. Note that
# pinning only restricts anything if no broader entry also covers the host --
# "https://api.example.com" next to "*.example.com" restricts nothing, and
# lint will tell you so. To mean "https only", exclude the other scheme.

[[in_scope]]
type = "cidr"
value = "198.51.100.0/24"
notes = "Published netblock. A hostname target is never resolved to an address, so this entry only decides IP targets."

# ---------------------------------------------------------------------------
# Out of scope
# ---------------------------------------------------------------------------
# Exclusions beat inclusions while exclusions_win = true, however general the
# exclusion and however specific the inclusion.

[[out_of_scope]]
type = "wildcard"
value = "*.staging.example.com"
notes = "Shared pre-production; no authorisation to test."

[[out_of_scope]]
type = "domain"
value = "staging.example.com"
notes = "The apex of the excluded wildcard needs its own entry too."

[[out_of_scope]]
type = "path"
value = "example.com/admin"
notes = "Resolved and decoded before matching, so /api/../admin is caught."

[[out_of_scope]]
type = "ip"
value = "198.51.100.1"
notes = "Shared gateway inside the in-scope netblock."
'''


def render_template(filename: str = "scope.toml", today: _datetime.date | None = None) -> str:
    """Render the scaffold, dated today."""
    stamp = (today or _datetime.date.today()).isoformat()
    return _TEMPLATE.format(filename=filename, today=stamp)

"""Shared fixtures for the test suite."""

from __future__ import annotations

import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = PROJECT_ROOT / "examples"

#: Pinned so that tests of the SG006 staleness check never depend on the day
#: they are run. The two realistic example scope files carry this date.
TODAY = datetime.date(2026, 10, 29)

#: A valid [program] block, so that tests of entries and precedence are not
#: cluttered by SG006/SG009 metadata findings.
HEADER = """
[program]
name = "Test Programme"
platform = "self-hosted"
policy_url = "https://example.com/policy"
last_verified = 2026-10-29
"""

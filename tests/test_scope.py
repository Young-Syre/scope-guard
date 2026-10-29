"""Scope-file loading: what is accepted, and what is refused outright.

scope-guard refuses to load a file it does not fully understand. A silently
misread scope file would give confident, wrong answers, which is worse than
no answer at all.
"""

from __future__ import annotations

import datetime
import tempfile
import unittest
from pathlib import Path

from scope_guard.errors import ScopeFileError
from scope_guard.scope import load_scope, parse_scope

from .helpers import EXAMPLES, HEADER, TODAY

MINIMAL = HEADER + '\n[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'


class TestProgramBlock(unittest.TestCase):
    def test_metadata_is_read(self):
        scope = parse_scope(MINIMAL)
        self.assertEqual(scope.program.name, "Test Programme")
        self.assertEqual(scope.program.platform, "self-hosted")
        self.assertEqual(scope.program.policy_url, "https://example.com/policy")
        self.assertEqual(scope.program.last_verified, datetime.date(2026, 10, 29))

    def test_hyphenated_keys_are_accepted(self):
        scope = parse_scope(
            '[program]\npolicy-url = "https://x.example/p"\nlast-verified = 2026-01-02\n'
            '\n[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'
        )
        self.assertEqual(scope.program.policy_url, "https://x.example/p")
        self.assertEqual(scope.program.last_verified, datetime.date(2026, 1, 2))

    def test_iso_string_date_is_accepted(self):
        scope = parse_scope(
            '[program]\nlast_verified = "2026-03-04"\n'
            '\n[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'
        )
        self.assertEqual(scope.program.last_verified, datetime.date(2026, 3, 4))

    def test_nonsense_date_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(
                '[program]\nlast_verified = "last tuesday"\n'
                '\n[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'
            )

    def test_age_in_days(self):
        scope = parse_scope(MINIMAL)
        self.assertEqual(scope.program.age_in_days(TODAY), 0)
        self.assertEqual(scope.program.age_in_days(TODAY + datetime.timedelta(days=10)), 10)

    def test_unknown_program_key_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(
                '[program]\nowner = "someone"\n'
                '\n[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'
            )


class TestRulesBlock(unittest.TestCase):
    def test_defaults_are_the_safe_ones(self):
        scope = parse_scope(MINIMAL)
        self.assertTrue(scope.settings.exclusions_win)
        self.assertEqual(scope.settings.unlisted_is, "out")

    def test_settings_are_read(self):
        scope = parse_scope(
            MINIMAL + '\n[rules]\nexclusions_win = false\nunlisted_is = "unknown"\n'
        )
        self.assertFalse(scope.settings.exclusions_win)
        self.assertEqual(scope.settings.unlisted_is, "unknown")

    def test_bad_unlisted_is_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(MINIMAL + '\n[rules]\nunlisted_is = "maybe"\n')

    def test_non_boolean_exclusions_win_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(MINIMAL + '\n[rules]\nexclusions_win = "yes"\n')

    def test_unknown_rules_key_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(MINIMAL + "\n[rules]\nstrict = true\n")


class TestEntryValidation(unittest.TestCase):
    def test_unknown_top_level_table_is_rejected(self):
        # Catches the typo [[inscope]], which would otherwise be silently ignored.
        with self.assertRaises(ScopeFileError) as caught:
            parse_scope(MINIMAL + '\n[[inscope]]\ntype = "domain"\nvalue = "a.example.com"\n')
        self.assertIn("inscope", str(caught.exception))

    def test_unknown_entry_key_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(
                HEADER
                + '\n[[in_scope]]\ntype = "domain"\nvalue = "example.com"\nseverity = "high"\n'
            )

    def test_unknown_entry_type_is_rejected(self):
        with self.assertRaises(ScopeFileError) as caught:
            parse_scope(HEADER + '\n[[in_scope]]\ntype = "subdomain"\nvalue = "a.example.com"\n')
        self.assertIn("subdomain", str(caught.exception))

    def test_missing_value_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(HEADER + '\n[[in_scope]]\ntype = "domain"\n')

    def test_empty_value_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(HEADER + '\n[[in_scope]]\ntype = "domain"\nvalue = "   "\n')

    def test_non_string_max_severity_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(
                HEADER + '\n[[in_scope]]\ntype = "domain"\nvalue = "example.com"\nmax_severity = 7\n'
            )

    def test_an_empty_scope_file_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope(HEADER)

    def test_invalid_toml_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            parse_scope("[program\nname = ")

    def test_entry_index_and_label_are_stable(self):
        scope = parse_scope(
            HEADER
            + '\n[[in_scope]]\ntype = "domain"\nvalue = "a.example.com"\n'
            + '\n[[in_scope]]\ntype = "domain"\nvalue = "b.example.com"\n'
            + '\n[[out_of_scope]]\ntype = "domain"\nvalue = "c.example.com"\n'
        )
        self.assertEqual(scope.in_scope[1].label, "in_scope[1] domain = 'b.example.com'")
        self.assertEqual(scope.out_of_scope[0].label, "out_of_scope[0] domain = 'c.example.com'")
        self.assertEqual(len(scope), 3)


class TestLoadFromDisk(unittest.TestCase):
    def test_missing_file_is_reported_clearly(self):
        with self.assertRaises(ScopeFileError) as caught:
            load_scope("/nonexistent/path/to/scope.toml")
        self.assertIn("cannot read scope file", str(caught.exception))

    def test_examples_load(self):
        for name in ("primacy-of-rules.toml", "primacy-of-impact.toml", "broken-scope.toml"):
            with self.subTest(name=name):
                scope = load_scope(EXAMPLES / name)
                self.assertGreater(len(scope), 0)

    def test_round_trip_through_a_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.toml"
            path.write_text(MINIMAL, encoding="utf-8")
            scope = load_scope(path)
            self.assertEqual(scope.path, path)
            self.assertEqual(len(scope.in_scope), 1)


if __name__ == "__main__":
    unittest.main()

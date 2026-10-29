"""Precedence: which entry decides, and what happens when they disagree."""

from __future__ import annotations

import unittest

from scope_guard.decide import IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, decide
from scope_guard.scope import parse_scope
from scope_guard.targets import parse_target

from .helpers import HEADER


def verdict(body: str, raw_target: str, *, settings: str = "") -> str:
    scope = parse_scope(HEADER + settings + "\n" + body)
    return decide(scope, parse_target(raw_target)).verdict


def decision(body: str, raw_target: str, *, settings: str = ""):
    scope = parse_scope(HEADER + settings + "\n" + body)
    return decide(scope, parse_target(raw_target))


WILDCARD_AND_APEX = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"
"""


class TestBasicVerdicts(unittest.TestCase):
    def test_included_target_is_in_scope(self):
        self.assertEqual(verdict(WILDCARD_AND_APEX, "a.example.com"), IN_SCOPE)

    def test_apex_is_in_scope_because_it_is_listed(self):
        self.assertEqual(verdict(WILDCARD_AND_APEX, "example.com"), IN_SCOPE)

    def test_apex_is_not_in_scope_from_the_wildcard_alone(self):
        body = '[[in_scope]]\ntype = "wildcard"\nvalue = "*.example.com"\n'
        self.assertEqual(verdict(body, "example.com"), OUT_OF_SCOPE)

    def test_unrelated_host_is_out_of_scope(self):
        self.assertEqual(verdict(WILDCARD_AND_APEX, "notexample.com"), OUT_OF_SCOPE)

    def test_suffix_confusion_host_is_out_of_scope(self):
        self.assertEqual(verdict(WILDCARD_AND_APEX, "example.com.evil.net"), OUT_OF_SCOPE)

    def test_the_deciding_rule_is_named(self):
        result = decision(WILDCARD_AND_APEX, "a.example.com")
        self.assertEqual(len(result.deciding), 1)
        self.assertEqual(result.deciding[0].value, "*.example.com")
        self.assertIn("in_scope[0]", result.reason)

    def test_in_scope_is_the_only_allowed_verdict(self):
        self.assertTrue(decision(WILDCARD_AND_APEX, "a.example.com").allowed)
        self.assertFalse(decision(WILDCARD_AND_APEX, "nope.invalid").allowed)


class TestExclusionsWin(unittest.TestCase):
    BODY = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "api.example.com"

[[out_of_scope]]
type = "wildcard"
value = "*.example.com"
"""

    def test_general_exclusion_beats_specific_inclusion_by_default(self):
        # api.example.com is named exactly in_scope and only caught by a
        # wildcard out_of_scope. The exclusion still wins.
        result = decision(self.BODY, "api.example.com")
        self.assertEqual(result.verdict, OUT_OF_SCOPE)
        self.assertEqual(result.deciding[0].side, "out")

    def test_specificity_decides_when_exclusions_do_not_win(self):
        result = decision(
            self.BODY,
            "api.example.com",
            settings="[rules]\nexclusions_win = false\n",
        )
        self.assertEqual(result.verdict, IN_SCOPE)
        self.assertEqual(result.deciding[0].value, "api.example.com")

    def test_equal_specificity_disagreement_is_unknown(self):
        body = """
[[in_scope]]
type = "domain"
value = "app.example.com"

[[out_of_scope]]
type = "domain"
value = "app.example.com"
"""
        result = decision(
            body, "app.example.com", settings="[rules]\nexclusions_win = false\n"
        )
        self.assertEqual(result.verdict, UNKNOWN)
        self.assertEqual(len(result.deciding), 2)
        self.assertIn("in_scope[0]", result.reason)
        self.assertIn("out_of_scope[0]", result.reason)

    def test_the_same_disagreement_is_out_of_scope_by_default(self):
        body = """
[[in_scope]]
type = "domain"
value = "app.example.com"

[[out_of_scope]]
type = "domain"
value = "app.example.com"
"""
        self.assertEqual(verdict(body, "app.example.com"), OUT_OF_SCOPE)

    def test_most_specific_exclusion_is_the_one_reported(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[out_of_scope]]
type = "wildcard"
value = "*.example.com"

[[out_of_scope]]
type = "domain"
value = "a.example.com"
"""
        result = decision(body, "a.example.com")
        self.assertEqual(result.verdict, OUT_OF_SCOPE)
        self.assertEqual(result.deciding[0].value, "a.example.com")


class TestSpecificityPrecedence(unittest.TestCase):
    def test_path_exclusion_carves_out_of_an_included_host(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "path"
value = "example.com/admin"
"""
        self.assertEqual(verdict(body, "https://example.com/"), IN_SCOPE)
        self.assertEqual(verdict(body, "https://example.com/admin"), OUT_OF_SCOPE)
        self.assertEqual(verdict(body, "https://example.com/admin/users"), OUT_OF_SCOPE)
        self.assertEqual(verdict(body, "https://example.com/administration"), IN_SCOPE)
        self.assertEqual(verdict(body, "https://example.com/api/../admin"), OUT_OF_SCOPE)

    def test_nested_inclusion_inside_an_exclusion_needs_exclusions_win_false(self):
        body = """
[[in_scope]]
type = "path"
value = "example.com/admin/reports"

[[out_of_scope]]
type = "path"
value = "example.com/admin"
"""
        self.assertEqual(verdict(body, "https://example.com/admin/reports"), OUT_OF_SCOPE)
        self.assertEqual(
            verdict(
                body,
                "https://example.com/admin/reports",
                settings="[rules]\nexclusions_win = false\n",
            ),
            IN_SCOPE,
        )

    def test_ip_exclusion_carves_out_of_an_included_cidr(self):
        body = """
[[in_scope]]
type = "cidr"
value = "198.51.100.0/24"

[[out_of_scope]]
type = "ip"
value = "198.51.100.1"
"""
        self.assertEqual(verdict(body, "198.51.100.42"), IN_SCOPE)
        self.assertEqual(verdict(body, "198.51.100.1"), OUT_OF_SCOPE)
        self.assertEqual(verdict(body, "::ffff:198.51.100.1"), OUT_OF_SCOPE)
        self.assertEqual(verdict(body, "198.51.101.1"), OUT_OF_SCOPE)


class TestUnlistedIs(unittest.TestCase):
    BODY = '[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'

    def test_primacy_of_rules_treats_unlisted_as_out(self):
        result = decision(
            self.BODY, "other.invalid", settings='[rules]\nunlisted_is = "out"\n'
        )
        self.assertEqual(result.verdict, OUT_OF_SCOPE)
        self.assertEqual(result.deciding, ())
        self.assertIn("primacy of rules", result.reason)

    def test_primacy_of_impact_treats_unlisted_as_unknown(self):
        result = decision(
            self.BODY, "other.invalid", settings='[rules]\nunlisted_is = "unknown"\n'
        )
        self.assertEqual(result.verdict, UNKNOWN)
        self.assertIn("primacy of impact", result.reason)

    def test_out_is_the_default(self):
        self.assertEqual(verdict(self.BODY, "other.invalid"), OUT_OF_SCOPE)

    def test_unlisted_is_does_not_override_a_match(self):
        self.assertEqual(
            verdict(self.BODY, "example.com", settings='[rules]\nunlisted_is = "unknown"\n'),
            IN_SCOPE,
        )

    def test_exclusion_still_decides_under_primacy_of_impact(self):
        body = self.BODY + '\n[[out_of_scope]]\ntype = "domain"\nvalue = "mail.example.com"\n'
        self.assertEqual(
            verdict(body, "mail.example.com", settings='[rules]\nunlisted_is = "unknown"\n'),
            OUT_OF_SCOPE,
        )


class TestSeverityCap(unittest.TestCase):
    def test_cap_is_reported_from_the_deciding_entry(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"
max_severity = "medium"
"""
        self.assertEqual(decision(body, "example.com").max_severity, "medium")

    def test_no_cap_when_the_entry_has_none(self):
        body = '[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'
        self.assertIsNone(decision(body, "example.com").max_severity)

    def test_tightest_cap_wins_among_equal_entries(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"
max_severity = "high"

[[in_scope]]
type = "domain"
value = "example.com"
max_severity = "low"
"""
        self.assertEqual(decision(body, "example.com").max_severity, "low")

    def test_the_more_specific_entry_supplies_the_cap(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "api.example.com"
max_severity = "critical"
"""
        self.assertEqual(decision(body, "api.example.com").max_severity, "critical")


class TestHonestNotes(unittest.TestCase):
    """The decision must say what it could not consider."""

    def test_hostname_target_reports_unevaluated_address_entries(self):
        body = """
[[in_scope]]
type = "cidr"
value = "192.0.2.0/24"
"""
        result = decision(body, "host.example.com")
        self.assertEqual(result.verdict, OUT_OF_SCOPE)
        self.assertTrue(any("DNS resolution" in note for note in result.notes))

    def test_no_dns_note_when_a_host_entry_already_decided(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[in_scope]]
type = "cidr"
value = "192.0.2.0/24"
"""
        result = decision(body, "example.com")
        self.assertFalse(any("DNS resolution" in note for note in result.notes))

    def test_pathless_target_reports_unevaluated_path_entries(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "path"
value = "example.com/admin"
"""
        result = decision(body, "example.com")
        self.assertEqual(result.verdict, IN_SCOPE)
        self.assertTrue(any("path-scoped" in note for note in result.notes))

    def test_path_entries_for_other_hosts_are_not_reported(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "path"
value = "other.example.net/admin"
"""
        result = decision(body, "example.com")
        self.assertFalse(any("path-scoped" in note for note in result.notes))

    def test_schemeless_target_reports_the_assumption(self):
        body = '[[in_scope]]\ntype = "url"\nvalue = "https://example.com/api"\n'
        result = decision(body, "example.com/api/v1")
        self.assertEqual(result.verdict, IN_SCOPE)
        self.assertTrue(any("without a scheme" in note for note in result.notes))

    def test_encoded_separator_note_is_carried_through(self):
        body = '[[in_scope]]\ntype = "domain"\nvalue = "example.com"\n'
        result = decision(body, "example.com/a%2Fb")
        self.assertTrue(any("encoded separator" in note for note in result.notes))

    def test_trace_names_every_match(self):
        result = decision(WILDCARD_AND_APEX, "a.example.com")
        joined = "\n".join(result.trace)
        self.assertIn("matched 1 entry", joined)
        self.assertIn("*.example.com", joined)

    def test_json_view_is_serialisable_and_complete(self):
        import json

        payload = decision(WILDCARD_AND_APEX, "a.example.com").to_dict()
        round_tripped = json.loads(json.dumps(payload))
        self.assertEqual(round_tripped["verdict"], IN_SCOPE)
        self.assertEqual(round_tripped["exit_code"], 0)
        self.assertEqual(round_tripped["deciding_rules"][0]["type"], "wildcard")
        self.assertEqual(round_tripped["normalised_target"], "a.example.com")


class TestExitCodes(unittest.TestCase):
    def test_in_scope_is_zero(self):
        self.assertEqual(decision(WILDCARD_AND_APEX, "a.example.com").exit_code, 0)

    def test_out_of_scope_is_one(self):
        self.assertEqual(decision(WILDCARD_AND_APEX, "nope.invalid").exit_code, 1)

    def test_unknown_is_two(self):
        result = decision(
            WILDCARD_AND_APEX, "nope.invalid", settings='[rules]\nunlisted_is = "unknown"\n'
        )
        self.assertEqual(result.exit_code, 2)


if __name__ == "__main__":
    unittest.main()

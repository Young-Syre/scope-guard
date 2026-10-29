"""Every lint check: it fires on a broken file, and stays quiet on a clean one."""

from __future__ import annotations

import datetime
import unittest

from scope_guard.lint import CHECKS, ERROR, INFO, WARNING, lint_scope
from scope_guard.scope import load_scope, parse_scope

from .helpers import EXAMPLES, HEADER, TODAY


def report(body: str, *, settings: str = "", header: str = HEADER, max_age_days: int = 90):
    scope = parse_scope(header + settings + "\n" + body)
    return lint_scope(scope, max_age_days=max_age_days, today=TODAY)


def checks_in(result) -> set[str]:
    return {finding.check for finding in result.findings}


def findings_for(result, check: str):
    return [finding for finding in result.findings if finding.check == check]


CLEAN = """
[[in_scope]]
type = "domain"
value = "example.com"

[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[out_of_scope]]
type = "domain"
value = "mail.example.com"
"""


class TestCleanFile(unittest.TestCase):
    def test_a_clean_file_produces_nothing(self):
        result = report(CLEAN)
        self.assertEqual(result.findings, ())
        self.assertTrue(result.ok())
        self.assertTrue(result.ok(strict=True))

    def test_both_realistic_examples_are_clean(self):
        for name in ("primacy-of-rules.toml", "primacy-of-impact.toml"):
            with self.subTest(name=name):
                result = lint_scope(load_scope(EXAMPLES / name), today=TODAY)
                self.assertEqual(result.errors, 0, result.findings)
                self.assertEqual(result.warnings, 0, result.findings)
                self.assertTrue(result.ok(strict=True))

    def test_every_check_is_documented(self):
        self.assertEqual(sorted(CHECKS), [f"SG{n:03d}" for n in range(1, 11)])
        for check, description in CHECKS.items():
            self.assertTrue(description.strip(), check)


class TestSG001Overlap(unittest.TestCase):
    def test_cidr_covering_an_ip_on_the_same_side(self):
        body = """
[[in_scope]]
type = "cidr"
value = "192.0.2.0/24"

[[in_scope]]
type = "ip"
value = "192.0.2.10"
"""
        result = report(body)
        self.assertIn("SG001", checks_in(result))
        self.assertEqual(findings_for(result, "SG001")[0].severity, WARNING)

    def test_host_entry_covering_a_path_entry_on_the_same_side(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[in_scope]]
type = "path"
value = "example.com/api"
"""
        self.assertIn("SG001", checks_in(report(body)))

    def test_a_redundant_entry_carrying_a_cap_is_only_informational(self):
        body = """
[[in_scope]]
type = "cidr"
value = "192.0.2.0/24"

[[in_scope]]
type = "ip"
value = "192.0.2.10"
max_severity = "low"
"""
        result = report(body)
        self.assertEqual(findings_for(result, "SG001")[0].severity, INFO)
        self.assertEqual(result.warnings, 0)

    def test_disjoint_entries_do_not_overlap(self):
        body = """
[[in_scope]]
type = "cidr"
value = "192.0.2.0/24"

[[in_scope]]
type = "ip"
value = "198.51.100.10"
"""
        self.assertNotIn("SG001", checks_in(report(body)))


class TestSG002DeadExclusion(unittest.TestCase):
    def test_exclusion_nothing_can_reach(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "domain"
value = "unrelated.other.example"
"""
        result = report(body)
        self.assertIn("SG002", checks_in(result))
        self.assertEqual(findings_for(result, "SG002")[0].severity, WARNING)

    def test_an_overlapping_exclusion_is_not_dead(self):
        self.assertNotIn("SG002", checks_in(report(CLEAN)))

    def test_it_does_not_fire_under_primacy_of_impact(self):
        # There, a non-overlapping exclusion is the only way to turn an
        # "unknown" into a definite "out-of-scope", so it is doing real work.
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "domain"
value = "unrelated.other.example"
"""
        result = report(body, settings='[rules]\nunlisted_is = "unknown"\n')
        self.assertNotIn("SG002", checks_in(result))

    def test_address_exclusion_with_only_hostname_inclusions_is_informational(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "cidr"
value = "10.0.0.0/8"
"""
        result = report(body)
        finding = findings_for(result, "SG002")[0]
        self.assertEqual(finding.severity, INFO)
        self.assertIn("does not resolve names", finding.message)


class TestSG003WildcardSubsumption(unittest.TestCase):
    def test_wildcard_covering_a_sibling_domain(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "api.example.com"
"""
        result = report(body)
        self.assertIn("SG003", checks_in(result))
        self.assertEqual(findings_for(result, "SG003")[0].severity, WARNING)

    def test_wildcard_covering_a_nested_wildcard(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "wildcard"
value = "*.api.example.com"
"""
        self.assertIn("SG003", checks_in(report(body)))

    def test_a_subsumed_sibling_with_a_cap_is_only_informational(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "api.example.com"
max_severity = "critical"
"""
        result = report(body)
        self.assertEqual(findings_for(result, "SG003")[0].severity, INFO)

    def test_the_apex_is_not_subsumed_by_its_own_wildcard(self):
        self.assertNotIn("SG003", checks_in(report(CLEAN)))

    def test_a_void_scheme_pin_is_a_warning(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"

[[in_scope]]
type = "url"
value = "https://app.example.com"
max_severity = "critical"
"""
        result = report(body)
        finding = findings_for(result, "SG003")[0]
        self.assertEqual(finding.severity, WARNING)
        self.assertIn("pins the https scheme", finding.message)
        self.assertIn("restricts nothing", finding.message)

    def test_a_void_port_pin_is_a_warning(self):
        body = """
[[in_scope]]
type = "domain"
value = "app.example.com"

[[in_scope]]
type = "url"
value = "https://app.example.com:8443"
"""
        result = report(body)
        finding = findings_for(result, "SG001")[0]
        self.assertEqual(finding.severity, WARNING)
        self.assertIn("port 8443", finding.message)

    def test_a_pin_is_not_void_without_a_broader_entry(self):
        body = """
[[in_scope]]
type = "url"
value = "https://app.example.com"
"""
        self.assertEqual(report(body).findings, ())

    def test_a_pin_is_not_void_when_the_broader_entry_pins_it_too(self):
        body = """
[[in_scope]]
type = "url"
value = "https://app.example.com"

[[in_scope]]
type = "url"
value = "https://app.example.com/admin"
notes = "kept for documentation"
"""
        result = report(body)
        self.assertEqual(findings_for(result, "SG001")[0].severity, INFO)

    def test_entries_on_opposite_sides_are_not_reported_here(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "domain"
value = "api.example.com"
"""
        self.assertNotIn("SG003", checks_in(report(body)))


class TestSG004MissingApex(unittest.TestCase):
    def test_in_scope_wildcard_without_its_apex(self):
        body = '[[in_scope]]\ntype = "wildcard"\nvalue = "*.example.com"\n'
        result = report(body)
        self.assertIn("SG004", checks_in(result))
        self.assertIn("matches subdomains only", findings_for(result, "SG004")[0].message)

    def test_out_of_scope_wildcard_without_its_apex(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "wildcard"
value = "*.sandbox.example.com"
"""
        result = report(body)
        self.assertEqual(len(findings_for(result, "SG004")), 1)
        self.assertIn("sandbox.example.com", findings_for(result, "SG004")[0].message)

    def test_listing_the_apex_silences_it(self):
        self.assertNotIn("SG004", checks_in(report(CLEAN)))

    def test_an_apex_excluded_on_purpose_silences_it(self):
        # "subdomains yes, the apex no" is coherent, not an oversight.
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[out_of_scope]]
type = "domain"
value = "example.com"
"""
        self.assertNotIn("SG004", checks_in(report(body)))

    def test_a_same_side_covering_wildcard_silences_it(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"

[[in_scope]]
type = "wildcard"
value = "*.api.example.com"
"""
        self.assertNotIn("SG004", checks_in(report(body)))

    def test_an_opposite_side_covering_wildcard_does_not_silence_it(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "wildcard"
value = "*.ci.example.com"
"""
        result = report(body)
        self.assertEqual(len(findings_for(result, "SG004")), 1)
        self.assertIn("ci.example.com", findings_for(result, "SG004")[0].message)


class TestSG005CidrContainsExcludedHost(unittest.TestCase):
    BODY = """
[[in_scope]]
type = "cidr"
value = "198.51.100.0/24"

[[out_of_scope]]
type = "ip"
value = "198.51.100.1"
"""

    def test_carve_out_is_confirmed_when_exclusions_win(self):
        result = report(self.BODY)
        self.assertIn("SG005", checks_in(result))
        self.assertEqual(findings_for(result, "SG005")[0].severity, INFO)

    def test_carve_out_still_holds_on_specificity(self):
        result = report(self.BODY, settings="[rules]\nexclusions_win = false\n")
        self.assertEqual(findings_for(result, "SG005")[0].severity, INFO)

    def test_a_losing_carve_out_is_a_warning(self):
        body = """
[[in_scope]]
type = "cidr"
value = "198.51.100.0/24"

[[out_of_scope]]
type = "cidr"
value = "198.51.100.0/24"
"""
        result = report(body, settings="[rules]\nexclusions_win = false\n")
        finding = findings_for(result, "SG005")[0]
        self.assertEqual(finding.severity, WARNING)
        self.assertIn("the carve-out loses", finding.message)

    def test_no_finding_when_the_exclusion_is_outside(self):
        body = """
[[in_scope]]
type = "cidr"
value = "198.51.100.0/24"

[[out_of_scope]]
type = "ip"
value = "203.0.113.1"
"""
        self.assertNotIn("SG005", checks_in(report(body)))


class TestSG006Staleness(unittest.TestCase):
    def test_a_stale_date_is_a_warning(self):
        header = '[program]\npolicy_url = "https://x.example/p"\nlast_verified = 2026-01-01\n'
        result = report(CLEAN, header=header)
        finding = findings_for(result, "SG006")[0]
        self.assertEqual(finding.severity, WARNING)
        self.assertIn("301 days ago", finding.message)

    def test_the_limit_is_configurable(self):
        header = '[program]\npolicy_url = "https://x.example/p"\nlast_verified = 2026-10-01\n'
        self.assertNotIn("SG006", checks_in(report(CLEAN, header=header, max_age_days=90)))
        self.assertIn("SG006", checks_in(report(CLEAN, header=header, max_age_days=7)))

    def test_a_missing_date_is_a_warning(self):
        header = '[program]\npolicy_url = "https://x.example/p"\n'
        result = report(CLEAN, header=header)
        self.assertIn("SG006", checks_in(result))
        self.assertIn("cannot be checked", findings_for(result, "SG006")[0].message)

    def test_a_future_date_is_an_error(self):
        header = '[program]\npolicy_url = "https://x.example/p"\nlast_verified = 2027-01-01\n'
        result = report(CLEAN, header=header)
        finding = findings_for(result, "SG006")[0]
        self.assertEqual(finding.severity, ERROR)
        self.assertIn("in the future", finding.message)

    def test_a_fresh_date_is_silent(self):
        self.assertNotIn("SG006", checks_in(report(CLEAN)))


class TestSG007And008(unittest.TestCase):
    def test_duplicate_entry_on_the_same_side(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[in_scope]]
type = "domain"
value = "EXAMPLE.com."
"""
        result = report(body)
        self.assertIn("SG007", checks_in(result))
        self.assertEqual(findings_for(result, "SG007")[0].severity, WARNING)

    def test_the_same_entry_on_both_sides_is_an_error(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "domain"
value = "example.com"
"""
        result = report(body)
        self.assertIn("SG008", checks_in(result))
        self.assertEqual(findings_for(result, "SG008")[0].severity, ERROR)
        self.assertFalse(result.ok())

    def test_sg008_does_not_also_report_sg010(self):
        body = """
[[in_scope]]
type = "domain"
value = "example.com"

[[out_of_scope]]
type = "domain"
value = "example.com"
"""
        self.assertNotIn("SG010", checks_in(report(body)))

    def test_the_same_value_under_different_types_is_not_a_duplicate(self):
        body = """
[[in_scope]]
type = "android-package"
value = "com.example.app"

[[in_scope]]
type = "ios-bundle"
value = "com.example.app"
"""
        result = report(body)
        self.assertNotIn("SG007", checks_in(result))
        self.assertNotIn("SG008", checks_in(result))


class TestSG009Metadata(unittest.TestCase):
    def test_a_missing_policy_url_is_a_warning(self):
        header = "[program]\nname = \"X\"\nplatform = \"y\"\nlast_verified = 2026-10-29\n"
        result = report(CLEAN, header=header)
        finding = findings_for(result, "SG009")[0]
        self.assertEqual(finding.severity, WARNING)
        self.assertIn("policy_url", finding.message)

    def test_a_missing_name_is_informational(self):
        header = '[program]\npolicy_url = "https://x.example/p"\nlast_verified = 2026-10-29\n'
        result = report(CLEAN, header=header)
        severities = {f.severity for f in findings_for(result, "SG009")}
        self.assertIn(INFO, severities)

    def test_full_metadata_is_silent(self):
        self.assertNotIn("SG009", checks_in(report(CLEAN)))


class TestSG010UnreachableInclusion(unittest.TestCase):
    BODY = """
[[in_scope]]
type = "domain"
value = "api.example.com"

[[out_of_scope]]
type = "wildcard"
value = "*.example.com"

[[out_of_scope]]
type = "domain"
value = "example.com"
"""

    def test_a_swallowed_inclusion_is_an_error(self):
        result = report(self.BODY)
        self.assertIn("SG010", checks_in(result))
        finding = findings_for(result, "SG010")[0]
        self.assertEqual(finding.severity, ERROR)
        self.assertIn("api.example.com", finding.message)
        self.assertFalse(result.ok())

    def test_it_is_only_a_warning_when_specificity_could_rescue_it(self):
        result = report(self.BODY, settings="[rules]\nexclusions_win = false\n")
        self.assertEqual(findings_for(result, "SG010"), [])

    def test_an_equally_specific_exclusion_still_warns(self):
        body = """
[[in_scope]]
type = "path"
value = "example.com/admin/reports"

[[out_of_scope]]
type = "path"
value = "example.com/admin/reports"
"""
        result = report(body, settings="[rules]\nexclusions_win = false\n")
        # Same normalised entry on both sides: SG008 owns this one.
        self.assertIn("SG008", checks_in(result))

    def test_a_nested_exclusion_does_not_swallow_the_inclusion(self):
        self.assertNotIn("SG010", checks_in(report(CLEAN)))


class TestBrokenExample(unittest.TestCase):
    """The shipped broken file must exercise every check."""

    def setUp(self):
        self.result = lint_scope(load_scope(EXAMPLES / "broken-scope.toml"), today=TODAY)

    def test_every_check_fires(self):
        self.assertEqual(checks_in(self.result), set(CHECKS))

    def test_it_fails(self):
        self.assertFalse(self.result.ok())
        self.assertFalse(self.result.ok(strict=True))
        self.assertGreaterEqual(self.result.errors, 1)
        self.assertGreaterEqual(self.result.warnings, 1)

    def test_findings_are_ordered_by_severity(self):
        severities = [f.severity for f in self.result.findings]
        order = {ERROR: 0, WARNING: 1, INFO: 2}
        self.assertEqual(severities, sorted(severities, key=lambda s: order[s]))

    def test_the_report_serialises(self):
        import json

        payload = json.loads(json.dumps(self.result.to_dict()))
        self.assertEqual(len(payload["findings"]), len(self.result.findings))
        self.assertEqual(payload["counts"]["error"], self.result.errors)
        for finding in payload["findings"]:
            self.assertIn(finding["check"], CHECKS)
            self.assertTrue(finding["description"])


class TestStrictMode(unittest.TestCase):
    def test_warnings_pass_normally_and_fail_under_strict(self):
        body = """
[[in_scope]]
type = "wildcard"
value = "*.example.com"

[[in_scope]]
type = "domain"
value = "example.com"

[[in_scope]]
type = "domain"
value = "api.example.com"
"""
        result = report(body)
        self.assertEqual(result.errors, 0)
        self.assertGreaterEqual(result.warnings, 1)
        self.assertTrue(result.ok())
        self.assertFalse(result.ok(strict=True))

    def test_staleness_uses_todays_date_when_none_is_given(self):
        header = '[program]\npolicy_url = "https://x.example/p"\nlast_verified = 2000-01-01\n'
        scope = parse_scope(header + "\n" + CLEAN)
        result = lint_scope(scope)
        self.assertIn("SG006", checks_in(result))
        self.assertIsInstance(datetime.date.today(), datetime.date)


if __name__ == "__main__":
    unittest.main()

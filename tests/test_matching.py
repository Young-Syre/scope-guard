"""Matching semantics: normalisation, wildcards, addresses, paths.

These are the tests that matter most. Everything else in scope-guard is
plumbing around the question "does this entry cover this target", and a
wrong answer here is the whole failure mode the tool exists to prevent.
"""

from __future__ import annotations

import unittest

from scope_guard.errors import ScopeFileError, TargetError
from scope_guard.normalise import normalise_host, normalise_path
from scope_guard.rules import build_rule, intersects, subsumes, wildcard_matches
from scope_guard.targets import parse_target

from .helpers import HEADER


def rule(rule_type: str, value: str, side: str = "in", index: int = 0, **extra):
    entry = {"type": rule_type, "value": value, **extra}
    return build_rule(side=side, index=index, entry=entry)


def matches(rule_type: str, value: str, raw_target: str, **kwargs) -> bool:
    return rule(rule_type, value).matches(parse_target(raw_target, **kwargs))


class TestHostNormalisation(unittest.TestCase):
    def test_uppercase_is_lowercased(self):
        self.assertEqual(normalise_host("EXAMPLE.com"), "example.com")

    def test_trailing_dot_is_the_same_host(self):
        self.assertEqual(normalise_host("example.com."), "example.com")
        self.assertEqual(normalise_host("example.com."), normalise_host("example.com"))

    def test_unicode_is_punycoded(self):
        self.assertEqual(normalise_host("bücher.example.com"), "xn--bcher-kva.example.com")

    def test_punycode_input_is_left_alone(self):
        self.assertEqual(
            normalise_host("xn--bcher-kva.example.com"), "xn--bcher-kva.example.com"
        )

    def test_unicode_and_punycode_converge(self):
        self.assertEqual(
            normalise_host("BÜCHER.Example.COM"),
            normalise_host("xn--bcher-kva.EXAMPLE.com"),
        )

    def test_ipv6_literal_is_canonicalised(self):
        self.assertEqual(normalise_host("2001:DB8::0:1"), "2001:db8::1")

    def test_bracketed_ipv6_loses_its_brackets(self):
        self.assertEqual(normalise_host("[2001:db8::1]"), "2001:db8::1")

    def test_empty_label_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            normalise_host("a..b.example.com")

    def test_star_in_a_host_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            normalise_host("*.example.com")

    def test_overlong_label_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            normalise_host("a" * 64 + ".example.com")


class TestWildcardMatching(unittest.TestCase):
    """The asymmetry: a wildcard covers subdomains, never the apex."""

    def test_single_label_subdomain_matches(self):
        self.assertTrue(matches("wildcard", "*.example.com", "a.example.com"))

    def test_multi_label_subdomain_matches(self):
        self.assertTrue(matches("wildcard", "*.example.com", "a.b.c.example.com"))

    def test_apex_does_not_match(self):
        self.assertFalse(matches("wildcard", "*.example.com", "example.com"))

    def test_sibling_suffix_does_not_match(self):
        self.assertFalse(matches("wildcard", "*.example.com", "notexample.com"))

    def test_attacker_suffix_does_not_match(self):
        self.assertFalse(matches("wildcard", "*.example.com", "example.com.evil.net"))

    def test_dash_prefixed_sibling_does_not_match(self):
        self.assertFalse(matches("wildcard", "*.example.com", "evil-example.com"))
        self.assertFalse(matches("wildcard", "*.example.com", "xexample.com"))

    def test_empty_leading_label_does_not_match(self):
        # ".example.com" has an empty first label and is not a valid host.
        with self.assertRaises(TargetError):
            parse_target(".example.com")

    def test_uppercase_target_matches(self):
        self.assertTrue(matches("wildcard", "*.example.com", "A.EXAMPLE.COM"))

    def test_trailing_dot_target_matches(self):
        self.assertTrue(matches("wildcard", "*.example.com", "a.example.com."))

    def test_punycode_target_matches_unicode_entry(self):
        self.assertTrue(matches("wildcard", "*.bücher.example", "shop.xn--bcher-kva.example"))

    def test_wildcard_never_matches_an_ip_target(self):
        self.assertFalse(matches("wildcard", "*.example.com", "192.0.2.5"))

    def test_nested_wildcard_requires_its_own_depth(self):
        self.assertTrue(matches("wildcard", "*.api.example.com", "v1.api.example.com"))
        self.assertFalse(matches("wildcard", "*.api.example.com", "api.example.com"))
        self.assertFalse(matches("wildcard", "*.api.example.com", "v1.example.com"))

    def test_helper_is_consistent_with_matching(self):
        self.assertTrue(wildcard_matches("example.com", "a.example.com"))
        self.assertFalse(wildcard_matches("example.com", "example.com"))
        self.assertFalse(wildcard_matches("example.com", "notexample.com"))
        self.assertFalse(wildcard_matches("example.com", "example.com.evil.net"))

    def test_partial_label_wildcard_is_rejected_not_half_supported(self):
        with self.assertRaises(ScopeFileError):
            rule("wildcard", "api-*.example.com")

    def test_wildcard_without_leading_star_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("wildcard", "example.com")

    def test_domain_entry_holding_a_wildcard_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("domain", "*.example.com")


class TestDomainMatching(unittest.TestCase):
    def test_exact_host_matches(self):
        self.assertTrue(matches("domain", "example.com", "example.com"))

    def test_subdomain_does_not_match_an_apex_entry(self):
        self.assertFalse(matches("domain", "example.com", "a.example.com"))

    def test_normalisation_applies_to_both_sides(self):
        self.assertTrue(matches("domain", "EXAMPLE.com.", "example.com"))

    def test_ip_in_a_domain_entry_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("domain", "192.0.2.5")


class TestAddressMatching(unittest.TestCase):
    def test_ipv4_in_cidr(self):
        self.assertTrue(matches("cidr", "192.0.2.0/24", "192.0.2.5"))

    def test_ipv4_outside_cidr(self):
        self.assertFalse(matches("cidr", "192.0.2.0/24", "192.0.3.5"))

    def test_ipv6_in_cidr(self):
        self.assertTrue(matches("cidr", "2001:db8::/32", "2001:db8:1::1"))

    def test_ipv6_outside_cidr(self):
        self.assertFalse(matches("cidr", "2001:db8::/32", "2001:db9::1"))

    def test_ipv4_mapped_ipv6_target_matches_an_ipv4_cidr(self):
        self.assertTrue(matches("cidr", "192.0.2.0/24", "::ffff:192.0.2.5"))

    def test_ipv4_mapped_hex_form_matches_an_ipv4_cidr(self):
        self.assertTrue(matches("cidr", "192.0.2.0/24", "::ffff:c000:205"))

    def test_ipv4_target_matches_a_mapped_ipv6_cidr(self):
        self.assertTrue(matches("cidr", "::ffff:192.0.2.0/120", "192.0.2.5"))

    def test_ipv4_mapped_target_matches_an_exact_ipv4_entry(self):
        self.assertTrue(matches("ip", "192.0.2.5", "::ffff:192.0.2.5"))

    def test_ipv6_cidr_does_not_match_an_unrelated_ipv4_target(self):
        self.assertFalse(matches("cidr", "2001:db8::/32", "192.0.2.5"))

    def test_hostname_target_is_never_matched_by_a_cidr(self):
        # No DNS resolution happens anywhere in the decision path.
        self.assertFalse(matches("cidr", "192.0.2.0/24", "host.example.com"))

    def test_exact_ip_entry(self):
        self.assertTrue(matches("ip", "192.0.2.5", "192.0.2.5"))
        self.assertFalse(matches("ip", "192.0.2.5", "192.0.2.6"))

    def test_ipv6_entry_is_normalised(self):
        self.assertTrue(matches("ip", "2001:DB8::0:1", "2001:db8::1"))

    def test_cidr_without_a_prefix_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("cidr", "192.0.2.5")

    def test_malformed_cidr_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("cidr", "192.0.2.0/33")

    def test_host_bits_in_a_cidr_are_accepted_and_masked(self):
        self.assertEqual(rule("cidr", "192.0.2.5/24").describe_normalised(), "192.0.2.0/24")


class TestPathNormalisation(unittest.TestCase):
    def test_segments_are_split_and_emptied(self):
        self.assertEqual(normalise_path("//a///b/"), ("a", "b"))

    def test_dot_segments_resolve(self):
        self.assertEqual(normalise_path("/api/../admin"), ("admin",))

    def test_encoded_dot_segments_resolve_too(self):
        self.assertEqual(normalise_path("/api/%2e%2e/admin"), ("admin",))

    def test_traversal_past_the_root_is_clamped(self):
        self.assertEqual(normalise_path("/a/b/../../../../c"), ("c",))

    def test_encoded_separator_stays_inside_one_segment(self):
        self.assertEqual(normalise_path("/api%2Fv1"), ("api/v1",))

    def test_root_is_no_segments(self):
        self.assertEqual(normalise_path("/"), ())

    def test_percent_decoding_applies(self):
        self.assertEqual(normalise_path("/a%20b"), ("a b",))

    def test_case_is_preserved(self):
        self.assertEqual(normalise_path("/API"), ("API",))


class TestPathMatching(unittest.TestCase):
    def test_prefix_match_on_whole_segments(self):
        self.assertTrue(matches("path", "example.com/api", "https://example.com/api/v1"))

    def test_exact_path_matches(self):
        self.assertTrue(matches("path", "example.com/api", "https://example.com/api"))

    def test_prefix_does_not_bleed_across_a_segment(self):
        self.assertFalse(matches("path", "example.com/api", "https://example.com/apifoo"))

    def test_sibling_path_does_not_match(self):
        self.assertFalse(matches("path", "example.com/api", "https://example.com/admin"))

    def test_traversal_cannot_smuggle_past_a_path_entry(self):
        self.assertFalse(matches("path", "example.com/api", "https://example.com/api/../admin"))

    def test_encoded_traversal_cannot_smuggle_past_a_path_entry(self):
        self.assertFalse(
            matches("path", "example.com/api", "https://example.com/api/%2e%2e/admin")
        )

    def test_traversal_lands_on_the_entry_it_resolves_to(self):
        self.assertTrue(matches("path", "example.com/admin", "https://example.com/api/../admin"))

    def test_encoded_separator_does_not_satisfy_a_path_entry(self):
        self.assertFalse(matches("path", "example.com/api", "https://example.com/api%2Fv1"))

    def test_wildcard_host_in_a_path_entry(self):
        self.assertTrue(matches("path", "*.example.com/api", "https://a.example.com/api/v1"))
        self.assertFalse(matches("path", "*.example.com/api", "https://example.com/api/v1"))

    def test_path_entry_does_not_decide_a_target_without_a_path(self):
        self.assertFalse(matches("path", "example.com/api", "example.com"))

    def test_path_entry_without_a_path_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("path", "example.com/")

    def test_path_entry_is_case_sensitive(self):
        self.assertFalse(matches("path", "example.com/api", "https://example.com/API"))


class TestUrlMatching(unittest.TestCase):
    def test_scheme_is_pinned_when_written(self):
        self.assertTrue(matches("url", "https://example.com/api", "https://example.com/api/v1"))
        self.assertFalse(matches("url", "https://example.com/api", "http://example.com/api/v1"))

    def test_implicit_port_matches_any_port(self):
        self.assertTrue(matches("url", "https://example.com", "https://example.com:8443/x"))

    def test_explicit_port_is_pinned(self):
        self.assertTrue(matches("url", "https://example.com:8443", "https://example.com:8443/x"))
        self.assertFalse(matches("url", "https://example.com:8443", "https://example.com/x"))

    def test_default_port_in_the_target_equals_no_port(self):
        self.assertTrue(matches("url", "https://example.com:443", "https://example.com/x"))

    def test_url_without_a_scheme_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("url", "example.com/api")

    def test_query_string_in_an_entry_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("url", "https://example.com/api?id=1")

    def test_userinfo_is_discarded(self):
        self.assertTrue(matches("url", "https://user@example.com/api", "https://example.com/api"))

    def test_schemeless_target_is_matched_as_any_scheme(self):
        self.assertTrue(matches("url", "https://example.com/api", "example.com/api/v1"))

    def test_ip_host_in_a_url_entry(self):
        self.assertTrue(matches("url", "https://192.0.2.5/api", "https://192.0.2.5/api/v1"))

    def test_bracketed_ipv6_host_in_a_url_entry(self):
        self.assertTrue(matches("url", "https://[2001:db8::1]:8443/a", "https://[2001:db8::1]:8443/a/b"))


class TestIdentifierMatching(unittest.TestCase):
    def test_exact_android_package(self):
        self.assertTrue(matches("android-package", "com.example.app", "android:com.example.app"))
        self.assertFalse(matches("android-package", "com.example.app", "android:com.example.other"))

    def test_package_wildcard_covers_children_not_the_stem(self):
        self.assertTrue(matches("android-package", "com.example.*", "android:com.example.app"))
        self.assertFalse(matches("android-package", "com.example.*", "android:com.example"))

    def test_package_wildcard_respects_component_boundaries(self):
        self.assertFalse(
            matches("android-package", "com.example.*", "android:com.exampleother.app")
        )

    def test_ios_bundle_and_android_package_are_distinct_families(self):
        self.assertFalse(matches("ios-bundle", "com.example.app", "android:com.example.app"))
        self.assertTrue(matches("ios-bundle", "com.example.app", "ios:com.example.app"))

    def test_package_identifiers_are_case_sensitive(self):
        self.assertFalse(matches("android-package", "com.example.App", "android:com.example.app"))

    def test_repo_forms_converge(self):
        for form in (
            "repo:https://git.example.com/acme/widget.git",
            "repo:git@git.example.com:acme/widget",
            "repo:git.example.com/acme/widget/",
        ):
            with self.subTest(form=form):
                self.assertTrue(matches("repo", "git.example.com/acme/widget", form))

    def test_repo_host_is_case_insensitive(self):
        self.assertTrue(
            matches("repo", "GIT.example.com/acme/widget", "repo:git.example.com/acme/widget")
        )

    def test_repo_entry_naming_only_a_host_is_rejected(self):
        with self.assertRaises(ScopeFileError):
            rule("repo", "git.example.com")

    def test_host_target_is_not_matched_by_a_package_entry(self):
        self.assertFalse(matches("android-package", "com.example.app", "com.example.app"))


class TestSpecificity(unittest.TestCase):
    def test_exact_host_beats_wildcard(self):
        self.assertGreater(
            rule("domain", "a.example.com").specificity(),
            rule("wildcard", "*.example.com").specificity(),
        )

    def test_deeper_wildcard_beats_shallower(self):
        self.assertGreater(
            rule("wildcard", "*.api.example.com").specificity(),
            rule("wildcard", "*.example.com").specificity(),
        )

    def test_tighter_cidr_beats_looser(self):
        self.assertGreater(
            rule("cidr", "192.0.2.0/28").specificity(),
            rule("cidr", "192.0.2.0/24").specificity(),
        )

    def test_exact_ip_beats_any_cidr(self):
        self.assertGreater(
            rule("ip", "192.0.2.5").specificity(),
            rule("cidr", "192.0.2.5/32").specificity(),
        )

    def test_deeper_path_beats_shallower(self):
        self.assertGreater(
            rule("path", "example.com/api/v1").specificity(),
            rule("path", "example.com/api").specificity(),
        )

    def test_path_beats_bare_host_on_the_same_host(self):
        self.assertGreater(
            rule("path", "example.com/api").specificity(),
            rule("domain", "example.com").specificity(),
        )

    def test_pinned_scheme_and_port_break_a_tie(self):
        self.assertGreater(
            rule("url", "https://example.com:8443/api").specificity(),
            rule("path", "example.com/api").specificity(),
        )


class TestRuleAlgebra(unittest.TestCase):
    """The relations lint reasons with."""

    def test_wildcard_subsumes_a_subdomain(self):
        self.assertTrue(subsumes(rule("wildcard", "*.example.com"), rule("domain", "a.example.com")))

    def test_wildcard_does_not_subsume_its_apex(self):
        self.assertFalse(subsumes(rule("wildcard", "*.example.com"), rule("domain", "example.com")))

    def test_wildcard_subsumes_a_nested_wildcard(self):
        self.assertTrue(
            subsumes(rule("wildcard", "*.example.com"), rule("wildcard", "*.api.example.com"))
        )

    def test_cidr_subsumes_a_contained_ip(self):
        self.assertTrue(subsumes(rule("cidr", "10.0.0.0/8"), rule("ip", "10.1.2.3")))

    def test_cidr_subsumes_a_contained_cidr(self):
        self.assertTrue(subsumes(rule("cidr", "10.0.0.0/8"), rule("cidr", "10.1.0.0/16")))

    def test_cidr_does_not_subsume_across_families(self):
        self.assertFalse(subsumes(rule("cidr", "10.0.0.0/8"), rule("cidr", "2001:db8::/32")))

    def test_host_entry_subsumes_a_path_entry_on_that_host(self):
        self.assertTrue(subsumes(rule("domain", "example.com"), rule("path", "example.com/api")))

    def test_path_entry_does_not_subsume_the_whole_host(self):
        self.assertFalse(subsumes(rule("path", "example.com/api"), rule("domain", "example.com")))

    def test_hostname_and_address_entries_never_subsume_each_other(self):
        self.assertFalse(subsumes(rule("wildcard", "*.example.com"), rule("cidr", "10.0.0.0/8")))
        self.assertFalse(subsumes(rule("cidr", "10.0.0.0/8"), rule("wildcard", "*.example.com")))

    def test_nested_paths_intersect(self):
        self.assertTrue(
            intersects(rule("path", "example.com/api"), rule("path", "example.com/api/v1"))
        )

    def test_sibling_paths_do_not_intersect(self):
        self.assertFalse(
            intersects(rule("path", "example.com/api"), rule("path", "example.com/admin"))
        )

    def test_different_schemes_do_not_intersect(self):
        self.assertFalse(
            intersects(rule("url", "https://example.com/a"), rule("url", "http://example.com/a"))
        )

    def test_different_families_do_not_intersect(self):
        self.assertFalse(
            intersects(rule("android-package", "com.example.app"), rule("domain", "example.com"))
        )


class TestCidrSpecificityAcrossFamilies(unittest.TestCase):
    """Prefix lengths are not comparable between IPv4 and IPv6.

    One target can carry an address in both families (an IPv4-mapped IPv6
    literal, in either spelling), so the two scales meet in one comparison.
    """

    @staticmethod
    def _score(value: str) -> int:
        return rule("cidr", value).specificity()[0]

    def test_a_v6_block_is_scored_by_the_addresses_it_covers(self):
        # ::ffff:0:0/96 is the whole IPv4 space. Scoring the raw prefix length
        # read it as four times more precise than a /24.
        self.assertLess(self._score("::ffff:0:0/96"), self._score("192.0.2.0/24"))
        self.assertEqual(self._score("::ffff:0:0/96"), self._score("0.0.0.0/0"))

    def test_a_single_address_is_a_single_address_in_either_family(self):
        self.assertEqual(self._score("192.0.2.1/32"), self._score("2001:db8::1/128"))

    def test_tighter_still_beats_looser_within_a_family(self):
        self.assertLess(self._score("192.0.2.0/24"), self._score("192.0.2.0/28"))
        self.assertLess(self._score("2001:db8::/32"), self._score("2001:db8::/48"))

    def test_an_excluded_v4_block_is_not_outranked_by_a_mapped_v6_block(self):
        from scope_guard.decide import OUT_OF_SCOPE, decide
        from scope_guard.scope import parse_scope

        body = (
            '[rules]\nexclusions_win = false\nunlisted_is = "unknown"\n'
            '[[in_scope]]\ntype = "cidr"\nvalue = "::ffff:0:0/96"\n'
            '[[out_of_scope]]\ntype = "cidr"\nvalue = "192.0.2.0/24"\n'
        )
        scope = parse_scope(HEADER + "\n" + body)
        for raw in ("192.0.2.1", "::ffff:192.0.2.1"):
            with self.subTest(raw=raw):
                result = decide(scope, parse_target(raw))
                self.assertEqual(result.verdict, OUT_OF_SCOPE)


class TestTargetParsing(unittest.TestCase):
    def test_bare_host(self):
        parsed = parse_target("example.com")
        self.assertEqual((parsed.kind, parsed.host, parsed.path), ("host", "example.com", None))

    def test_host_with_path(self):
        parsed = parse_target("example.com/api/v1")
        self.assertEqual(parsed.path, ("api", "v1"))

    def test_url_components(self):
        parsed = parse_target("https://API.Example.com:8443/v1/../admin")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.host, "api.example.com")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.path, ("admin",))

    def test_ip_target(self):
        self.assertEqual(parse_target("192.0.2.5").kind, "ip")

    def test_bare_ipv6_target(self):
        self.assertEqual(parse_target("2001:db8::1").kind, "ip")

    def test_effective_port_falls_back_to_the_scheme_default(self):
        self.assertEqual(parse_target("https://example.com/").effective_port, 443)
        self.assertEqual(parse_target("http://example.com/").effective_port, 80)

    def test_forced_kind_overrides_detection(self):
        parsed = parse_target("com.example.app", kind="android-package")
        self.assertEqual((parsed.kind, parsed.identifier), ("android-package", "com.example.app"))

    def test_encoded_separator_raises_a_note(self):
        self.assertTrue(any("encoded separator" in n for n in parse_target("example.com/a%2Fb").notes))

    def test_a_query_or_fragment_is_carved_off_with_or_without_a_scheme(self):
        # The schemeless form used to keep the query glued to the last path
        # segment, so `example.com/api?x=1` and `https://example.com/api?x=1`
        # disagreed about the same target.
        for raw in (
            "example.com/api/v1?x=1",
            "example.com/api/v1#frag",
            "example.com/api/v1?x=1#frag",
            "https://example.com/api/v1?x=1",
        ):
            with self.subTest(raw=raw):
                parsed = parse_target(raw)
                self.assertEqual(parsed.host, "example.com")
                self.assertEqual(parsed.path, ("api", "v1"))

    def test_a_query_with_no_path_leaves_the_host_alone(self):
        parsed = parse_target("example.com?x=1")
        self.assertEqual((parsed.host, parsed.path), ("example.com", None))

    def test_a_query_survives_a_port_and_an_ipv6_literal(self):
        parsed = parse_target("example.com:8443/api?x=1")
        self.assertEqual((parsed.host, parsed.port, parsed.path), ("example.com", 8443, ("api",)))
        parsed = parse_target("[2001:db8::1]:8443/a/b?x=1")
        self.assertEqual((parsed.host, parsed.port, parsed.path), ("2001:db8::1", 8443, ("a", "b")))

    def test_an_encoded_separator_is_still_noted_behind_a_query(self):
        self.assertTrue(
            any("encoded separator" in n for n in parse_target("example.com/a%2Fb?x=1").notes)
        )

    def test_empty_target_is_rejected(self):
        with self.assertRaises(TargetError):
            parse_target("   ")

    def test_bad_port_is_rejected(self):
        with self.assertRaises(TargetError):
            parse_target("example.com:99999")

    def test_unknown_forced_kind_is_rejected(self):
        with self.assertRaises(TargetError):
            parse_target("example.com", kind="nonsense")


def load_tests(loader, tests, ignore):
    """Also run the doctests in scope_guard.rules.

    The wildcard examples in that module's docstrings are the same examples
    the README promises, so they are executed rather than trusted.
    """
    import doctest

    from scope_guard import rules

    tests.addTests(doctest.DocTestSuite(rules))
    return tests


if __name__ == "__main__":
    unittest.main()


class TestHostnameValidation(unittest.TestCase):
    """The host check allowlists rather than blocklists.

    It used to reject `*`, `/` and `\\` by name, which left `@`, `?`, `%`, `:`
    and a literal space through. Those were accepted as *hostnames* and then
    reported out-of-scope -- fail-closed, but silently, when the real answer is
    that the entry is an authoring mistake.
    """

    def test_a_host_that_is_not_a_hostname_is_rejected(self):
        for value in (
            "user@example.com",
            "example.com?x=1",
            "example.com#frag",
            "example.com:80:90",
            "example.com%2f",
            "ex ample.com",
            "-example.com",
            "example-.com",
            "exa mple.com",
            "example..com",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ScopeFileError):
                    normalise_host(value)

    def test_real_hostnames_still_normalise(self):
        cases = {
            "example.com": "example.com",
            "EXAMPLE.com": "example.com",
            "sub.example.com": "sub.example.com",
            "my-host.example.com": "my-host.example.com",
            # Service labels: _dmarc and _acme-challenge are ordinary scope
            # entries and start with an underscore.
            "_dmarc.example.com": "_dmarc.example.com",
            "_acme-challenge.example.com": "_acme-challenge.example.com",
            "xn--exmple-cua.com": "xn--exmple-cua.com",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalise_host(value), expected)

    def test_a_root_dot_is_stripped_in_every_form_idna_treats_as_one(self):
        # The strip ran before IDNA and only handled U+002E, so the ideographic
        # full stop survived it and was then mapped to a dot -- normalising
        # `example.com。` to `example.com.`, which never matched `example.com`.
        for separator in (".", "。", "．", "｡"):
            with self.subTest(separator=separator):
                self.assertEqual(normalise_host(f"example.com{separator}"), "example.com")

    def test_two_trailing_dots_are_still_an_error(self):
        with self.assertRaises(ScopeFileError):
            normalise_host("example.com..")

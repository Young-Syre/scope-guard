"""The command-line surface: exit codes, output formats, and the pipeline use."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scope_guard.cli import USAGE_EXIT, main

from .helpers import EXAMPLES, HEADER

RULES_SCOPE = str(EXAMPLES / "primacy-of-rules.toml")
IMPACT_SCOPE = str(EXAMPLES / "primacy-of-impact.toml")
BROKEN_SCOPE = str(EXAMPLES / "broken-scope.toml")


def run(argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
    """Run the CLI in-process and capture its streams."""
    out, err = io.StringIO(), io.StringIO()
    if stdin is not None:
        import sys

        original = sys.stdin
        sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main(argv)
            except SystemExit as exc:
                # argparse exits directly for --help and --version.
                code = exc.code if isinstance(exc.code, int) else 0
    finally:
        if stdin is not None:
            import sys

            sys.stdin = original
    return code, out.getvalue(), err.getvalue()


class TestCheckExitCodes(unittest.TestCase):
    def test_in_scope_exits_zero(self):
        code, out, _ = run(["check", "api.meridianpay.example", "--scope", RULES_SCOPE])
        self.assertEqual(code, 0)
        self.assertIn("IN-SCOPE", out)

    def test_out_of_scope_exits_one(self):
        code, out, _ = run(["check", "a.sandbox.meridianpay.example", "--scope", RULES_SCOPE])
        self.assertEqual(code, 1)
        self.assertIn("OUT-OF-SCOPE", out)

    def test_unlisted_under_primacy_of_rules_exits_one(self):
        code, _, _ = run(["check", "unrelated.invalid", "--scope", RULES_SCOPE])
        self.assertEqual(code, 1)

    def test_unknown_exits_two(self):
        code, out, _ = run(["check", "unlisted.invalid", "--scope", IMPACT_SCOPE])
        self.assertEqual(code, 2)
        self.assertIn("UNKNOWN", out)

    def test_an_unreadable_scope_file_exits_three(self):
        code, _, err = run(["check", "example.com", "--scope", "/nonexistent.toml"])
        self.assertEqual(code, USAGE_EXIT)
        self.assertIn("scope file error", err)

    def test_an_unparseable_target_exits_three(self):
        code, _, err = run(["check", "example.com:999999", "--scope", RULES_SCOPE])
        self.assertEqual(code, USAGE_EXIT)
        self.assertIn("port out of range", err)

    def test_no_command_prints_help_and_exits_three(self):
        code, out, _ = run([])
        self.assertEqual(code, USAGE_EXIT)
        self.assertIn("usage: scope-guard", out)

    def test_the_four_exit_codes_are_documented_in_help(self):
        code, out, _ = run(["check", "--help"])
        self.assertEqual(code, 0)
        for line in ("0  in-scope", "1  out-of-scope", "2  unknown", f"{USAGE_EXIT}  usage error"):
            self.assertIn(line, out)

    def test_help_states_that_nothing_is_contacted(self):
        _, out, _ = run(["--help"])
        self.assertIn("no network requests", out)


class TestCheckOutput(unittest.TestCase):
    def test_the_deciding_rule_is_printed(self):
        _, out, _ = run(["check", "api.meridianpay.example", "--scope", RULES_SCOPE])
        self.assertIn("in_scope[1] wildcard = '*.meridianpay.example'", out)

    def test_explain_prints_the_decision_tree(self):
        _, out, _ = run(
            ["check", "https://checkout.meridianpay.example/webhooks", "--scope", RULES_SCOPE,
             "--explain"]
        )
        self.assertIn("decision tree", out)
        self.assertIn("exclusions_win is true", out)
        self.assertIn("specificity", out)

    def test_json_output_is_machine_readable(self):
        code, out, _ = run(
            ["check", "api.meridianpay.example", "--scope", RULES_SCOPE, "--json"]
        )
        payload = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(payload["verdict"], "in-scope")
        self.assertEqual(payload["exit_code"], 0)
        self.assertEqual(payload["deciding_rules"][0]["value"], "*.meridianpay.example")

    def test_severity_cap_is_surfaced(self):
        _, out, _ = run(
            ["check", "https://checkout.meridianpay.example/pay", "--scope", RULES_SCOPE]
        )
        self.assertIn("max severity critical", out)

    def test_quiet_prints_nothing_but_still_exits_correctly(self):
        code, out, _ = run(
            ["check", "a.sandbox.meridianpay.example", "--scope", RULES_SCOPE, "--quiet"]
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_forced_type_is_honoured(self):
        code, _, _ = run(
            ["check", "example.meridianpay.wallet", "--scope", RULES_SCOPE,
             "--type", "android-package"]
        )
        self.assertEqual(code, 0)

    def test_without_the_forced_type_it_is_read_as_a_hostname(self):
        code, _, _ = run(["check", "example.meridianpay.wallet", "--scope", RULES_SCOPE])
        self.assertEqual(code, 1)


class TestAdversarialTargetsEndToEnd(unittest.TestCase):
    """The cases that cost people submissions, run through the real CLI."""

    CASES = (
        ("meridianpay.example", 0),
        ("api.meridianpay.example", 0),
        ("MERIDIANPAY.example.", 0),
        ("notmeridianpay.example", 1),
        ("meridianpay.example.evil.invalid", 1),
        ("https://meridianpay.example/legal/terms", 1),
        ("https://meridianpay.example/legalese", 0),
        ("https://meridianpay.example/api/../legal", 1),
        ("https://meridianpay.example/api/%2e%2e/legal", 1),
        ("203.0.113.42", 0),
        ("203.0.113.1", 1),
        ("::ffff:203.0.113.42", 0),
        ("::ffff:203.0.113.1", 1),
        ("2001:db8:bf::1", 0),
        ("198.51.100.1", 1),
        ("http://checkout.meridianpay.example/pay", 1),
        ("https://checkout.meridianpay.example/pay", 0),
        ("https://checkout.meridianpay.example/webhooks/stripe", 1),
    )

    def test_each_case(self):
        for raw_target, expected in self.CASES:
            with self.subTest(target=raw_target):
                code, _, err = run(["check", raw_target, "--scope", RULES_SCOPE, "--quiet"])
                self.assertEqual(code, expected, err)


class TestBatch(unittest.TestCase):
    TARGETS = """
# a recon list, with comments and blanks

api.meridianpay.example
meridianpay.example
a.sandbox.meridianpay.example
unrelated.invalid
203.0.113.42
"""

    def test_csv_is_the_default(self):
        code, out, _ = run(["batch", "-", "--scope", RULES_SCOPE], stdin=self.TARGETS)
        self.assertEqual(code, 0)
        rows = list(csv.DictReader(io.StringIO(out)))
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["target"], "api.meridianpay.example")
        self.assertEqual(rows[0]["verdict"], "in-scope")
        self.assertEqual(rows[2]["verdict"], "out-of-scope")
        self.assertIn("sandbox", rows[2]["rule_value"])
        self.assertEqual(rows[3]["deciding_rule"], "")

    def test_plain_with_only_in_is_the_pipeline_filter(self):
        code, out, _ = run(
            ["batch", "-", "--scope", RULES_SCOPE, "--format", "plain", "--only", "in"],
            stdin=self.TARGETS,
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            out.split(),
            ["api.meridianpay.example", "meridianpay.example", "203.0.113.42"],
        )

    def test_only_accepts_several_verdicts(self):
        _, out, _ = run(
            ["batch", "-", "--scope", IMPACT_SCOPE, "--format", "plain", "--only", "out,unknown"],
            stdin="heliosresearch.example\nmail.heliosresearch.example\nunlisted.invalid\n",
        )
        self.assertEqual(out.split(), ["mail.heliosresearch.example", "unlisted.invalid"])

    def test_json_output(self):
        _, out, _ = run(
            ["batch", "-", "--scope", RULES_SCOPE, "--format", "json"], stdin=self.TARGETS
        )
        payload = json.loads(out)
        self.assertEqual(len(payload), 5)
        self.assertEqual(payload[0]["verdict"], "in-scope")
        self.assertIn("trace", payload[0])

    def test_strict_fails_when_anything_is_not_in_scope(self):
        code, _, _ = run(
            ["batch", "-", "--scope", RULES_SCOPE, "--strict", "--format", "plain"],
            stdin=self.TARGETS,
        )
        self.assertEqual(code, 1)

    def test_strict_passes_when_everything_is_in_scope(self):
        code, _, _ = run(
            ["batch", "-", "--scope", RULES_SCOPE, "--strict", "--format", "plain"],
            stdin="api.meridianpay.example\nmeridianpay.example\n",
        )
        self.assertEqual(code, 0)

    def test_an_unparseable_target_is_reported_per_row_not_fatal(self):
        code, out, _ = run(
            ["batch", "-", "--scope", RULES_SCOPE], stdin="api.meridianpay.example\nhost:bad\n"
        )
        self.assertEqual(code, 0)
        rows = list(csv.DictReader(io.StringIO(out)))
        self.assertEqual(rows[1]["verdict"], "error")
        self.assertIn("invalid port", rows[1]["reason"])

    def test_reading_from_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text(self.TARGETS, encoding="utf-8")
            code, out, _ = run(["batch", str(path), "--scope", RULES_SCOPE, "--format", "plain"])
            self.assertEqual(code, 0)
            self.assertEqual(len(out.split()), 5)

    def test_writing_to_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verdicts.csv"
            code, out, _ = run(
                ["batch", "-", "--scope", RULES_SCOPE, "-o", str(path)], stdin=self.TARGETS
            )
            self.assertEqual(code, 0)
            self.assertEqual(out, "")
            rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"))))
            self.assertEqual(len(rows), 5)

    def test_a_missing_target_list_exits_three(self):
        code, _, err = run(["batch", "/nonexistent/targets.txt", "--scope", RULES_SCOPE])
        self.assertEqual(code, USAGE_EXIT)
        self.assertIn("cannot read target list", err)

    def test_an_unknown_only_verdict_exits_three(self):
        code, _, err = run(["batch", "-", "--scope", RULES_SCOPE, "--only", "maybe"], stdin="x\n")
        self.assertEqual(code, USAGE_EXIT)
        self.assertIn("unknown verdict", err)


class TestLintCommand(unittest.TestCase):
    def test_a_clean_file_passes(self):
        code, out, _ = run(["lint", RULES_SCOPE])
        self.assertEqual(code, 0)
        self.assertIn("0 error(s)", out)

    def test_the_broken_file_fails(self):
        code, out, _ = run(["lint", BROKEN_SCOPE])
        self.assertEqual(code, 1)
        for check in ("SG001", "SG002", "SG003", "SG004", "SG005",
                      "SG006", "SG007", "SG008", "SG009", "SG010"):
            self.assertIn(check, out)

    def test_json_output(self):
        code, out, _ = run(["lint", BROKEN_SCOPE, "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(len(payload["counts"]), 3)
        self.assertGreaterEqual(payload["counts"]["error"], 1)
        self.assertEqual(payload["entries"], 12)

    def test_strict_fails_a_file_that_only_warns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "warn.toml"
            path.write_text(
                HEADER
                + '\n[[in_scope]]\ntype = "wildcard"\nvalue = "*.example.com"\n',
                encoding="utf-8",
            )
            self.assertEqual(run(["lint", str(path)])[0], 0)
            self.assertEqual(run(["lint", str(path), "--strict"])[0], 1)

    def test_max_age_days_is_configurable(self):
        self.assertEqual(run(["lint", RULES_SCOPE, "--max-age-days", "100000"])[0], 0)

    def test_a_negative_max_age_is_rejected(self):
        code, _, err = run(["lint", RULES_SCOPE, "--max-age-days", "-1"])
        self.assertEqual(code, USAGE_EXIT)
        self.assertIn("must not be negative", err)

    def test_positional_and_flag_together_are_rejected(self):
        code, _, err = run(["lint", RULES_SCOPE, "--scope", IMPACT_SCOPE])
        self.assertEqual(code, USAGE_EXIT)
        self.assertIn("not both", err)


class TestInitCommand(unittest.TestCase):
    def test_the_scaffold_is_valid_toml_and_loads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.toml"
            code, out, _ = run(["init", str(path)])
            self.assertEqual(code, 0)
            self.assertIn("wrote", out)
            text = path.read_text(encoding="utf-8")
            parsed = tomllib.loads(text)
            self.assertIn("program", parsed)
            self.assertGreater(len(parsed["in_scope"]), 0)
            self.assertGreater(len(parsed["out_of_scope"]), 0)

    def test_the_scaffold_lints_without_errors_or_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.toml"
            run(["init", str(path)])
            code, out, _ = run(["lint", str(path)])
            self.assertEqual(code, 0)
            self.assertIn("0 error(s), 0 warning(s)", out)

    def test_the_scaffold_answers_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.toml"
            run(["init", str(path)])
            self.assertEqual(run(["check", "a.example.com", "--scope", str(path), "--quiet"])[0], 0)
            self.assertEqual(run(["check", "example.com", "--scope", str(path), "--quiet"])[0], 0)
            self.assertEqual(
                run(["check", "a.staging.example.com", "--scope", str(path), "--quiet"])[0], 1
            )
            self.assertEqual(
                run(["check", "https://example.com/admin", "--scope", str(path), "--quiet"])[0], 1
            )

    def test_it_refuses_to_clobber_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.toml"
            self.assertEqual(run(["init", str(path)])[0], 0)
            code, _, err = run(["init", str(path)])
            self.assertEqual(code, USAGE_EXIT)
            self.assertIn("already exists", err)
            self.assertEqual(run(["init", str(path), "--force"])[0], 0)

    def test_it_can_write_to_stdout(self):
        code, out, _ = run(["init", "-"])
        self.assertEqual(code, 0)
        self.assertIn("[program]", out)
        self.assertIn("exclusions_win = true", out)


class TestScopeFileResolution(unittest.TestCase):
    def test_the_environment_variable_is_used(self):
        import os

        original = os.environ.get("SCOPE_GUARD_SCOPE")
        os.environ["SCOPE_GUARD_SCOPE"] = RULES_SCOPE
        try:
            self.assertEqual(run(["check", "api.meridianpay.example", "--quiet"])[0], 0)
        finally:
            if original is None:
                del os.environ["SCOPE_GUARD_SCOPE"]
            else:
                os.environ["SCOPE_GUARD_SCOPE"] = original

    def test_a_helpful_message_when_nothing_is_configured(self):
        import os

        original = os.environ.pop("SCOPE_GUARD_SCOPE", None)
        cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                code, _, err = run(["check", "example.com"])
                self.assertEqual(code, USAGE_EXIT)
                self.assertIn("scope-guard init", err)
        finally:
            os.chdir(cwd)
            if original is not None:
                os.environ["SCOPE_GUARD_SCOPE"] = original


if __name__ == "__main__":
    unittest.main()

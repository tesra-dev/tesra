"""Tests for scripts/asvs_gate.py."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asvs_gate  # noqa: E402

ASVS = {"V3.3.1": "1", "V6.2.9": "2", "V6.8.3": "2", "V7.2.4": "1"}
COLUMNS = ["req_id", "level", "chapter", "section", "scope", "status", "implementation", "tests", "notes", "requirement"]
SESSION_TEST = "v7_2_4_new_session_token_on_login"


def base_rows() -> list[dict[str, str]]:
    return [
        {"req_id": "V3.3.1", "level": "1", "scope": "kit", "status": "planned"},
        {"req_id": "V6.2.9", "level": "2", "scope": "kit", "status": "planned"},
        {"req_id": "V6.8.3", "level": "2", "scope": "n/a", "status": "n/a", "notes": "SAML is not supported"},
        {"req_id": "V7.2.4", "level": "1", "scope": "kit", "status": "planned"},
    ]


def mark_verified(rows: list[dict[str, str]], req_id: str, tests: str) -> list[dict[str, str]]:
    for row in rows:
        if row["req_id"] == req_id:
            row["status"] = "verified"
            row["tests"] = tests
    return rows


def junit(cases: dict[str, str]) -> str:
    """Build a JUnit report from {testcase name: outcome}; outcome is "pass" or a child element name."""
    body = "".join(
        f'<testcase name="{name}" classname="tesra-auth-core">{"" if outcome == "pass" else f"<{outcome}/>"}</testcase>'
        for name, outcome in cases.items()
    )
    return f'<?xml version="1.0"?><testsuites><testsuite name="t">{body}</testsuite></testsuites>'


class GateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.asvs_path = self.dir / "asvs.json"
        self.asvs_path.write_text(json.dumps({"requirements": [{"req_id": k, "L": v} for k, v in ASVS.items()]}))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_gate(self, rows, reports=(), require_level=0, matrix=None):
        if matrix is None:
            matrix = self.dir / "matrix.csv"
            with matrix.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=COLUMNS)
                writer.writeheader()
                for row in rows:
                    writer.writerow({column: row.get(column, "") for column in COLUMNS})
        argv = ["--matrix", str(matrix), "--asvs", str(self.asvs_path), "--require-level", str(require_level)]
        for index, report in enumerate(reports):
            path = self.dir / f"junit-{index}.xml"
            path.write_text(report)
            argv += ["--junit", str(path)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = asvs_gate.main(argv)
        return code, out.getvalue()

    def assert_passes(self, rows, **kwargs):
        code, output = self.run_gate(rows, **kwargs)
        self.assertEqual(code, 0, output)
        return output

    def assert_fails(self, rows, message, **kwargs):
        code, output = self.run_gate(rows, **kwargs)
        self.assertEqual(code, 1, output)
        self.assertIn(message, output)


class IntegrityTests(GateTestCase):
    def test_clean_matrix_passes(self):
        output = self.assert_passes(base_rows())
        self.assertIn("L1 0/2, L2 0/1, L3 0/0", output)

    def test_missing_requirement_fails(self):
        self.assert_fails(base_rows()[1:], "V3.3.1: missing from the matrix")

    def test_duplicate_row_fails(self):
        rows = base_rows()
        rows.append(dict(rows[0]))
        self.assert_fails(rows, "V3.3.1: duplicate of line 2")

    def test_unknown_requirement_fails(self):
        rows = [*base_rows(), {"req_id": "V99.1.1", "level": "1", "scope": "kit", "status": "planned"}]
        self.assert_fails(rows, "V99.1.1: not an ASVS 5.0 requirement")

    def test_level_mismatch_fails(self):
        rows = base_rows()
        rows[0]["level"] = "2"
        self.assert_fails(rows, "level is '2', ASVS says '1'")

    def test_unknown_scope_fails(self):
        rows = base_rows()
        rows[0]["scope"] = "maybe"
        self.assert_fails(rows, "unknown scope 'maybe'")

    def test_status_must_fit_scope(self):
        rows = base_rows()
        rows[0]["status"] = "n/a"
        self.assert_fails(rows, "status 'n/a' isn't allowed for scope 'kit'")

    def test_na_rows_need_a_note(self):
        rows = base_rows()
        rows[2]["notes"] = ""
        self.assert_fails(rows, "n/a rows need a note")

    def test_missing_columns_fail_cleanly(self):
        matrix = self.dir / "bad.csv"
        matrix.write_text("req_id,level\nV3.3.1,1\n")
        code, output = self.run_gate([], matrix=matrix)
        self.assertEqual(code, 1, output)
        self.assertIn("missing columns", output)


class EvidenceTests(GateTestCase):
    def test_verified_row_with_passing_test_passes(self):
        rows = mark_verified(base_rows(), "V7.2.4", SESSION_TEST)
        output = self.assert_passes(rows, reports=[junit({f"session::tests::{SESSION_TEST}": "pass"})])
        self.assertIn("L1 1/2", output)

    def test_verified_row_without_tests_fails(self):
        self.assert_fails(mark_verified(base_rows(), "V7.2.4", ""), "verified rows must list the tests")

    def test_verified_test_missing_from_reports_fails(self):
        rows = mark_verified(base_rows(), "V7.2.4", SESSION_TEST)
        cookie_test = "v3_3_1_session_cookie_is_secure"
        rows[0]["tests"] = cookie_test
        self.assert_fails(
            rows,
            f"{SESSION_TEST} is missing from the test reports",
            reports=[junit({cookie_test: "pass"})],
        )

    def test_without_reports_structure_is_checked_but_evidence_is_not(self):
        rows = mark_verified(base_rows(), "V7.2.4", SESSION_TEST)
        output = self.assert_passes(rows)
        self.assertIn("checking structure only", output)

    def test_without_reports_structure_problems_still_fail(self):
        rows = mark_verified(base_rows()[1:], "V7.2.4", SESSION_TEST)
        self.assert_fails(rows, "V3.3.1: missing from the matrix")

    def test_failed_error_skipped_and_flaky_tests_fail(self):
        for outcome in ("failure", "error", "skipped", "flakyFailure", "rerunFailure"):
            with self.subTest(outcome=outcome):
                rows = mark_verified(base_rows(), "V7.2.4", SESSION_TEST)
                self.assert_fails(rows, f"{SESSION_TEST} did not pass", reports=[junit({SESSION_TEST: outcome})])

    def test_a_failure_in_any_report_fails(self):
        rows = mark_verified(base_rows(), "V7.2.4", SESSION_TEST)
        reports = [junit({SESSION_TEST: "pass"}), junit({SESSION_TEST: "failure"})]
        self.assert_fails(rows, "did not pass", reports=reports)

    def test_failing_test_on_unverified_row_fails(self):
        rows = base_rows()
        rows[3]["tests"] = SESSION_TEST
        self.assert_fails(rows, "did not pass", reports=[junit({SESSION_TEST: "failure"})])

    def test_test_must_belong_to_its_row(self):
        rows = mark_verified(base_rows(), "V3.3.1", SESSION_TEST)
        self.assert_fails(rows, f"{SESSION_TEST} belongs to V7.2.4", reports=[junit({SESSION_TEST: "pass"})])

    def test_malformed_test_id_fails(self):
        for bad in ("session_rotates", "v7_2_4", "v7_2_4_trailing_", "V7_2_4_upper"):
            with self.subTest(test_id=bad):
                rows = base_rows()
                rows[3]["tests"] = bad
                self.assert_fails(rows, "isn't a valid test ID")

    def test_unlisted_asvs_test_in_reports_fails(self):
        message = f"{SESSION_TEST}: in the test reports but not listed on V7.2.4's row"
        self.assert_fails(base_rows(), message, reports=[junit({SESSION_TEST: "pass"})])

    def test_tests_without_asvs_ids_are_ignored(self):
        self.assert_passes(base_rows(), reports=[junit({"parses_empty_cookie_header": "pass"})])

    def test_several_tests_on_one_row(self):
        second = "v7_2_4_old_session_token_rejected"
        rows = mark_verified(base_rows(), "V7.2.4", f"{SESSION_TEST}; {second}")
        self.assert_passes(rows, reports=[junit({SESSION_TEST: "pass", second: "pass"})])

    def test_malformed_report_fails_cleanly(self):
        code, output = self.run_gate(base_rows(), reports=["<testsuites><testcase"])
        self.assertEqual(code, 1, output)
        self.assertIn("asvs-gate:", output)


class CoverageTests(GateTestCase):
    def test_require_level_needs_kit_rows_verified(self):
        self.assert_fails(base_rows(), "L1 kit requirement is 'planned'; --require-level 1", require_level=1)

    def test_require_level_ignores_higher_levels_and_other_scopes(self):
        cookie_test = "v3_3_1_session_cookie_is_secure"
        rows = mark_verified(mark_verified(base_rows(), "V3.3.1", cookie_test), "V7.2.4", SESSION_TEST)
        self.assert_passes(rows, reports=[junit({cookie_test: "pass", SESSION_TEST: "pass"})], require_level=1)


class RepositoryMatrixTests(unittest.TestCase):
    def test_repository_matrix_is_consistent(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = asvs_gate.main([])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("checking structure only", out.getvalue())


if __name__ == "__main__":
    unittest.main()

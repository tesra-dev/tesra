#!/usr/bin/env python3
"""Check the ASVS traceability matrix against ASVS and the test reports.

Checks, in order:

1. Integrity: every upstream ASVS requirement appears exactly once, with the
   upstream level and a known scope.
2. Consistency: each status is allowed for its scope, n/a rows explain why, and
   each listed test ID names the requirement on its row.
3. Evidence: `verified` rows list tests, all of which appear in the JUnit
   reports, and no listed test that appears in a report failed.
4. Orphans: every ASVS-named test in the reports is listed in the matrix.
5. Coverage: with --require-level N, every `kit` row at level N or lower is
   `verified`.

Test IDs look like `v7_2_4_new_session_token_on_login` for requirement V7.2.4.
Uses only the Python standard library. Exits 1 on any problem.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MATRIX = ROOT / "security" / "asvs-matrix.csv"
DEFAULT_ASVS = ROOT / "standards" / "owasp-asvs-5.0.0" / "asvs-5.0.0.flat.json"

ALLOWED_STATUS = {
    "kit": {"planned", "implemented", "verified"},
    "shared": {"planned", "implemented", "verified"},
    "triage": {"needs-review"},
    "n/a": {"n/a"},
    "app": {"out-of-scope"},
}
REQUIRED_COLUMNS = {"req_id", "level", "scope", "status", "tests", "notes"}
TEST_ID = re.compile(r"\bv(\d+)_(\d+)_(\d+)_[a-z0-9_]*[a-z0-9]\b")
# A retried test that eventually passed still counts as failed: security tests must be deterministic.
NOT_PASSED = {"failure", "error", "skipped", "flakyFailure", "flakyError", "rerunFailure", "rerunError"}


class GateError(Exception):
    """An input file can't be used."""


@dataclass(frozen=True)
class Row:
    line: int
    req_id: str
    level: str
    scope: str
    status: str
    tests: tuple[str, ...]
    notes: str


def requirement_for(test_id: str) -> str:
    match = TEST_ID.fullmatch(test_id)
    if match is None:
        raise ValueError(f"not an ASVS test ID: {test_id!r}")
    return "V{}.{}.{}".format(*match.groups())


def sort_key(req_id: str) -> tuple[int, ...]:
    return tuple(int(part) for part in req_id.lstrip("V").split("."))


def load_asvs(path: Path) -> dict[str, str]:
    """Return {requirement ID: level} from the ASVS flat JSON export."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return {req["req_id"]: str(req["L"]) for req in data["requirements"]}


def load_matrix(path: Path) -> list[Row]:
    rows = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or ())
        if missing:
            raise GateError(f"{path}: missing columns {sorted(missing)}")
        for record in reader:
            field = lambda name: (record.get(name) or "").strip()  # noqa: E731
            rows.append(
                Row(
                    line=reader.line_num,
                    req_id=field("req_id"),
                    level=field("level"),
                    scope=field("scope"),
                    status=field("status"),
                    tests=tuple(t for t in re.split(r"[\s;,]+", field("tests")) if t),
                    notes=field("notes"),
                )
            )
    return rows


def load_reports(paths: list[Path]) -> dict[str, bool]:
    """Return {ASVS test ID: passed} from JUnit XML reports produced by our CI."""
    results: dict[str, bool] = {}
    for path in paths:
        for case in ET.parse(path).getroot().iter("testcase"):
            passed = not any(child.tag in NOT_PASSED for child in case)
            for match in TEST_ID.finditer(case.get("name", "")):
                test_id = match.group(0)
                results[test_id] = results.get(test_id, True) and passed
    return results


def check(rows: list[Row], asvs: dict[str, str], results: dict[str, bool], require_level: int = 0) -> list[str]:
    problems: list[str] = []
    first_line: dict[str, int] = {}

    for row in rows:
        where = f"line {row.line} {row.req_id or '(no req_id)'}"
        if row.req_id in first_line:
            problems.append(f"{where}: duplicate of line {first_line[row.req_id]}")
            continue
        first_line[row.req_id] = row.line

        if row.req_id not in asvs:
            problems.append(f"{where}: not an ASVS 5.0 requirement")
            continue
        level = asvs[row.req_id]
        if row.level != level:
            problems.append(f"{where}: level is {row.level!r}, ASVS says {level!r}")
        if row.scope not in ALLOWED_STATUS:
            problems.append(f"{where}: unknown scope {row.scope!r}")
            continue
        if row.status not in ALLOWED_STATUS[row.scope]:
            allowed = ", ".join(sorted(ALLOWED_STATUS[row.scope]))
            problems.append(f"{where}: status {row.status!r} isn't allowed for scope {row.scope!r} (use {allowed})")
        if row.scope == "n/a" and not row.notes:
            problems.append(f"{where}: n/a rows need a note saying why")

        for test_id in row.tests:
            if not TEST_ID.fullmatch(test_id):
                problems.append(
                    f"{where}: {test_id!r} isn't a valid test ID (expected v<chapter>_<section>_<requirement>_<description>)"
                )
            elif requirement_for(test_id) != row.req_id:
                problems.append(f"{where}: {test_id} belongs to {requirement_for(test_id)}")
            elif test_id in results and not results[test_id]:
                problems.append(f"{where}: {test_id} did not pass")
            elif row.status == "verified" and test_id not in results:
                problems.append(f"{where}: {test_id} is missing from the test reports")

        if row.status == "verified" and not row.tests:
            problems.append(f"{where}: verified rows must list the tests that prove them")
        if require_level and row.scope == "kit" and int(level) <= require_level and row.status != "verified":
            problems.append(
                f"{where}: L{level} kit requirement is {row.status!r}; --require-level {require_level} needs 'verified'"
            )

    for req_id in sorted(asvs.keys() - first_line.keys(), key=sort_key):
        problems.append(f"{req_id}: missing from the matrix")

    listed = {test_id for row in rows for test_id in row.tests}
    for test_id in sorted(results.keys() - listed):
        problems.append(f"{test_id}: in the test reports but not listed on {requirement_for(test_id)}'s row")
    return problems


def summary(rows: list[Row], asvs: dict[str, str]) -> str:
    total: Counter[str] = Counter()
    verified: Counter[str] = Counter()
    for row in rows:
        if row.scope == "kit" and row.req_id in asvs:
            total[asvs[row.req_id]] += 1
            verified[asvs[row.req_id]] += row.status == "verified"
    return "kit requirements verified: " + ", ".join(f"L{lvl} {verified[lvl]}/{total[lvl]}" for lvl in ("1", "2", "3"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the ASVS traceability matrix against ASVS and the test reports.")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--asvs", type=Path, default=DEFAULT_ASVS)
    parser.add_argument("--junit", type=Path, action="append", default=[], metavar="REPORT", help="JUnit XML report (repeatable)")
    parser.add_argument(
        "--require-level", type=int, choices=(0, 1, 2, 3), default=0, help="every kit requirement up to this level must be verified"
    )
    args = parser.parse_args(argv)

    try:
        asvs = load_asvs(args.asvs)
        rows = load_matrix(args.matrix)
        results = load_reports(args.junit)
    except (OSError, ValueError, KeyError, ET.ParseError, GateError) as error:
        print(f"asvs-gate: {error}", file=sys.stderr)
        return 1

    problems = check(rows, asvs, results, args.require_level)
    for problem in problems:
        print(f"asvs-gate: {problem}", file=sys.stderr)
    print(summary(rows, asvs))
    if problems:
        print(f"asvs-gate: FAILED with {len(problems)} problem(s)", file=sys.stderr)
        return 1
    print("asvs-gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Summarize a nextest JUnit report by wall time: slowest tests and per-binary totals.

nextest lists every trial in one process and runs each in another, so the JUnit `time`
attribute is real per-test wall time, contention included, not an in-process stopwatch. That
makes this the right lens for "what is the suite's critical path", since the whole run cannot
finish faster than its slowest single test.

Usage: profile_junit.py <junit.xml> [top_n]
"""

import sys
import xml.etree.ElementTree as ET
from collections import defaultdict


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: profile_junit.py <junit.xml> [top_n]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    top_n = int(sys.argv[2]) if len(sys.argv) > 2 else 25

    root = ET.parse(path).getroot()
    tests = []
    per_bin_sum: dict[str, float] = defaultdict(float)
    per_bin_n: dict[str, int] = defaultdict(int)
    for suite in root.iter("testsuite"):
        binary = suite.get("name", "?")
        for case in suite.iter("testcase"):
            t = float(case.get("time", 0.0))
            tests.append((t, binary, case.get("name", "?")))
            per_bin_sum[binary] += t
            per_bin_n[binary] += 1

    if not tests:
        print("no testcases in report", file=sys.stderr)
        return 1

    tests.sort(reverse=True)
    total = sum(t for t, _, _ in tests)

    print(f"=== {len(tests)} tests, {total:.1f}s total CPU-work ===\n")
    print(f"top {top_n} slowest tests (each is a hard floor on wall time):")
    for t, binary, name in tests[:top_n]:
        print(f"  {t:7.2f}s  {binary}::{name}")

    print("\nper-binary totals (sum drives wall time once divided by its thread cap):")
    ranked = sorted(per_bin_sum.items(), key=lambda kv: kv[1], reverse=True)
    for binary, s in ranked:
        n = per_bin_n[binary]
        print(f"  {s:7.1f}s  n={n:<4d} mean={s / n:5.2f}s  {binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

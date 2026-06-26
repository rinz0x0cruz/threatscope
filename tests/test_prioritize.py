"""Offline unit tests for the prioritization engine.

Run with either:
    python -m threatscope selftest
    python tests/test_prioritize.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatscope.prioritize import score_cve, tier_for, enrich_and_sort  # noqa: E402


def run():
    failures = [0]

    def check(cond, msg):
        print(("PASS  " if cond else "FAIL  ") + msg)
        if not cond:
            failures[0] += 1

    _, t, _ = score_cve(9.8, 0.97, True)
    check(t == "Critical", "KEV + high CVSS/EPSS -> Critical")

    s, _, _ = score_cve(2.0, 0.0, True)
    check(s >= 80, "KEV floor enforced for low-CVSS exploited bug")

    _, t, _ = score_cve(4.0, 0.02, False)
    check(t in ("Low", "Medium"), "low CVSS + low EPSS -> Low/Medium")

    s, _, _ = score_cve(None, None, False)
    check(s == 0.0, "no data -> score 0")

    check(tier_for(80) == "Critical", "score 80 -> Critical")
    check(tier_for(59.9) == "Medium", "score 59.9 -> Medium")

    rows = [{"cve_id": "A", "cvss": 5, "epss": 0.1, "in_kev": False},
            {"cve_id": "B", "cvss": 9, "epss": 0.9, "in_kev": True}]
    enrich_and_sort(rows)
    check(rows[0]["cve_id"] == "B", "enrich_and_sort orders highest risk first")

    print("\n%d failure(s)" % failures[0])
    return 1 if failures[0] else 0


if __name__ == "__main__":
    sys.exit(run())

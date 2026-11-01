"""Self-tests for run_rule_tests.py: it must catch bad rules, not just pass.

Run: python -I -m unittest discover -s scripts
"""

import io
import json
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_rule_tests as rt  # noqa: E402

RULE = "okta_mfa_push_fatigue"


def push(user, ingested):
    return {"event": {"dataset": "okta.system", "ingested": ingested,
                      "action": "system.push.send_factor_verify_push"},
            "user": {"name": user}}


class Matching(unittest.TestCase):
    def setUp(self):
        self.rule = rt.load_condition(rt.DETECTIONS / "okta" / f"{RULE}.yml",
                                      rt.DETECTIONS / "pipelines" / "okta-ecs.yml")

    def test_push_event_matches(self):
        self.assertTrue(rt.matches(self.rule, push("a", "2026-01-01T00:00:00Z")))

    def test_case_sensitive_like_keyword_fields(self):
        e = push("a", "2026-01-01T00:00:00Z")
        e["event"]["action"] = e["event"]["action"].upper()
        self.assertFalse(rt.matches(self.rule, e))

    def test_other_dataset_does_not_match(self):
        e = push("a", "2026-01-01T00:00:00Z")
        e["event"]["dataset"] = "other"
        self.assertFalse(rt.matches(self.rule, e))

    def test_flat_dotted_keys(self):
        e = {"event.dataset": "okta.system",
             "event.action": "system.push.send_factor_verify_push"}
        self.assertTrue(rt.matches(self.rule, e))


class Counting(unittest.TestCase):
    def count(self, events):
        return rt.fires(events, ["user.name"], 5, timedelta(minutes=6),
                        "event.ingested", "t")

    def test_threshold_inside_window_fires(self):
        events = [push("a", f"2026-01-01T00:0{m}:00Z") for m in range(5)]
        self.assertEqual(self.count(events), [("a",)])

    def test_threshold_spread_past_window_does_not(self):
        events = [push("a", f"2026-01-01T00:{m}0:00Z") for m in range(5)]
        self.assertEqual(self.count(events), [])

    def test_missing_group_field_is_dropped(self):
        events = [push(None, f"2026-01-01T00:0{m}:00Z") for m in range(5)]
        self.assertEqual(self.count(events), [])

    def test_unknown_rule_type_is_an_error(self):
        with self.assertRaises(rt.RuleError):
            rt.load_counting({"type": "eql", "from": "now-6m"}, "t")


class EndToEnd(unittest.TestCase):
    """Each test breaks a temporary copy of the repo's rule files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ("okta", "pipelines"):
            shutil.copytree(rt.DETECTIONS / name, self.root / name)
        self.cases_path = self.root / "okta" / "tests" / f"{RULE}.cases.json"
        self.cases = json.loads(self.cases_path.read_text(encoding="utf-8"))

    def run_main(self):
        self.cases_path.write_text(json.dumps(self.cases), encoding="utf-8")
        out = io.StringIO()
        return rt.main([], root=self.root, out=out), out.getvalue()

    def test_real_rule_passes(self):
        self.assertEqual(self.run_main()[0], 0)

    def test_wrong_expectation_fails(self):
        self.cases["cases"][1]["expect"] = "fire"  # a quiet case, now claimed to fire
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_malformed_cases_file_is_an_error(self):
        self.cases_path.write_text("{not json", encoding="utf-8")
        out = io.StringIO()
        self.assertEqual(rt.main([], root=self.root, out=out), 2)

    def test_mismatched_rule_id_is_an_error(self):
        self.cases["rule_id"] = "another-rule"
        self.assertEqual(self.run_main()[0], 2)

    def test_only_fire_cases_is_an_error(self):
        self.cases["cases"] = [c for c in self.cases["cases"] if c["expect"] == "fire"]
        self.assertEqual(self.run_main()[0], 2)

    def test_zero_event_case_is_skipped_not_passed(self):
        self.cases["cases"].append({"name": "gap", "expect": "fire", "events": []})
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("1 skipped", out)
        self.assertIn("5/5 cases passed", out)


if __name__ == "__main__":
    unittest.main()

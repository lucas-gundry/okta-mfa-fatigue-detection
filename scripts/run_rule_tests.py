"""Run every detection rule's test cases and fail loudly on any mismatch.

For each rule <folder>/<name>.yml there must be:
  <folder>/<name>.json              the deployed Elastic rule
  <folder>/tests/<name>.cases.json  made-up events, each case expecting
                                    "fire" or "no_fire"

How a case is judged:
  1. The Sigma rule goes through its processing pipeline (the same one used
     to convert it for Elastic), so field names and values are the ECS ones
     the deployed query uses. Each event is matched against that logic.
  2. The deployed rule's count is applied: a threshold rule's field and
     value. A plain query rule fires on one matching event.
  3. A group fires if N matching events fall inside one lookback (the
     rule's "from", on its timestamp_override field). This is the best
     case: a real run every "interval" might split the events across two
     runs.

Matching is exact and case-sensitive, like Elastic keyword fields. Sigma
features no rule uses yet (wildcards, regex, keyword search, other
modifiers) stop the run with an error instead of being guessed.

Usage (from the repo root, with requirements.txt installed):
  python -I scripts/run_rule_tests.py

A case with no events is a known gap (nothing is logged to test). It is
reported as SKIP, counted separately, and doesn't fail the run. Only cases
with events count toward the "one fire and one no_fire case" rule.

Exit codes: 0 all cases pass, 1 a case failed, 2 a file or rule is broken.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaExists, SigmaString

DETECTIONS = Path(__file__).resolve().parent.parent

# Which pipeline converts the rules in each folder. A folder not listed here
# is an error, not a guess.
PIPELINES = {
    "okta": "okta-ecs.yml",
}


class RuleError(Exception):
    """A rule, its deployed JSON, or its cases file is broken or unsupported."""


# --- Sigma matching ---------------------------------------------------------

def load_condition(rule_path, pipeline_path):
    """Parse a Sigma rule, apply its pipeline, return one condition tree."""
    try:
        rule = SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))
        pipeline = ProcessingPipeline.from_yaml(pipeline_path.read_text(encoding="utf-8"))
        pipeline.apply(rule)
        conditions = [c.parse() for c in rule.detection.parsed_condition]
    except Exception as e:  # pySigma raises many error types
        raise RuleError(f"{rule_path.name}: Sigma parse failed: {e}") from e
    if len(conditions) != 1:
        raise RuleError(f"{rule_path.name}: expected 1 condition, got {len(conditions)}")
    return conditions[0]


def get_field(event, dotted):
    """Value at a dotted path in a nested event, or None if absent."""
    if dotted in event:  # flat keys, e.g. {"event.dataset": ...}
        return event[dotted]
    node = event
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def matches(node, event):
    """True if the event satisfies the condition tree."""
    if isinstance(node, ConditionAND):
        return all(matches(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(matches(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not matches(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        value = get_field(event, node.field)
        expected = node.value
        if isinstance(expected, SigmaExists):
            return (value is not None) == expected.exists
        if isinstance(expected, SigmaString):
            if expected.contains_special():
                raise RuleError(f"wildcards in {node.field} are not supported yet")
            values = value if isinstance(value, list) else [value]
            return str(expected) in [v for v in values if isinstance(v, str)]
        raise RuleError(f"value type {type(expected).__name__} on {node.field} is not supported yet")
    raise RuleError(f"condition type {type(node).__name__} is not supported yet")


# --- The deployed rule's count ----------------------------------------------

FROM_NOW = re.compile(r"^now-(?P<n>\d+)(?P<unit>[smh])$")
UNITS = {"s": "seconds", "m": "minutes", "h": "hours"}


def load_counting(deployed, name):
    """Return (group_by_fields, threshold, lookback, time_field) from the Elastic rule."""
    kind = deployed.get("type")
    if kind == "query":
        group_by, threshold = [], 1
    elif kind == "threshold":
        t = deployed.get("threshold") or {}
        group_by, threshold = list(t.get("field") or []), t.get("value")
    else:
        raise RuleError(f"{name}: rule type {kind!r} is not supported yet")
    if not isinstance(threshold, int) or threshold < 1:
        raise RuleError(f"{name}: bad threshold {threshold!r}")

    lookback = FROM_NOW.match(deployed.get("from", ""))
    if not lookback:
        raise RuleError(f"{name}: can't read the lookback from 'from': {deployed.get('from')!r}")
    window = timedelta(**{UNITS[lookback["unit"]]: int(lookback["n"])})
    time_field = deployed.get("timestamp_override") or "@timestamp"
    return group_by, threshold, window, time_field


def parse_time(value, name):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as e:
        raise RuleError(f"{name}: bad timestamp {value!r}") from e


def fires(matched, group_by, threshold, window, time_field, name):
    """Groups (as tuples) where `threshold` matched events fit in one window."""
    groups = defaultdict(list)
    for event in matched:
        key = tuple(get_field(event, f) for f in group_by)
        if any(k is None for k in key):
            continue  # Elastic drops events missing a group-by field
        groups[key].append(parse_time(get_field(event, time_field), name))
    firing = []
    for key, times in groups.items():
        times.sort()
        for i in range(len(times) - threshold + 1):
            if times[i + threshold - 1] - times[i] <= window:
                firing.append(key)
                break
    return firing


# --- Running the cases ------------------------------------------------------

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise RuleError(f"{path.name}: can't read JSON: {e}") from e


def run_rule(rule_path, root):
    """Run one rule's cases. Return a list of (case_name, expect, status, detail),
    where status is PASS, FAIL, or SKIP (a case with no events: a known gap)."""
    folder, name = rule_path.parent.name, rule_path.stem
    if folder not in PIPELINES:
        raise RuleError(f"{name}: no pipeline listed for folder '{folder}'")
    deployed_path = rule_path.with_suffix(".json")
    cases_path = rule_path.parent / "tests" / f"{name}.cases.json"
    for p in (deployed_path, cases_path):
        if not p.exists():
            raise RuleError(f"{name}: missing {p.relative_to(root)}")

    condition = load_condition(rule_path, root / "pipelines" / PIPELINES[folder])
    deployed = load_json(deployed_path)
    group_by, threshold, window, time_field = load_counting(deployed, name)

    suite = load_json(cases_path)
    if suite.get("rule_id") != deployed.get("rule_id"):
        raise RuleError(f"{name}: cases rule_id {suite.get('rule_id')} != deployed {deployed.get('rule_id')}")
    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuleError(f"{name}: no cases")
    for case in cases:
        if not isinstance(case.get("events"), list):
            raise RuleError(f"{name}: case {case.get('name')!r} has no events list")
    expects = {c.get("expect") for c in cases}
    if not expects <= {"fire", "no_fire"}:
        raise RuleError(f"{name}: 'expect' must be fire or no_fire, got {sorted(map(str, expects))}")
    # Cases with no events test nothing, so they don't count toward coverage.
    if {c["expect"] for c in cases if c["events"]} != {"fire", "no_fire"}:
        raise RuleError(f"{name}: needs at least one fire case and one no_fire case with events")

    results = []
    for case in cases:
        events = case["events"]
        if not events:
            # A known gap: nothing is logged, so there is nothing to test.
            results.append((case.get("name", "?"), case["expect"], "SKIP", "known gap, no events"))
            continue
        matched = [e for e in events if matches(condition, e)]
        firing = fires(matched, group_by, threshold, window, time_field, name)
        fired = bool(firing)
        passed = fired == (case["expect"] == "fire")
        detail = f"{len(matched)}/{len(events)} events match"
        if group_by:
            detail += f", need {threshold} per {'+'.join(group_by)} in {window}"
        detail += f": {'fired' if fired else 'no alert'}"
        if firing and group_by:
            detail += f" for {', '.join('/'.join(map(str, k)) for k in firing)}"
        results.append((case.get("name", "?"), case["expect"], "PASS" if passed else "FAIL", detail))
    return results


def main(argv=None, root=DETECTIONS, out=sys.stdout):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)

    rules = sorted(p for folder in PIPELINES for p in (root / folder).glob("*.yml"))
    unlisted = sorted(
        p for p in root.glob("*/*.yml")
        if p.parent.name not in PIPELINES and p.parent.name != "pipelines"
    )
    if unlisted:
        for p in unlisted:
            print(f"ERROR {p.relative_to(root)}: folder has no pipeline in PIPELINES", file=out)
        return 2
    if not rules:
        print("ERROR no rules found", file=out)
        return 2

    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    errors = 0
    for rule_path in rules:
        label = rule_path.relative_to(root)
        try:
            results = run_rule(rule_path, root)
        except RuleError as e:
            print(f"ERROR {label}: {e}", file=out)
            errors += 1
            continue
        print(f"{label}", file=out)
        for case_name, expect, status, detail in results:
            counts[status] += 1
            shown = "SKIP (known gap)" if status == "SKIP" else status
            print(f"  {shown}  expect {expect:<7}  {case_name}  ({detail})", file=out)

    failed, skipped = counts["FAIL"], counts["SKIP"]
    tested = counts["PASS"] + failed
    print(f"\n{counts['PASS']}/{tested} cases passed, {failed} failed, "
          f"{skipped} skipped (known gap), {errors} rule errors", file=out)
    if errors:
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

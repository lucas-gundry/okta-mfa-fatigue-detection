# Okta MFA fatigue detection

A homelab detection-as-code sample: a Sigma rule, the Elastic threshold rule
built from it, test cases that say why it should or shouldn't fire, and CI
that runs them. The write-up, including what I got wrong along the way, is at
[lucasgundry.com](https://lucasgundry.com/projects/mfa-fatigue-detection/).

MFA fatigue is when an attacker who already has a password sends push after
push, hoping the user taps Approve to make them stop (MITRE ATT&CK T1621). One
push is a normal sign-in. A burst of pushes to one person is the signal.

## What's here

| Path | What it is |
| --- | --- |
| `okta/okta_mfa_push_fatigue.yml` | Sigma rule: matches one push event |
| `okta/okta_mfa_push_fatigue.json` | Elastic rule: 5 or more pushes per user in a 6-minute lookback, plus triage notes |
| `okta/tests/` | 5 made-up cases: 1 fires, 4 stay quiet, including a known gap |
| `pipelines/okta-ecs.yml` | Maps Okta's field names to the ones Elastic uses |
| `scripts/run_rule_tests.py` | Runs the cases through the Sigma logic and the Elastic rule's count |
| `scripts/test_run_rule_tests.py` | Self-tests: the runner must catch bad rules, not just pass |
| `scripts/check-private.sh` | Pre-publish check for secrets and private details |
| `.github/workflows/test.yml` | Runs the cases and self-tests on pushes and pull requests |

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -I scripts/run_rule_tests.py
python -I -m unittest discover -s scripts
```

The runner exits 0 if every case passes, 1 if a case fails, and 2 if a rule or
file is broken.

## Limits

- This is homelab work, not production experience. The rule is turned off
  (`enabled: false`).
- The 5-push threshold is a starting value. It hasn't fired on real data.
- A slow drip, such as one push every 10 minutes, never reaches 5 in one
  lookback. A test case records that gap. A companion rule on denials, or a
  longer window, would catch it.
- The runner's result is a best case: a real rule run might split events across
  two runs.
- Only a denial that wasn't reported as suspicious was tested. A reported one
  may log a different event.
- Number matching makes blind approval much harder. The rule still matters for
  accounts or policies without it.

All test events are made up. They use `example.com` users and documentation IP
ranges.

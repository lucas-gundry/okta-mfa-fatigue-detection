#!/usr/bin/env bash
# Pre-publish privacy check. Any hit blocks publishing.
#   1. gitleaks over the files, and the history once this is a git repo
#   2. a grep for private details a secret scanner wouldn't flag
# Patterns here are shapes, never real values. Real names go in the file
# named by PRIVATE_PATTERNS (default .check-private-patterns, git-ignored,
# one regex per line), so this public file can't leak them itself.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
private=${PRIVATE_PATTERNS:-.check-private-patterns}

if command -v gitleaks >/dev/null; then
  gitleaks dir --no-banner --redact . || fail=1
  if git rev-parse --verify -q HEAD >/dev/null 2>&1; then
    gitleaks git --no-banner --redact . || fail=1
  fi
else
  echo "FAIL: gitleaks not installed" >&2; fail=1
fi

patterns=(
  '\b[0-9]{12}\b' '\bd-[0-9a-z]{10}\b' 'awsapps\.com'
  'integrator-[0-9]+' 'okta(preview)?\.com/' '-admin\.okta'
  'fleet-server' 'kibana_rules' '_env\b'
  'hc-ping\.com' '@gmail\.com' 'localhost:[0-9]+' '/home/[a-z]'
)
if [ -s "$private" ]; then
  while IFS= read -r p; do [ -n "$p" ] && patterns+=("$p"); done < "$private"
else
  echo "FAIL: $private missing or empty; private names unchecked" >&2; fail=1
fi

files=$(find . -type f -not -path './.git/*' -not -path './.venv/*' -not -path '*/__pycache__/*' \
  -not -path './scripts/check-private.sh' -not -name '.check-private-patterns')
for p in "${patterns[@]}"; do
  hits=$(echo "$files" | xargs -r grep -nEi -- "$p" 2>/dev/null)
  if [ -n "$hits" ]; then echo "FAIL private detail /$p/:"; echo "$hits"; fail=1; fi
done

# IP addresses: only the documentation ranges (RFC 5737) are allowed.
hits=$(echo "$files" | xargs -r grep -nEo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' 2>/dev/null \
  | grep -vE ':(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]+$')
if [ -n "$hits" ]; then echo "FAIL address outside the documentation ranges:"; echo "$hits"; fail=1; fi

# UUIDs: only the Sigma rule's own id line, which Sigma requires.
hits=$(echo "$files" | xargs -r grep -nEi '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-' 2>/dev/null \
  | grep -vE '^\./okta/[^:]+\.yml:[0-9]+:id: ')
if [ -n "$hits" ]; then echo "FAIL UUID outside the Sigma id:"; echo "$hits"; fail=1; fi

[ $fail -eq 0 ] && echo "All checks passed." || echo "Checks FAILED: fix before publishing."
exit $fail

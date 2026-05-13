#!/bin/bash
# scripts/verify-scan.sh
#
# Smoke-validate the numbers `node9 scan` reports against the raw data
# sources it summarises. For each panel, independently compute the same
# metric from the filesystem / JSONL and compare.
#
# Catches counter regressions in the scan pipeline — does NOT validate
# the algorithmic checks (loop detection, smart-rule evaluation, DLP
# pattern matching). Those are covered by unit tests; this script
# focuses on the boring-but-load-bearing arithmetic.
#
# Usage:
#   ./scripts/verify-scan.sh           # validates --days 90 against live data
#   ./scripts/verify-scan.sh --all     # validates --all against live data
#
# Exits 0 when every check passes, 1 if any mismatch is found.

set -euo pipefail

SCAN_FLAGS="--days 90"
if [ "${1:-}" = "--all" ]; then
  SCAN_FLAGS="--all"
fi

# Locate the node9 binary. Prefer a freshly-built local dist over the
# globally installed package so checks reflect the current code.
if [ -x "$(dirname "$0")/../dist/cli.js" ]; then
  NODE9="$(dirname "$0")/../dist/cli.js"
else
  NODE9=$(which node9)
fi

if [ -z "$NODE9" ]; then
  echo "ERR: cannot locate node9 binary" >&2
  exit 1
fi

echo "Verifying scan numbers against raw sources..."
echo "  binary:  $NODE9"
echo "  flags:   $SCAN_FLAGS"
echo ""

# Run scan once, cache the JSON.
SCAN_JSON=$("$NODE9" scan $SCAN_FLAGS --json 2>/dev/null)

# Helper: PASS/FAIL line.
exit_code=0
check() {
  local label="$1"
  local scan_val="$2"
  local indep_val="$3"
  if [ "$scan_val" = "$indep_val" ]; then
    printf "  %-32s %10s  ✓\n" "$label" "$scan_val"
  else
    printf "  %-32s scan=%-7s independent=%-7s  ✗\n" "$label" "$scan_val" "$indep_val"
    exit_code=1
  fi
}

# ── Sessions ──────────────────────────────────────────────────────────────
# Scan filters sessions by their first event timestamp inside the JSONL,
# not by file mtime. There's no shell equivalent for that — re-implementing
# it would just duplicate the scan logic, defeating the purpose of an
# independent check. So we only verify the UNFILTERED count: total JSONL
# files in the agent dirs must be ≥ what scan reports (scan can drop
# sessions outside the window, but can't add ones that don't exist).
SESSIONS_SCAN=$(echo "$SCAN_JSON" | jq -r '.summary.stats.sessions')
SESSIONS_TOTAL=$(find ~/.claude/projects ~/.gemini/tmp ~/.codex/sessions \
  -name '*.jsonl' 2>/dev/null | wc -l)
if [ "$SESSIONS_SCAN" -le "$SESSIONS_TOTAL" ]; then
  printf "  %-32s scan=%-7s ≤ %-7s on-disk  ✓\n" "Sessions ≤ on-disk total" "$SESSIONS_SCAN" "$SESSIONS_TOTAL"
else
  printf "  %-32s scan=%-7s on-disk=%-7s  ✗ (scan exceeds total!)\n" "Sessions" "$SESSIONS_SCAN" "$SESSIONS_TOTAL"
  exit_code=1
fi

# ── Blast radius paths reachable ──────────────────────────────────────────
# Scan walks a list of sensitive paths; each must be readable by the user
# to count as exposed. Independent check: stat each path scan reports.
BLAST_PATHS=$(echo "$SCAN_JSON" | jq -r '.blast.reachable[].label')
BLAST_INDEP=0
BLAST_FAIL=""
while IFS= read -r path; do
  [ -z "$path" ] && continue
  # Expand ~ and glob the path
  expanded=$(eval echo "$path")
  if [ -r "$expanded" ]; then
    BLAST_INDEP=$((BLAST_INDEP + 1))
  else
    BLAST_FAIL+=" $path"
  fi
done <<< "$BLAST_PATHS"
BLAST_SCAN=$(echo "$SCAN_JSON" | jq -r '.blast.reachable | length')
check "Blast radius paths reachable" "$BLAST_SCAN" "$BLAST_INDEP"
if [ -n "$BLAST_FAIL" ]; then
  echo "    not readable as \$USER:$BLAST_FAIL"
fi

# ── Credential leaks present in JSONL ─────────────────────────────────────
# Scan reports N detected leaks. For each, verify the source session
# JSONL exists. Doesn't re-run DLP (that's algorithmic — covered by
# unit tests); just confirms the rows scan attributes actually exist.
LEAKS_SCAN=$(echo "$SCAN_JSON" | jq -r '.totals.leaks')
LEAK_SESSION_IDS=$(echo "$SCAN_JSON" \
  | jq -r '.summary.leaks[]? | .sessionId // empty' \
  | sort -u)
LEAK_FOUND=0
LEAK_MISSING=""
if [ -n "$LEAK_SESSION_IDS" ]; then
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    # Session ids appear as filenames or in path segments — grep for them
    if find ~/.claude/projects ~/.gemini/tmp ~/.codex/sessions \
        -name "*${sid}*" 2>/dev/null | grep -q .; then
      LEAK_FOUND=$((LEAK_FOUND + 1))
    else
      LEAK_MISSING+=" $sid"
    fi
  done <<< "$LEAK_SESSION_IDS"
fi
LEAK_SESSION_COUNT=$(echo "$LEAK_SESSION_IDS" | grep -c . || echo 0)
check "Leak source sessions found" "$LEAK_SESSION_COUNT" "$LEAK_FOUND"
if [ -n "$LEAK_MISSING" ]; then
  echo "    missing session files:$LEAK_MISSING"
fi

# ── Score envelope (internal consistency, not external) ───────────────────
# Headline score = max(0, 100 - sum of per-path deductions). Per-path
# deduction is on `blast.reachable[].score` (the field name is confusing;
# it's a deduction value, not a per-path score). Internal check —
# verifies scan didn't drift its own arithmetic, doesn't need a raw
# source.
SCORE=$(echo "$SCAN_JSON" | jq -r '.score')
DEDUCT_SUM=$(echo "$SCAN_JSON" \
  | jq -r '[.blast.reachable[].score // 0, .blast.envFindings[].score // 0] | add // 0')
EXPECTED_SCORE=$(( DEDUCT_SUM > 100 ? 0 : 100 - DEDUCT_SUM ))
check "Score envelope (100 − deductions)" "$SCORE" "$EXPECTED_SCORE"

echo ""
if [ $exit_code -eq 0 ]; then
  echo "═══════════════════════════════════════"
  echo "✓ All scan numbers consistent with raw data sources."
  echo "═══════════════════════════════════════"
else
  echo "═══════════════════════════════════════"
  echo "✗ Mismatches found — investigate above."
  echo "═══════════════════════════════════════"
fi

exit $exit_code

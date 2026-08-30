#!/usr/bin/env bash
# =============================================================================
# Node9 End-to-End Test
# Tests the exact same flow Claude Code / Gemini CLI uses in production.
# Run from the repo root: bash scripts/e2e.sh
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

PASS=0; FAIL=0

pass() { echo -e "  ${GREEN}✓${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}✗${RESET} $1"; FAIL=$((FAIL+1)); }
section() { echo -e "\n${BOLD}${BLUE}── $1 ──${RESET}"; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── Build ─────────────────────────────────────────────────────────────────────
section "Build"
cd "$REPO_ROOT"
npm run build --silent
NODE9="node $REPO_ROOT/dist/cli.js"
pass "Build succeeded → dist/cli.js"

# ── Version ───────────────────────────────────────────────────────────────────
section "Version"
VERSION=$($NODE9 --version)
EXPECTED=$(node -e "console.log(require('$REPO_ROOT/package.json').version)")
if [ "$VERSION" = "$EXPECTED" ]; then
  pass "Version reads from package.json: $VERSION"
else
  fail "Version mismatch: got '$VERSION', expected '$EXPECTED'"
fi

# ── Isolated test environment ─────────────────────────────────────────────────
# Run all hook checks from a temp dir with a known config so tests are
# independent of whatever node9.config.json exists in the repo root.
TESTDIR=$(mktemp -d)
TEST_HOME=$(mktemp -d)
mkdir -p "$TEST_HOME/.node9"
trap 'rm -rf "$TESTDIR" "$TEST_HOME"' EXIT

cat > "$TESTDIR/node9.config.json" << 'EOF'
{
  "settings": {
    "mode": "standard",
    "approvalTimeoutMs": 0,
    "approvers": { "native": false, "browser": false, "cloud": false, "terminal": false }
  },
  "policy": {
    "dangerousWords": [
      "delete","drop","remove","rm","rmdir","terminate",
      "refund","write","update","destroy","purge","revoke","format","truncate"
    ],
    "ignoredTools": ["list_*","get_*","read_*","describe_*"]
  },
  "environments": {}
}
EOF

cd "$TESTDIR"
# Disable all daemon interaction so tests never open a browser or hang waiting for clicks
export NODE9_NO_AUTO_DAEMON=1
# Stop any running daemon using the real HOME before we isolate the environment
node "$REPO_ROOT/dist/cli.js" daemon stop 2>/dev/null || true
# Use an isolated HOME so credentials.json and decisions.json don't affect results
export HOME="$TEST_HOME"
# Keyedness hygiene (PR-2 §0.12): never inherit the developer machine's real
# key — a keyed run would build policy from the CLOUD and test a different
# config source depending on whose machine runs this script.
unset NODE9_API_KEY NODE9_API_URL NODE9_PROFILE

# Client-identity hygiene — the same class of leak as the key above, and the
# reason v2.6.0 got a tag on main while npm stayed at 2.5.0.
#
# A review verdict only surfaces as an inline ask when the CLIENT can render
# one; node9 detects Claude Code from CLAUDECODE / CLAUDE_CODE_SESSION_ID
# (src/cli/commands/check.ts). Without it a review fails CLOSED to a block,
# which is correct.
#
# This suite's Part 1 heading claims it simulates a Claude Code hook, but it
# never set the variable that makes it one: it inherited it from the shell.
# That made it pass on any developer box (always inside a Claude Code
# session) and fail on every CI runner. Pin the identity so the suite tests
# what it says it tests, and drop the second signal so exactly one thing
# drives the branch.
export CLAUDECODE=1
unset CLAUDE_CODE_SESSION_ID

# =============================================================================
# PART 1 — node9 check  (simulates Claude Code's PreToolUse hook)
# Claude Code pipes JSON to stdin: { tool_name, tool_input }
# Expected for BLOCK: JSON with decision:"deny", exit 0
# Expected for ALLOW: empty stdout, exit 0
# =============================================================================
section "Part 1 · node9 check — simulating Claude Code PreToolUse hook"

check_blocked() {
  local label="$1"
  local payload="$2"
  local out
  out=$(echo "$payload" | $NODE9 check 2>/dev/null) || true
  if echo "$out" | grep -q '"decision":"block"'; then
    pass "BLOCKED  → $label"
  else
    fail "Expected block for: $label  (got: '$out')"
  fi
}

check_allowed() {
  local label="$1"
  local payload="$2"
  local out
  out=$(echo "$payload" | $NODE9 check 2>/dev/null) || true
  if [ -z "$out" ]; then
    pass "ALLOWED  → $label"
  else
    fail "Expected allow (empty output) for: $label  (got: '$out')"
  fi
}

# Review-tier verdicts surface as an inline ASK since inline-ask v2
# (permissionDecision:"ask") — the agent UI shows the approval prompt. The old
# expectation here (decision:"block") predates that release; only Layer-1
# block rules (e.g. rm -rf /) still hard-deny.
check_review() {
  local label="$1"
  local payload="$2"
  local out
  out=$(echo "$payload" | $NODE9 check 2>/dev/null) || true
  if echo "$out" | grep -q '"permissionDecision":"ask"'; then
    pass "REVIEW   → $label"
  else
    fail "Expected inline ask for: $label  (got: '$out')"
  fi
}

echo -e "\n  ${YELLOW}MCP tool names:${RESET}"
check_review "delete_user"         '{"tool_name":"delete_user","tool_input":{"id":1}}'
check_review "drop_table"          '{"tool_name":"drop_table","tool_input":{"table":"users"}}'
check_review "remove_file"         '{"tool_name":"remove_file","tool_input":{"path":"/tmp/x"}}'
check_review "aws.rds.rm_database" '{"tool_name":"aws.rds.rm_database","tool_input":{}}'
check_review "purge_queue"         '{"tool_name":"purge_queue","tool_input":{}}'
check_review "destroy_cluster"     '{"tool_name":"destroy_cluster","tool_input":{}}'

echo -e "\n  ${YELLOW}Claude Code Bash tool — dangerous commands (review-tier → inline ask):${RESET}"

# 1. Test 'rm' on a SENSITIVE path (not in allowPaths and not in /tmp)
check_review "Bash: rm /etc/passwd"    '{"tool_name":"Bash","tool_input":{"command":"rm /etc/passwd"}}'

# 2. Test a "Nuke" word (drop) inside the sandbox (Nukes should be blocked everywhere)
check_review "Bash: drop /tmp/db"      '{"tool_name":"Bash","tool_input":{"command":"psql -c \"drop table users\""}}'

# 3. Existing passing tests
check_blocked "Bash: rm -rf /"          '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
check_review "Bash: sudo rm -rf /home" '{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /home/user"}}'

# 4. Test 'docker' (a Nuke word)
check_review "Bash: docker rm -f"      '{"tool_name":"Bash","tool_input":{"command":"docker rm -f container_id"}}'

# 5. Test 'purge' (a Nuke word)
check_review "Bash: purge /opt/data"   '{"tool_name":"Bash","tool_input":{"command":"purge /opt/data"}}'

# 6. Test 'find -delete' (the parser finds the "delete" token which is often a rule action)
check_review "Bash: find . -delete"    '{"tool_name":"Bash","tool_input":{"command":"find . -name tmp -delete"}}'

# The inverse of every assertion above, and the behaviour that made this suite
# environment-dependent in the first place: with NO inline-ask-capable client,
# a review verdict must fail CLOSED to a block rather than sail through. Real
# security behaviour that nothing verified until v2.6.0 failed to publish.
echo -e "\n  ${YELLOW}No inline-ask-capable client — review must fail closed:${RESET}"
out=$(env -u CLAUDECODE -u CLAUDE_CODE_SESSION_ID sh -c \
  'echo '"'"'{"tool_name":"delete_user","tool_input":{"id":1}}'"'"' | '"$NODE9"' check' 2>/dev/null) || true
if echo "$out" | grep -q '"decision":"block"'; then
  pass "FAIL-CLOSED → review becomes a block with no client to ask"
else
  fail "Review did not fail closed without a client  (got: '$out')"
fi


echo -e "\n  ${YELLOW}Claude Code Bash tool — safe commands (must NOT be blocked):${RESET}"
check_allowed "Bash: ls -la"         '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
check_allowed "Bash: git status"     '{"tool_name":"Bash","tool_input":{"command":"git status"}}'
check_allowed "Bash: cat file"       '{"tool_name":"Bash","tool_input":{"command":"cat /etc/hosts"}}'
check_allowed "Bash: npm install"    '{"tool_name":"Bash","tool_input":{"command":"npm install express"}}'
check_allowed "Bash: node --version" '{"tool_name":"Bash","tool_input":{"command":"node --version"}}'

echo -e "\n  ${YELLOW}Ignored patterns (must NOT be blocked):${RESET}"
check_allowed "list_users"    '{"tool_name":"list_users","tool_input":{}}'
check_allowed "get_config"    '{"tool_name":"get_config","tool_input":{}}'
check_allowed "read_file"     '{"tool_name":"read_file","tool_input":{"path":"/etc/hosts"}}'
check_allowed "describe_table" '{"tool_name":"describe_table","tool_input":{}}'

echo -e "\n  ${YELLOW}False-positive regression (rm substring — old impl would block these):${RESET}"
check_allowed "confirm_action"  '{"tool_name":"confirm_action","tool_input":{}}'
check_allowed "check_permissions" '{"tool_name":"check_permissions","tool_input":{}}'
check_allowed "perform_search"  '{"tool_name":"perform_search","tool_input":{}}'

echo -e "\n  ${YELLOW}Malformed / empty input (must never crash Claude):${RESET}"
out=$(echo '' | $NODE9 check 2>/dev/null) || true; ec=$?
[ $ec -eq 0 ] && pass "Empty stdin → exits 0 (fail-open)" || fail "Empty stdin crashed (exit $ec)"

out=$(echo 'not json at all' | $NODE9 check 2>/dev/null) || true; ec=$?
[ $ec -eq 0 ] && pass "Invalid JSON → exits 0 (fail-open)" || fail "Invalid JSON crashed (exit $ec)"

echo -e "\n  ${YELLOW}Daemon isolation (NODE9_NO_AUTO_DAEMON=1 must prevent auto-start):${RESET}"
if [ ! -f "$HOME/.node9/daemon.pid" ]; then
  pass "NODE9_NO_AUTO_DAEMON=1 — no daemon was started during check tests"
else
  fail "Daemon was auto-started during tests — NODE9_NO_AUTO_DAEMON=1 had no effect"
  node "$REPO_ROOT/dist/cli.js" daemon stop 2>/dev/null || true
fi

# =============================================================================
# PART 2 — node9 log  (simulates Claude Code's PostToolUse hook)
# =============================================================================
section "Part 2 · node9 log — audit trail"

LOG_FILE="$HOME/.node9/audit.log"
LINES_BEFORE=0
[ -f "$LOG_FILE" ] && LINES_BEFORE=$(wc -l < "$LOG_FILE")

echo '{"tool_name":"read_file","tool_input":{"path":"/etc/hosts"}}' | $NODE9 log 2>/dev/null

LINES_AFTER=0
[ -f "$LOG_FILE" ] && LINES_AFTER=$(wc -l < "$LOG_FILE")

if [ "$LINES_AFTER" -gt "$LINES_BEFORE" ]; then
  LAST=$(tail -1 "$LOG_FILE")
  pass "Audit log written → $LOG_FILE"
  echo -e "    ${YELLOW}Last entry:${RESET} $LAST"
else
  fail "Audit log not written to $LOG_FILE"
fi

# =============================================================================
# PART 3 — Log injection guard
# =============================================================================
section "Part 3 · Log injection guard"

LINES_BEFORE=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
printf '{"tool_name":"evil\\ninjected_line","tool_input":{}}' | $NODE9 log 2>/dev/null
LINES_AFTER=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)

ADDED=$((LINES_AFTER - LINES_BEFORE))
if [ "$ADDED" -le 1 ]; then
  pass "Newline in tool_name did not inject extra log lines (added: $ADDED)"
else
  fail "Log injection: $ADDED lines added (expected 1)"
fi

# =============================================================================
# PART 4 — Response format (Claude Code reads hookSpecificOutput)
# =============================================================================
section "Part 4 · Response format"

# The DENY wire shape needs a Layer-1 block rule (delete_user is review-tier
# and surfaces as an inline ask since inline-ask v2).
RESPONSE=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | $NODE9 check 2>/dev/null) || true

echo "$RESPONSE" | grep -q '"decision":"block"' \
  && pass 'Block response has decision:"block"' \
  || fail 'Block response missing decision field'

echo "$RESPONSE" | grep -q '"hookSpecificOutput"' \
  && pass "Block response has hookSpecificOutput (Claude Code field)" \
  || fail "Block response missing hookSpecificOutput"

echo "$RESPONSE" | grep -q '"permissionDecision":"deny"' \
  && pass 'Block response has permissionDecision:"deny" (Claude Code field)' \
  || fail "Block response missing permissionDecision"

ASK_RESPONSE=$(echo '{"tool_name":"delete_user","tool_input":{"id":1}}' | $NODE9 check 2>/dev/null) || true
echo "$ASK_RESPONSE" | grep -q '"permissionDecision":"ask"' \
  && pass 'Review response has permissionDecision:"ask" (inline-ask v2 wire)' \
  || fail "Review response missing permissionDecision:ask"

# =============================================================================
# PART 5 — Global config (~/.node9/config.json)
# =============================================================================
section "Part 5 · Global config (~/.node9/config.json)"

GLOBAL_HOME=$(mktemp -d)
mkdir -p "$GLOBAL_HOME/.node9"
cat > "$GLOBAL_HOME/.node9/config.json" << 'EOF'
{
  "settings": {
    "mode": "standard",
    "approvalTimeoutMs": 0,
    "approvers": { "native": false, "browser": false, "cloud": false, "terminal": false }
  },
  "policy": {
    "dangerousWords": ["nuke"],
    "ignoredTools": ["list_*","get_*","read_*","describe_*"]
  },
  "environments": {}
}
EOF

# Run from a dir with NO project config — global config must apply
NOPROJECT=$(mktemp -d)

out=$(cd "$NOPROJECT" && echo '{"tool_name":"nuke_everything","tool_input":{}}' | HOME="$GLOBAL_HOME" $NODE9 check 2>/dev/null) || true
if echo "$out" | grep -q '"permissionDecision":"ask"'; then
  pass "Global config: custom dangerous word 'nuke' flags for review (inline ask)"
else
  fail "Global config not applied: 'nuke_everything' not flagged (got: '$out')"
fi

out=$(cd "$NOPROJECT" && echo '{"tool_name":"list_users","tool_input":{}}' | HOME="$GLOBAL_HOME" $NODE9 check 2>/dev/null) || true
if [ -z "$out" ]; then
  pass "Global config: ignoredTools still work"
else
  fail "Global config: ignoredTools broken (got: '$out')"
fi

# Project config must take precedence over global config
cat > "$NOPROJECT/node9.config.json" << 'EOF'
{
  "settings": {
    "mode": "standard",
    "approvalTimeoutMs": 0,
    "approvers": { "native": false, "browser": false, "cloud": false, "terminal": false }
  },
  "policy": { "dangerousWords": [], "ignoredTools": [] },
  "environments": {}
}
EOF

out=$(cd "$NOPROJECT" && echo '{"tool_name":"nuke_everything","tool_input":{}}' | HOME="$GLOBAL_HOME" $NODE9 check 2>/dev/null) || true
if [ -z "$out" ]; then
  pass "Project config takes precedence over global config"
else
  fail "Project config did not override global config (got: '$out')"
fi

rm -rf "$GLOBAL_HOME" "$NOPROJECT"

# =============================================================================
# PART 6 — Keyed machine (PR-2 replace-mode): the workspace config governs
# Fixture = credentials.json with an UNROUTABLE apiUrl (no network) + a
# rules-cache.json standing in for the synced workspace config. The local
# config.json carries a 'nuke' dangerous word that MUST be inert while keyed
# and MUST come back under login --local (localOnly).
# =============================================================================
section "Part 6 · Keyed machine — workspace config governs (PR-2)"

KEYED_HOME=$(mktemp -d)
KEYED_DIR=$(mktemp -d)   # run dir with NO project config
mkdir -p "$KEYED_HOME/.node9"

cat > "$KEYED_HOME/.node9/credentials.json" << 'EOF'
{ "default": { "apiKey": "n9_live_e2e_keyed_fixture", "apiUrl": "http://127.0.0.1:1" } }
EOF

# The synced workspace policy: one org block rule; managed settings keep the
# run deterministic (all approver channels off + 50ms timeout → no waits).
cat > "$KEYED_HOME/.node9/rules-cache.json" << 'EOF'
{
  "fetchedAt": "2026-08-01T00:00:00Z",
  "rules": [
    {
      "name": "org-block-frobnicate",
      "tool": "bash",
      "conditions": [{ "field": "command", "op": "contains", "value": "frobnicate" }],
      "conditionMode": "all",
      "verdict": "block",
      "reason": "org rule (e2e keyed fixture)"
    }
  ],
  "shields": [],
  "managedConfig": {
    "mode": "standard",
    "approvalTimeoutMs": 50,
    "approvers": { "native": false, "browser": false, "cloud": false, "terminal": false },
    "locked": []
  }
}
EOF

cat > "$KEYED_HOME/.node9/config.json" << 'EOF'
{
  "settings": { "mode": "standard" },
  "policy": { "dangerousWords": ["nuke"] }
}
EOF

# 6.1 — the workspace rule is enforced (the K13c bug, live at the real gate)
out=$(cd "$KEYED_DIR" && echo '{"tool_name":"Bash","tool_input":{"command":"frobnicate --all"}}' | HOME="$KEYED_HOME" $NODE9 check 2>/dev/null) || true
if echo "$out" | grep -q '"decision":"block"'; then
  pass "Keyed: workspace (cloud cache) rule blocks at the gate"
else
  fail "Keyed: workspace rule NOT enforced (got: '$out')"
fi

# 6.2 — the local dangerousWords list is INERT while keyed
out=$(cd "$KEYED_DIR" && echo '{"tool_name":"nuke_everything","tool_input":{}}' | HOME="$KEYED_HOME" $NODE9 check 2>/dev/null) || true
if [ -z "$out" ]; then
  pass "Keyed: local config.json dangerousWords are inert"
else
  fail "Keyed: local dangerousWords still enforced (got: '$out')"
fi

# 6.3 — local policy writes are refused with a non-zero exit and touch nothing
guard_refused() {
  local label="$1"; shift
  local ec=0
  local out
  out=$(cd "$KEYED_DIR" && HOME="$KEYED_HOME" $NODE9 "$@" 2>&1) || ec=$?
  if [ "$ec" -ne 0 ] && echo "$out" | grep -qi "workspace configuration"; then
    pass "Keyed write-guard: '$label' refused (exit $ec, points at the dashboard)"
  else
    fail "Keyed write-guard: '$label' NOT refused (exit $ec, out: '$out')"
  fi
}
guard_refused "shield enable postgres" shield enable postgres
guard_refused "egress off"             egress off
guard_refused "trust add"              trust add api.example.com
guard_refused "jail add"               jail add /tmp/e2e-jail-probe

if [ ! -f "$KEYED_HOME/.node9/shields.json" ] && [ ! -f "$KEYED_HOME/.node9/trusted-hosts.json" ]; then
  pass "Keyed write-guard: refused writes left no store files behind"
else
  fail "Keyed write-guard: a refused write still created a store file"
fi

# 6.4 — introspection tells the truth
out=$(cd "$KEYED_DIR" && HOME="$KEYED_HOME" $NODE9 status 2>/dev/null) || true
if echo "$out" | grep -q "Workspace config"; then
  pass "Keyed: 'node9 status' names the workspace as the policy source"
else
  fail "Keyed: 'node9 status' does not name the workspace source"
fi

# 6.5 — the localOnly promise (login --local): same key, local policy governs again
cat > "$KEYED_HOME/.node9/credentials.json" << 'EOF'
{ "default": { "apiKey": "n9_live_e2e_keyed_fixture", "apiUrl": "http://127.0.0.1:1", "localOnly": true } }
EOF
out=$(cd "$KEYED_DIR" && echo '{"tool_name":"nuke_everything","tool_input":{}}' | HOME="$KEYED_HOME" $NODE9 check 2>/dev/null) || true
if echo "$out" | grep -q '"permissionDecision":"ask"'; then
  pass "localOnly: local dangerousWords govern again (the --local promise)"
else
  fail "localOnly: local config still inert (got: '$out')"
fi
ec=0
out=$(cd "$KEYED_DIR" && HOME="$KEYED_HOME" $NODE9 trust add api.example.com 2>&1) || ec=$?
if [ "$ec" -eq 0 ] && [ -f "$KEYED_HOME/.node9/trusted-hosts.json" ]; then
  pass "localOnly: local policy writes proceed (trust add wrote the store)"
else
  fail "localOnly: trust add refused or wrote nothing (exit $ec, out: '$out')"
fi

rm -rf "$KEYED_HOME" "$KEYED_DIR"

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "\n${BOLD}══════════════════════════════════════════${RESET}"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}  All $TOTAL tests passed ✓${RESET}"
else
  echo -e "${RED}${BOLD}  $FAIL/$TOTAL tests FAILED${RESET}"
fi
echo -e "${BOLD}══════════════════════════════════════════${RESET}\n"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1

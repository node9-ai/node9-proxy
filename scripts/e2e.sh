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
trap 'rm -rf "$TESTDIR"' EXIT

cat > "$TESTDIR/node9.config.json" << 'EOF'
{
  "settings": { "mode": "standard" },
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
  out=$(echo "$payload" | $NODE9 check 2>/dev/null)
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
  out=$(echo "$payload" | $NODE9 check 2>/dev/null)
  if [ -z "$out" ]; then
    pass "ALLOWED  → $label"
  else
    fail "Expected allow (empty output) for: $label  (got: '$out')"
  fi
}

echo -e "\n  ${YELLOW}MCP tool names:${RESET}"
check_blocked "delete_user"         '{"tool_name":"delete_user","tool_input":{"id":1}}'
check_blocked "drop_table"          '{"tool_name":"drop_table","tool_input":{"table":"users"}}'
check_blocked "remove_file"         '{"tool_name":"remove_file","tool_input":{"path":"/tmp/x"}}'
check_blocked "aws.rds.rm_database" '{"tool_name":"aws.rds.rm_database","tool_input":{}}'
check_blocked "purge_queue"         '{"tool_name":"purge_queue","tool_input":{}}'
check_blocked "destroy_cluster"     '{"tool_name":"destroy_cluster","tool_input":{}}'

echo -e "\n  ${YELLOW}Claude Code Bash tool — dangerous commands:${RESET}"
check_blocked "Bash: rm /tmp/file"      '{"tool_name":"Bash","tool_input":{"command":"rm /tmp/file"}}'
check_blocked "Bash: rm -rf /"          '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
check_blocked "Bash: sudo rm -rf /home" '{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /home/user"}}'
check_blocked "Bash: rmdir /tmp/dir"    '{"tool_name":"Bash","tool_input":{"command":"rmdir /tmp/dir"}}'
check_blocked "Bash: /usr/bin/rm file"  '{"tool_name":"Bash","tool_input":{"command":"/usr/bin/rm file.txt"}}'
check_blocked "Bash: find . -delete"    '{"tool_name":"Bash","tool_input":{"command":"find . -name tmp -delete"}}'

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
out=$(echo '' | $NODE9 check 2>/dev/null); ec=$?
[ $ec -eq 0 ] && pass "Empty stdin → exits 0 (fail-open)" || fail "Empty stdin crashed (exit $ec)"

out=$(echo 'not json at all' | $NODE9 check 2>/dev/null); ec=$?
[ $ec -eq 0 ] && pass "Invalid JSON → exits 0 (fail-open)" || fail "Invalid JSON crashed (exit $ec)"

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

RESPONSE=$(echo '{"tool_name":"delete_user","tool_input":{"id":1}}' | $NODE9 check 2>/dev/null)

echo "$RESPONSE" | grep -q '"decision":"block"' \
  && pass 'Response has decision:"block"' \
  || fail 'Response missing decision field'

echo "$RESPONSE" | grep -q '"hookSpecificOutput"' \
  && pass "Response has hookSpecificOutput (Claude Code field)" \
  || fail "Response missing hookSpecificOutput"

echo "$RESPONSE" | grep -q '"permissionDecision":"deny"' \
  && pass 'Response has permissionDecision:"deny" (Claude Code field)' \
  || fail "Response missing permissionDecision"

# =============================================================================
# PART 5 — Global config (~/.node9/config.json)
# =============================================================================
section "Part 5 · Global config (~/.node9/config.json)"

GLOBAL_HOME=$(mktemp -d)
mkdir -p "$GLOBAL_HOME/.node9"
cat > "$GLOBAL_HOME/.node9/config.json" << 'EOF'
{
  "settings": { "mode": "standard" },
  "policy": {
    "dangerousWords": ["nuke"],
    "ignoredTools": ["list_*","get_*","read_*","describe_*"]
  },
  "environments": {}
}
EOF

# Run from a dir with NO project config — global config must apply
NOPROJECT=$(mktemp -d)

out=$(cd "$NOPROJECT" && echo '{"tool_name":"nuke_everything","tool_input":{}}' | HOME="$GLOBAL_HOME" $NODE9 check 2>/dev/null)
if echo "$out" | grep -q '"decision":"block"'; then
  pass "Global config: custom dangerous word 'nuke' is blocked"
else
  fail "Global config not applied: 'nuke_everything' not blocked (got: '$out')"
fi

out=$(cd "$NOPROJECT" && echo '{"tool_name":"list_users","tool_input":{}}' | HOME="$GLOBAL_HOME" $NODE9 check 2>/dev/null)
if [ -z "$out" ]; then
  pass "Global config: ignoredTools still work"
else
  fail "Global config: ignoredTools broken (got: '$out')"
fi

# Project config must take precedence over global config
cat > "$NOPROJECT/node9.config.json" << 'EOF'
{
  "settings": { "mode": "standard" },
  "policy": { "dangerousWords": [], "ignoredTools": [] },
  "environments": {}
}
EOF

out=$(cd "$NOPROJECT" && echo '{"tool_name":"nuke_everything","tool_input":{}}' | HOME="$GLOBAL_HOME" $NODE9 check 2>/dev/null)
if [ -z "$out" ]; then
  pass "Project config takes precedence over global config"
else
  fail "Project config did not override global config (got: '$out')"
fi

rm -rf "$GLOBAL_HOME" "$NOPROJECT"

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

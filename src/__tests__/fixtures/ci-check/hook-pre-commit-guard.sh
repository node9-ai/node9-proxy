#!/bin/sh
# PreToolUse guard for Bash `git commit` calls: runs the staged-file lint gate before an agent
# commits, even when the git pre-commit hook was never installed.
#
#   * reads the hook JSON from stdin and extracts .tool_input.command
#   * exits 0 fast for anything that is not a `git commit`
#   * SKIP_HOOKS=1 (in the environment or as a command prefix) is the emergency bypass
#   * on a failed gate: exit 2, which blocks the tool call and shows stderr to the agent

input=$(cat)

# Fast path: most Bash calls are not commits; skip the Python spawn for them.
case "$input" in
    *commit*) ;;
    *) exit 0 ;;
esac

python_cmd=${HOOK_PYTHON:-}
if [ -z "$python_cmd" ]; then
    project_dir=${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || true)}
    if [ -x "$project_dir/.venv/bin/python" ]; then
        python_cmd="$project_dir/.venv/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        python_cmd=python3
    fi
fi
if [ -z "$python_cmd" ]; then
    echo "commit guard: python3 unavailable; guard disabled" >&2
    exit 0
fi

# Parse the hook JSON with Python (no jq dependency) and decide whether this is a commit.
is_commit=$(printf '%s' "$input" | "$python_cmd" -c '
import json, shlex, sys
cmd = json.load(sys.stdin).get("tool_input", {}).get("command", "")
env = {}
words = shlex.split(cmd)
while words and "=" in words[0]:
    k, _, v = words.pop(0).partition("=")
    env[k] = v
print("skip" if env.get("SKIP_HOOKS") == "1" else ("yes" if words[:2] == ["git", "commit"] else "no"))
')

[ "$is_commit" = "yes" ] || exit 0
[ "${SKIP_HOOKS:-}" = "1" ] && exit 0

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
if ! (cd "$repo_root" && "$python_cmd" scripts/check_staged.py >&2); then
    echo "commit guard: 'scripts/check_staged.py' FAILED, commit blocked." >&2
    echo "  Fix the lint errors, re-stage, then retry. Emergency bypass: SKIP_HOOKS=1." >&2
    exit 2
fi

exit 0

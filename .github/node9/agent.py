import json
import os
import re
import subprocess
import urllib.request
import urllib.error
import time
import sys

import anthropic
from dotenv import load_dotenv
from node9 import ActionDeniedException

import tools

load_dotenv()
# Initialize client
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

CI_CONTEXT_PATH = os.path.expanduser("~/.node9/ci-context.json")


def _write_github_summary(issues_found, issues_fixed, pr_url=""):
    """Writes the review results to the GitHub Actions Summary page."""
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_file:
        print("⚠️  GITHUB_STEP_SUMMARY not set — skipping step summary", flush=True)
        return

    with open(summary_file, 'a') as f:
        f.write("### 🤖 node9 AI Code Review\n\n")
        if pr_url:
            f.write(f"**[View Draft PR on GitHub]({pr_url})**\n\n")
        if issues_found:
            f.write("#### Issues Found\n")
            for issue in issues_found:
                f.write(f"- {issue}\n")
            f.write("\n")
        if issues_fixed:
            f.write("#### Fixes Applied\n")
            for fix in issues_fixed:
                f.write(f"- {fix}\n")
            f.write("\n")
        if not issues_found and not issues_fixed:
            f.write("No issues found in this diff.\n\n")
        f.write("> **Action Required:** Go to the [node9 Dashboard](https://app.node9.ai) to Approve, Discard, or Run Again.\n")


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _github_request(method: str, url: str, github_token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if data else {}),
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


def _build_pr_body(
    issues_found: list, issues_fixed: list,
    tests_passed: int, tests_total: int,
    files_changed: list, last_test_output: str,
    iteration: int,
) -> str:
    lines = ["## 🤖 node9 AI Code Review\n"]

    # Test results
    if tests_total > 0:
        icon = "✅" if tests_passed == tests_total else "❌"
        lines.append(f"### {icon} Tests: {tests_passed}/{tests_total} passed\n")
        if tests_passed < tests_total and last_test_output:
            lines.append("<details><summary>Test output</summary>\n")
            lines.append(f"\n```\n{last_test_output.strip()}\n```\n")
            lines.append("</details>\n")
    else:
        lines.append("### ⚪ Tests: not run\n")

    # Issues found
    if issues_found:
        lines.append("### 🔍 Issues Found\n")
        for issue in issues_found:
            lines.append(f"- {issue}\n")
        lines.append("")

    # Fixes applied
    if issues_fixed:
        lines.append("### 🔧 Fixes Applied\n")
        for fix in issues_fixed:
            lines.append(f"- {fix}\n")
        lines.append("")

    # Files changed
    if files_changed:
        lines.append("### 📁 Files Changed\n")
        for f in files_changed:
            lines.append(f"- `{f}`\n")
        lines.append("")

    if not issues_found and not issues_fixed:
        lines.append("_No issues found in this diff._\n")

    if iteration > 1:
        lines.append(f"\n---\n_Iteration {iteration} — updated by node9 AI reviewer_\n")
    else:
        lines.append("\n---\n_Review and approve in the [node9 Dashboard](https://app.node9.ai)_\n")

    return "".join(lines)


def _open_or_find_draft_pr(
    fix_branch: str, base_branch: str, repo: str, github_token: str,
    issues_found: list, issues_fixed: list,
    tests_passed: int, tests_total: int,
    files_changed: list, last_test_output: str,
    iteration: int,
) -> int | None:
    pr_body = _build_pr_body(
        issues_found, issues_fixed, tests_passed, tests_total,
        files_changed, last_test_output, iteration,
    )
    create_body = {
        "title": f"[node9] AI review: {base_branch}",
        "head": fix_branch,
        "base": base_branch,
        "draft": True,
        "body": pr_body,
    }
    result, status = _github_request("POST", f"https://api.github.com/repos/{repo}/pulls", github_token, create_body)
    if status == 201:
        print(f"  ✅ Draft PR created: #{result.get('number')}", flush=True)
        return result.get("number")

    # 422 = already exists; try to find it. Anything else = real error.
    if status not in (422, 200):
        print(f"  ⚠️  PR create returned HTTP {status}: {result}", flush=True)

    owner = repo.split("/")[0]
    result, status = _github_request(
        "GET",
        f"https://api.github.com/repos/{repo}/pulls?head={owner}:{fix_branch}&base={base_branch}&state=open",
        github_token,
    )
    if status == 200 and result:
        pr_num = result[0].get("number")
        print(f"  ♻️  Found existing Draft PR: #{pr_num} — updating body...", flush=True)
        # Update the PR body with fresh review details
        _github_request(
            "PATCH",
            f"https://api.github.com/repos/{repo}/pulls/{pr_num}",
            github_token,
            {"body": pr_body},
        )
        return pr_num
    print(f"  ⚠️  Could not find existing PR either (HTTP {status}): {result}", flush=True)
    return None


def _get_pr_review_comments(pr_number: int, repo: str, github_token: str) -> str:
    result, status = _github_request(
        "GET",
        f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments",
        github_token,
    )
    if status != 200 or not result:
        return ""
    lines = []
    for c in result:
        file_path = c.get("path", "?")
        line = c.get("line") or c.get("original_line", "?")
        comment_body = c.get("body", "")
        lines.append(f"- {file_path}:{line}: {comment_body}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Token management helpers
# ---------------------------------------------------------------------------

def _truncate_output(text: str, max_chars: int = 8000) -> str:
    """Middle-out truncation: keep the first and last half so both the error
    header and the test summary survive. Tail-only truncation drops the error."""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    removed = len(text) - max_chars
    return text[:half] + f"\n\n... [{removed} chars truncated] ...\n\n" + text[-half:]


def _apply_rolling_cache(messages: list) -> None:
    """Keep exactly one cache breakpoint, always on the last user message.
    Strips stale markers from earlier messages so we never exceed the 4-breakpoint limit
    and so the cache window moves forward with the conversation."""
    for msg in messages:
        if msg["role"] == "user" and isinstance(msg["content"], list):
            for block in msg["content"]:
                if isinstance(block, dict):
                    block.pop("cache_control", None)
    for msg in reversed(messages):
        if msg["role"] == "user" and isinstance(msg["content"], list):
            for block in reversed(msg["content"]):
                if isinstance(block, dict):
                    block["cache_control"] = {"type": "ephemeral"}
                    return


def _create_with_retry(client, **kwargs):
    """Wrap client.messages.create with exponential backoff on 429."""
    for attempt in range(5):
        try:
            return client.messages.create(**kwargs)
        except anthropic.RateLimitError:
            wait = 30 * (2 ** attempt)
            print(f"  ⏳ Rate limited — waiting {wait}s before retry {attempt + 1}/5...", flush=True)
            time.sleep(wait)
    return client.messages.create(**kwargs)  # Final attempt — let it raise


# ---------------------------------------------------------------------------
# CI context
# ---------------------------------------------------------------------------

def _write_ci_context(tests_passed, tests_total, files_changed, issues_found, issues_fixed, pr_url="", pr_number=None):
    os.makedirs(os.path.dirname(CI_CONTEXT_PATH), exist_ok=True)
    # Use the freshly created PR number if available; otherwise fall back to the
    # env var (set for iteration 2+ by the RUN_AGAIN dispatch).
    stored_pr_number = pr_number or os.environ.get("DRAFT_PR_NUMBER") or None
    with open(CI_CONTEXT_PATH, "w") as f:
        json.dump({
            "tests_after": {"passed": tests_passed, "total": tests_total},
            "files_changed": files_changed,
            "issues_found": issues_found,
            "issues_fixed": issues_fixed,
            "github_repository": os.environ.get("GITHUB_REPOSITORY"),
            "github_head_ref": os.environ.get("GITHUB_HEAD_REF"),
            "github_token": os.environ.get("GITHUB_TOKEN"),
            "iteration": int(os.environ.get("ITERATION", "1")),
            "draft_pr_number": stored_pr_number,
            "draft_pr_url": pr_url,
        }, f)


# ---------------------------------------------------------------------------
# Agent entry point
# ---------------------------------------------------------------------------

def execute_review_fix() -> None:
    original_branch = os.environ.get("GITHUB_HEAD_REF", "").strip()
    if not original_branch:
        # GITHUB_HEAD_REF is only set for PR events; derive from git for push events
        try:
            original_branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=tools.WORKSPACE_DIR, stderr=subprocess.STDOUT,
            ).decode().strip()
            if original_branch in ("HEAD", ""):
                original_branch = "unknown-branch"
        except Exception:
            original_branch = "unknown-branch"

    base_branch = os.environ.get("GITHUB_BASE_REF", "").strip() or "main"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    iteration = int(os.environ.get("ITERATION", "1"))
    feedback = os.environ.get("FEEDBACK", "")
    draft_pr_number_str = os.environ.get("DRAFT_PR_NUMBER", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    fix_branch = f"node9/fix/{original_branch}"

    print(f"🤖 node9 CI Review — iteration {iteration} on {original_branch} → {base_branch}", flush=True)

    diff_output = tools._run_unprotected(f"git diff origin/{base_branch}...HEAD")

    if iteration == 1:
        diff_truncated = len(diff_output) > 8000
        user_content = (
            f"Review the following git diff for {original_branch} → {base_branch} "
            f"and fix any issues you find.\n\n"
            f"Git diff:\n```\n{diff_output[:8000]}\n```\n\n"
            "Instructions:\n1. Read files\n2. Fix bugs\n3. Run tests\n4. Respond with summary."
        )
    else:
        pr_comments = ""
        if draft_pr_number_str:
            pr_comments = _get_pr_review_comments(int(draft_pr_number_str), repo, github_token)

        user_content = (
            f"Iteration {iteration}. Apply requested changes.\n\n"
            + (f"Feedback: {feedback}\n\n" if feedback else "")
            + (f"PR line comments:\n{pr_comments}\n\n" if pr_comments else "")
        )

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": user_content,
                    "cache_control": {"type": "ephemeral"}
                }
            ]
        }
    ]

    files_changed: list = []
    issues_found: list = []
    issues_fixed: list = []
    tests_passed = 0
    tests_total = 0
    last_test_output = ""

    _write_ci_context(0, 0, [], [], [])

    for i in range(20):
        # Roll the cache checkpoint to the latest message before every API call.
        # This keeps input tokens low as history grows and avoids 429 rate limits.
        _apply_rolling_cache(messages)

        response = _create_with_retry(
            client,
            model="claude-sonnet-4-6",
            max_tokens=4096,
            extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
            tools=[
                {
                    "name": "read_code",
                    "description": "Read a source file",
                    "input_schema": {
                        "type": "object",
                        "properties": {"filename": {"type": "string"}},
                        "required": ["filename"],
                    },
                },
                {
                    "name": "write_code",
                    "description": "Write or fix a source file",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "filename": {"type": "string"},
                            "content": {"type": "string"},
                        },
                        "required": ["filename", "content"],
                    },
                },
                {
                    "name": "run_bash",
                    "description": "Run a bash command (tests, linting, etc)",
                    "input_schema": {
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"],
                    },
                },
            ],
            system=[
                {
                    "type": "text",
                    "text": (
                        "You are a CI code reviewer and fixer. "
                        "Review the diff, fix issues, run tests to verify your fixes, "
                        "then respond with a plain text summary in this format:\n"
                        "FOUND: <one-line description>\n"
                        "FIXED: <one-line description>"
                    ),
                    "cache_control": {"type": "ephemeral"}
                }
            ],
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            # Verification gate: run tests one final time before accepting the summary.
            # Only force re-loop if Claude hasn't already tried 3+ times (avoid exhausting 20 loops).
            if i < 3:
                print("🕵️  Final verification: running tests...", flush=True)
                test_cmd = os.environ.get("NODE9_TEST_CMD", "npm test 2>&1 | tail -50")
                verify = tools._run_unprotected(test_cmd)
                failed = re.search(r"(\d+)\s+failed", verify)
                if failed and int(failed.group(1)) > 0:
                    print(f"❌ {failed.group(1)} test(s) still failing — forcing another fix loop...", flush=True)
                    if m_p := re.search(r"(\d+)\s+passed", verify):
                        p = int(m_p.group(1))
                        f = int(failed.group(1))
                        tests_passed, tests_total = p, p + f
                        last_test_output = verify
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({"role": "user", "content": [{
                        "type": "text",
                        "text": f"Tests are still failing. Please fix them:\n\n{_truncate_output(verify)}",
                    }]})
                    time.sleep(12)
                    continue

            for block in response.content:
                if hasattr(block, "text") and block.text:
                    for line in block.text.splitlines():
                        clean = line.strip()
                        if clean.upper().startswith("FOUND:"):
                            item = clean[6:].strip()
                            if item: issues_found.append(item[:200])
                        elif clean.upper().startswith("FIXED:"):
                            item = clean[6:].strip()
                            if item: issues_fixed.append(item[:200])
                    break
            break

        tool_results = []
        for tool_use in response.content:
            if tool_use.type != "tool_use": continue

            name, args = tool_use.name, tool_use.input
            print(f"  → {name}({list(args.keys())})", flush=True)

            func = getattr(tools, name)
            result = func(**args)

            if name == "write_code":
                fname = args.get("filename", "")
                if fname and fname not in files_changed:
                    files_changed.append(fname)

            if name == "run_bash" and isinstance(result, str):
                m_passed = re.search(r"(\d+)\s+passed", result)
                m_failed = re.search(r"(\d+)\s+failed", result)
                if m_passed:
                    p = int(m_passed.group(1))
                    f = int(m_failed.group(1)) if m_failed else 0
                    tests_passed = p
                    tests_total = p + f
                    last_test_output = result  # keep latest test run output for PR body

            sanitized_result = _truncate_output(str(result))

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": sanitized_result,
            })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

        print(f"  (Loop {i+1}/20) Waiting 12s...", flush=True)
        time.sleep(12)

    # 1. Prepare the local branch
    tools._run_unprotected(f"git checkout -b {fix_branch} 2>/dev/null || git checkout {fix_branch}")
    # Remove pycache created by pip install — they must not go into the PR
    tools._run_unprotected("find . -type d -name '__pycache__' -not -path './.git/*' -exec rm -rf {} + 2>/dev/null || true")
    tools._run_unprotected("find . -name '*.pyc' -not -path './.git/*' -delete 2>/dev/null || true")
    tools._run_unprotected("git add -A")
    commit_msg = f"node9: automated fixes for {original_branch} (iteration {iteration})"
    subprocess.run(["git", "commit", "-m", commit_msg, "--allow-empty"], cwd=tools.WORKSPACE_DIR, check=True)

    # 2. PUSH PREVIEW (Unprotected): Makes branch exist on GitHub so PR can be created
    print("📤 Uploading preview branch...", flush=True)
    push_result = tools._run_unprotected(f"git push origin {fix_branch} --force")
    if push_result.startswith("Error:"):
        print(f"⚠️  Preview push failed: {push_result}", flush=True)
    else:
        print(f"✅ Preview branch pushed: {push_result.strip() or 'ok'}", flush=True)

    # 3. CREATE DRAFT PR & GET LINK
    pr_url = ""
    pr_number = None
    if not github_token:
        print("⚠️  GITHUB_TOKEN not set — skipping Draft PR creation", flush=True)
    elif not repo:
        print("⚠️  GITHUB_REPOSITORY not set — skipping Draft PR creation", flush=True)
    elif push_result.startswith("Error:"):
        print("⚠️  Skipping Draft PR — preview branch push failed", flush=True)
    else:
        pr_number = _open_or_find_draft_pr(
            fix_branch, original_branch, repo, github_token,
            issues_found, issues_fixed, tests_passed, tests_total,
            files_changed, last_test_output, iteration,
        )
        if pr_number:
            pr_url = f"https://github.com/{repo}/pull/{pr_number}"
            print(f"👀 PREVIEW YOUR CHANGES HERE: {pr_url}", flush=True)
        else:
            print(f"⚠️  Draft PR creation failed for {fix_branch} → {original_branch}", flush=True)

    # 4. GitHub Actions Step Summary (written here so it includes the PR link)
    _write_github_summary(issues_found, issues_fixed, pr_url=pr_url)

    # 5. FINAL CONTEXT UPDATE: Includes the PR Link for the Node9 Dashboard
    _write_ci_context(tests_passed, tests_total, files_changed, issues_found, issues_fixed, pr_url=pr_url, pr_number=pr_number)

    # 6. THE GOVERNANCE GATE (Protected Push)
    try:
        print("🛡️ Node9: Waiting for dashboard approval...", flush=True)
        tools.governance_push(f"git push origin {fix_branch}")
        print("✅ Push approved and completed.")
    except ActionDeniedException:
        print("\n🛑 Action Denied: Review discarded. PR can be closed manually.", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    execute_review_fix()
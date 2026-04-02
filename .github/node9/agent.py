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


def _write_github_summary(issues_found, issues_fixed):
    """Writes the review results to the GitHub Actions Summary page."""
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_file:
        return
    
    with open(summary_file, 'a') as f:
        f.write("### 🤖 node9 AI Code Review Summary\n")
        f.write("#### 🔍 Issues Found:\n")
        for issue in issues_found:
            f.write(f"- {issue}\n")
        f.write("\n#### ✅ Fixes Applied:\n")
        for fix in issues_fixed:
            f.write(f"- {fix}\n")
        f.write("\n> **Action Required:** Please go to the Node9 Dashboard to Approve or Discard these changes.")


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


def _open_or_find_draft_pr(fix_branch: str, base_branch: str, repo: str, github_token: str) -> int | None:
    body = {
        "title": f"[node9] AI review: {base_branch}",
        "head": fix_branch,
        "base": base_branch,
        "draft": True,
        "body": "Automated fixes by node9 CI code reviewer.\n\nReview this diff and click **Approve & Merge** in the node9 dashboard.",
    }
    result, status = _github_request("POST", f"https://api.github.com/repos/{repo}/pulls", github_token, body)
    if status == 201:
        return result.get("number")

    owner = repo.split("/")[0]
    result, status = _github_request(
        "GET",
        f"https://api.github.com/repos/{repo}/pulls?head={owner}:{fix_branch}&base={base_branch}&state=open",
        github_token,
    )
    if status == 200 and result:
        return result[0].get("number")
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
# CI context
# ---------------------------------------------------------------------------

def _write_ci_context(tests_passed, tests_total, files_changed, issues_found, issues_fixed, pr_url=""):
    os.makedirs(os.path.dirname(CI_CONTEXT_PATH), exist_ok=True)
    
    # Copy lists to avoid modifying original lists in place (since we run context updates in a loop)
    found_copy = list(issues_found)
    if pr_url:
        found_copy.insert(0, f"🔗 [View Draft PR on GitHub]({pr_url})")

    with open(CI_CONTEXT_PATH, "w") as f:
        json.dump({
            "tests_after": {"passed": tests_passed, "total": tests_total},
            "files_changed": files_changed,
            "issues_found": found_copy,
            "issues_fixed": issues_fixed,
            "github_repository": os.environ.get("GITHUB_REPOSITORY"),
            "github_head_ref": os.environ.get("GITHUB_HEAD_REF"),
            "github_token": os.environ.get("GITHUB_TOKEN"),
            "iteration": int(os.environ.get("ITERATION", "1")),
            "draft_pr_number": os.environ.get("DRAFT_PR_NUMBER"),
        }, f)


# ---------------------------------------------------------------------------
# Agent entry point
# ---------------------------------------------------------------------------

def execute_review_fix() -> None:
    original_branch = os.environ.get("GITHUB_HEAD_REF", "unknown-branch")
    base_branch = os.environ.get("GITHUB_BASE_REF", "main")
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

    _write_ci_context(0, 0, [], [], [])

    for i in range(20):
        response = client.messages.create(
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

            sanitized_result = str(result)
            if len(sanitized_result) > 10000:
                sanitized_result = sanitized_result[:10000] + "\n... (truncated)"

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": sanitized_result,
            })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

        print(f"  (Loop {i+1}/20) Waiting 12s...", flush=True)
        time.sleep(12) 

    # 1. Update GitHub Actions Step Summary UI
    _write_github_summary(issues_found, issues_fixed)

    # 2. Prepare the local branch
    tools._run_unprotected(f"git checkout -b {fix_branch} 2>/dev/null || git checkout {fix_branch}")
    tools._run_unprotected("git add -A")
    commit_msg = f"node9: automated fixes for {original_branch} (iteration {iteration})"
    subprocess.run(["git", "commit", "-m", commit_msg, "--allow-empty"], cwd=tools.WORKSPACE_DIR, check=True)

    # 3. PUSH PREVIEW (Unprotected): Makes branch exist on GitHub so PR can be created
    print("📤 Uploading preview branch...", flush=True)
    tools._run_unprotected(f"git push origin {fix_branch} --force")

    # 4. CREATE DRAFT PR & GET LINK
    pr_url = ""
    if github_token and repo:
        pr_number = _open_or_find_draft_pr(fix_branch, original_branch, repo, github_token)
        if pr_number:
            pr_url = f"https://github.com/{repo}/pull/{pr_number}"
            print(f"👀 PREVIEW YOUR CHANGES HERE: {pr_url}", flush=True)

    # 5. FINAL CONTEXT UPDATE: Includes the PR Link for the Node9 Dashboard
    _write_ci_context(tests_passed, tests_total, files_changed, issues_found, issues_fixed, pr_url=pr_url)

    # 6. THE GOVERNANCE GATE (Protected Push)
    try:
        print("🛡️ Node9: Waiting for dashboard approval...", flush=True)
        tools.run_bash(f"git push origin {fix_branch}")
        print("✅ Push approved and completed.")
    except ActionDeniedException:
        print("\n🛑 Action Denied: Review discarded. PR can be closed manually.", flush=True)
        sys.exit(0) 

if __name__ == "__main__":
    execute_review_fix()
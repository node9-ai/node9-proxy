import json
import os
import re
import subprocess
import urllib.request
import urllib.error

import anthropic
from dotenv import load_dotenv

import tools

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

CI_CONTEXT_PATH = os.path.expanduser("~/.node9/ci-context.json")


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

    # 422 = PR already exists — find it
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

def _write_ci_context(
    tests_passed: int,
    tests_total: int,
    files_changed: list,
    issues_found: list,
    issues_fixed: list,
) -> None:
    # GITHUB_TOKEN is included so the SaaS backend can call the GitHub API for
    # APPROVE_MERGE, DISCARD, and RUN_AGAIN within the token's 1-hour window.
    # The CI runner is ephemeral; the token is sent over HTTPS and used only
    # during the approval window. It is never logged or surfaced to the agent.
    os.makedirs(os.path.dirname(CI_CONTEXT_PATH), exist_ok=True)
    with open(CI_CONTEXT_PATH, "w") as f:
        json.dump(
            {
                "tests_after": {"passed": tests_passed, "total": tests_total},
                "files_changed": files_changed,
                "issues_found": issues_found,
                "issues_fixed": issues_fixed,
                "github_repository": os.environ.get("GITHUB_REPOSITORY"),
                "github_head_ref": os.environ.get("GITHUB_HEAD_REF"),
                "github_token": os.environ.get("GITHUB_TOKEN"),
                "iteration": int(os.environ.get("ITERATION", "1")),
                "draft_pr_number": os.environ.get("DRAFT_PR_NUMBER"),
            },
            f,
        )


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

    print(f"🤖 node9 CI Review — iteration {iteration} on {original_branch} → {base_branch}")

    # Get the diff (unprotected — reading git metadata, not writing)
    diff_output = tools._run_unprotected(f"git diff origin/{base_branch}...HEAD")

    if iteration == 1:
        diff_truncated = len(diff_output) > 8000
        if diff_truncated:
            print(f"⚠️  Diff is {len(diff_output)} chars — truncated to 8000 for context window. Agent will read full files as needed.")
        user_message = (
            f"Review the following git diff for {original_branch} → {base_branch} "
            f"and fix any issues you find.\n\n"
            f"Git diff{' (truncated — read files directly for full context)' if diff_truncated else ''}:\n```\n{diff_output[:8000]}\n```\n\n"
            "Instructions:\n"
            "1. Read the changed files to understand context\n"
            "2. Fix bugs, security issues, or code quality problems\n"
            "3. Run tests to verify your fixes didn't break anything\n"
            "4. When done, respond with a plain-text summary of what you fixed\n\n"
            "Do NOT re-run the full test suite to validate the developer's code — "
            "only run tests to confirm YOUR changes don't break anything."
        )
    else:
        pr_comments = ""
        if draft_pr_number_str:
            pr_comments = _get_pr_review_comments(int(draft_pr_number_str), repo, github_token)

        user_message = (
            f"Iteration {iteration}. Apply the requested changes to the code.\n\n"
            + (f"Feedback from reviewer:\n{feedback}\n\n" if feedback else "")
            + (f"PR line comments:\n{pr_comments}\n\n" if pr_comments else "")
            + "Read the current files, make the changes, run tests to verify, "
            "then respond with a plain-text summary."
        )

    messages = [{"role": "user", "content": user_message}]

    files_changed: list = []
    issues_found: list = []
    issues_fixed: list = []
    tests_passed = 0
    tests_total = 0

    # Write a stub ci-context.json immediately so that every SDK call in the loop
    # carries ciContext. This triggers node9 SaaS auto-provisioning of CI policies
    # on the very first tool call, not just at the git push gate.
    _write_ci_context(0, 0, [], [], [])

    for _ in range(20):
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
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
            system=(
                "You are a CI code reviewer and fixer. "
                "Review the diff, fix issues, run tests to verify your fixes, "
                "then respond with a plain text summary in this format:\n"
                "FOUND: <one-line description of each issue found>\n"
                "FIXED: <one-line description of each fix applied>\n"
                "Do not modify test files unless the tests themselves are wrong."
            ),
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            # Agent is done — extract FOUND/FIXED from structured summary
            for block in response.content:
                if hasattr(block, "text") and block.text:
                    for line in block.text.splitlines():
                        clean = line.strip()
                        if clean.upper().startswith("FOUND:"):
                            item = clean[6:].strip()
                            if item:
                                issues_found.append(item[:200])
                        elif clean.upper().startswith("FIXED:"):
                            item = clean[6:].strip()
                            if item:
                                issues_fixed.append(item[:200])
                    break
            break

        # Execute all tool calls in this response
        tool_results = []
        for tool_use in response.content:
            if tool_use.type != "tool_use":
                continue

            name, args = tool_use.name, tool_use.input
            print(f"  → {name}({list(args.keys())})")

            func = getattr(tools, name)
            result = func(**args)

            # Track files written
            if name == "write_code":
                fname = args.get("filename", "")
                if fname and fname not in files_changed:
                    files_changed.append(fname)

            # Parse test counts from output (pytest / jest style)
            if name == "run_bash" and isinstance(result, str):
                m_passed = re.search(r"(\d+)\s+passed", result)
                m_failed = re.search(r"(\d+)\s+failed", result)
                if m_passed:
                    p = int(m_passed.group(1))
                    f = int(m_failed.group(1)) if m_failed else 0
                    tests_passed = p
                    tests_total = p + f

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": str(result),
            })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    # Write ci-context.json — node9 reads this at the git push gate
    _write_ci_context(tests_passed, tests_total, files_changed, issues_found, issues_fixed)

    # Stage and push fixes to node9/fix/<branch>
    # The @protect on run_bash will intercept the git push — that's the HITL gate
    tools._run_unprotected(f"git checkout -b {fix_branch} 2>/dev/null || git checkout {fix_branch}")
    tools._run_unprotected("git add -A")
    # Use subprocess list to avoid shell injection via attacker-controlled branch name
    commit_msg = f"node9: automated fixes for {original_branch} (iteration {iteration})"
    subprocess.run(
        ["git", "commit", "-m", commit_msg, "--allow-empty"],
        cwd=tools.WORKSPACE_DIR,
        check=True,
    )

    # THIS is the governance gate — node9 intercepts, sends dashboard notification,
    # blocks until human approves, discards, or requests another iteration
    tools.run_bash(f"git push origin {fix_branch}")

    # If we reach here, human approved — open (or find existing) Draft PR
    if github_token and repo:
        pr_number = _open_or_find_draft_pr(fix_branch, original_branch, repo, github_token)
        if pr_number:
            print(f"✅ Draft PR #{pr_number} ready for review")
        else:
            print("⚠️  Could not open Draft PR — push succeeded but PR creation failed")


if __name__ == "__main__":
    execute_review_fix()

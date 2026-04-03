import json
import os
import re
import subprocess
import urllib.request
import urllib.error
import time

import anthropic
from dotenv import load_dotenv

import tools

load_dotenv()
_api_key = os.getenv("ANTHROPIC_API_KEY")
if not _api_key:
    raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot start agent")
client = anthropic.Anthropic(api_key=_api_key)

CI_CONTEXT_PATH = os.path.expanduser("~/.node9/ci-context.json")

# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------

_SKIP_DIFF_RE = re.compile(
    r"diff --git a/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|.*\.lock"
    r"|.*migrations/.*|.*\.generated\.\w|dist/|build/|.*\.min\.(js|css)|.*\.snap"
    r"|\.github/node9/|\.github/workflows/)",
    re.IGNORECASE,
)


def _filter_diff(raw_diff: str) -> str:
    sections = re.split(r"(?=^diff --git )", raw_diff, flags=re.MULTILINE)
    kept = []
    for section in sections:
        if not section.startswith("diff --git"):
            kept.append(section)
            continue
        if _SKIP_DIFF_RE.search(section.splitlines()[0]):
            continue
        kept.append(section)
    return "".join(kept)


def _chunk_diff(diff: str, max_chars: int = 8000) -> str:
    if len(diff) <= max_chars:
        return diff
    sections = re.split(r"(?=^diff --git )", diff, flags=re.MULTILINE)
    kept: list[str] = []
    total = 0
    skipped: list[str] = []
    for section in sections:
        if not section.startswith("diff --git"):
            kept.append(section)
            continue
        if total + len(section) <= max_chars:
            kept.append(section)
            total += len(section)
        else:
            m = re.match(r"diff --git a/(\S+)", section)
            skipped.append(m.group(1) if m else "?")
    result = "".join(kept)
    if skipped:
        result += f"\n\n# ⚠️  {len(skipped)} file(s) omitted (diff too large): {', '.join(skipped)}"
    return result


def _count_diff_lines(diff: str) -> int:
    return sum(
        1 for line in diff.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    )


def _diff_file_list(diff: str) -> list:
    files = []
    for line in diff.splitlines():
        m = re.match(r"diff --git a/(\S+)", line)
        if m and m.group(1) not in files:
            files.append(m.group(1))
    return files


# ---------------------------------------------------------------------------
# Test output helpers
# ---------------------------------------------------------------------------

def _parse_test_counts(output: str) -> tuple[int, int]:
    lines = output.splitlines()
    for line in reversed(lines):
        if "Tests" in line and ("passed" in line or "failed" in line):
            m_p = re.search(r"(\d+)\s+passed", line)
            m_f = re.search(r"(\d+)\s+failed", line)
            passed = int(m_p.group(1)) if m_p else 0
            failed = int(m_f.group(1)) if m_f else 0
            return passed, passed + failed
    return 0, 0


def _extract_test_summary(raw: str, max_chars: int = 2000) -> str:
    if len(raw) <= max_chars:
        return raw
    lines = raw.splitlines()
    summary_lines = [l for l in lines if re.search(r"\d+.*(passed|failed|total)", l)]
    failure_lines: list[str] = []
    in_failure = False
    for line in lines:
        if re.search(r"(^●\s|^FAIL\s|^FAILED\s|✕|✗|Error:)", line):
            in_failure = True
        if in_failure:
            if not line.strip():
                in_failure = False
            else:
                failure_lines.append(line)
                if len("\n".join(failure_lines)) > max_chars - 300:
                    failure_lines.append("... [truncated]")
                    break
    if failure_lines or summary_lines:
        combined = "\n".join(failure_lines) + "\n\n" + "\n".join(summary_lines)
        return combined[:max_chars]
    half = max_chars // 2
    return raw[:half] + f"\n\n... [truncated] ...\n\n" + raw[-half:]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _truncate_output(text: str, max_chars: int = 4000) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + f"\n\n... [truncated] ...\n\n" + text[-half:]


def _apply_rolling_cache(messages: list) -> None:
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
    for attempt in range(5):
        try:
            return client.messages.create(**kwargs)
        except (anthropic.RateLimitError, anthropic.APIStatusError) as e:
            if isinstance(e, anthropic.APIStatusError) and e.status_code != 529:
                raise
            wait = 30 * (2 ** attempt)
            print(f"  ⏳ API overloaded/rate-limited — waiting {wait}s (attempt {attempt+1}/5)...", flush=True)
            time.sleep(wait)
    return client.messages.create(**kwargs)


def _resolve_branch() -> str:
    # GITHUB_HEAD_REF is only set for pull_request events.
    # For push events, extract the branch from GITHUB_REF (refs/heads/<branch>).
    ref = os.environ.get("GITHUB_HEAD_REF") or ""
    if not ref:
        ref = os.environ.get("GITHUB_REF", "refs/heads/dev")
        ref = ref.replace("refs/heads/", "")
    return ref or "dev"


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
            "User-Agent": "Node9-CI-Runner",
            **({"Content-Type": "application/json"} if data else {}),
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except:
            return {}, e.code


def _post_pr_comment(pr_number: int, repo: str, github_token: str, comment: str, issues_fixed: list | None = None) -> None:
    if not pr_number or not github_token or not repo:
        return
    body = f"## 🔍 node9 Code Review\n\n{comment}"
    if issues_fixed:
        body += "\n\n### 🔧 Fixes Applied by Agent\n" + "\n".join(f"- {f}" for f in issues_fixed)
    body += "\n\n---\n*Automated review by node9 AI*"
    _github_request("POST", f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments", github_token, {"body": body})


def _open_or_find_draft_pr(fix_branch: str, base_branch: str, repo: str, github_token: str, pr_body: str) -> tuple:
    create_body = {"title": f"[node9] AI review: {base_branch}", "head": fix_branch, "base": base_branch, "draft": True, "body": pr_body}
    result, status = _github_request("POST", f"https://api.github.com/repos/{repo}/pulls", github_token, create_body)
    if status == 201:
        return result.get("number"), result.get("html_url")
    owner = repo.split("/")[0]
    result, status = _github_request("GET", f"https://api.github.com/repos/{repo}/pulls?head={owner}:{fix_branch}&base={base_branch}&state=open", github_token)
    if status == 200 and result:
        pr_num = result[0].get("number")
        _github_request("PATCH", f"https://api.github.com/repos/{repo}/pulls/{pr_num}", github_token, {"body": pr_body})
        return pr_num, result[0].get("html_url")
    return None, ""


def _write_github_summary(issues_found, issues_fixed, pr_url, before_out, after_out):
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    b_p, b_t = _parse_test_counts(before_out)
    a_p, a_t = _parse_test_counts(after_out)
    with open(summary_file, "a") as f:
        f.write(f"### 🤖 node9 AI Code Review\n\n[View PR]({pr_url})\n\n")
        f.write(f"**Tests:** {b_p}/{b_t} → {a_p}/{a_t} passed\n\n")
        if issues_found:
            f.write("#### Issues Found\n" + "\n".join(f"- {i}" for i in issues_found) + "\n\n")
        if issues_fixed:
            f.write("#### Fixes Applied\n" + "\n".join(f"- {f}" for f in issues_fixed) + "\n\n")


# ---------------------------------------------------------------------------
# Core Phases
# ---------------------------------------------------------------------------

def _phase1_baseline(base_branch, original_branch, iteration, test_cmd):
    raw_diff = tools._run_unprotected(f"git diff origin/{base_branch}...HEAD")
    filtered = _filter_diff(raw_diff)
    diff_lines = _count_diff_lines(filtered)
    print(f"  Diff: {diff_lines} lines across {len(_diff_file_list(filtered))} files")
    
    print("  Running baseline tests...")
    cwd = tools.WORKSPACE_DIR if hasattr(tools, 'WORKSPACE_DIR') else os.getcwd()
    proc = subprocess.run(test_cmd, shell=True, capture_output=True, text=True, cwd=cwd)
    before_output = proc.stdout + "\n" + proc.stderr
    
    print(f"\n--- DEBUG: RAW TEST OUTPUT ---\n{before_output}\n---------------------------\n")

    passed, total = _parse_test_counts(before_output)
    
    # Reliably determine if tests passed via the test runner exit code instead of regex parsing alone
    tests_passed = (proc.returncode == 0)
    
    print(f"  Baseline: {passed}/{total} passing (exit code: {proc.returncode})")
    
    skip = (iteration == 1) and tests_passed and (diff_lines < 100)
    return filtered, before_output, diff_lines, skip, tests_passed


def _phase2_engineering(filtered_diff, before_out, original_branch, base_branch, test_cmd, tests_passed=False):
    files_changed, issues_found, issues_fixed = [], [], []
    after_test_output = before_out
    file_list = ", ".join(_diff_file_list(filtered_diff))

    # Less aggressive prompt context if test runners are already green
    status_msg = (
        "The tests currently PASS. Only modify code if there is a critical security or logic bug."
        if tests_passed else "Fix ONLY bugs introduced by this diff."
    )

    user_content = (
        f"Review this git diff for `{original_branch}` → `{base_branch}`.\n\n"
        f"The following files are in the diff: {file_list}\n\n"
        f"```diff\n{_chunk_diff(filtered_diff, 8000)}\n```\n\n"
        "## Your instructions:\n"
        "1. **Read these files immediately** using `read_code` to understand the logic.\n"
        "2. **DO NOT use grep or find** to search for code. Use `read_code` on the files above.\n"
        f"3. Run tests: `run_bash('{test_cmd}')`.\n"
        f"4. {status_msg}\n"
        "5. Report FOUND: <issues> and FIXED: <fixes>."
    )

    messages = [{"role": "user", "content": [{"type": "text", "text": user_content, "cache_control": {"type": "ephemeral"}}]}]
    system_prompt = "You are a PRAGMATIC senior engineer. Fix bugs and STOP. Read files immediately. DO NOT WASTE TURNS ON GREP."

    for i in range(8):
        _apply_rolling_cache(messages)
        response = _create_with_retry(client, model="claude-sonnet-4-6", max_tokens=4096, extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"}, tools=[{"name": "read_code", "description": "Read file", "input_schema": {"type": "object", "properties": {"filename": {"type": "string"}}, "required": ["filename"]}}, {"name": "write_code", "description": "Fix file", "input_schema": {"type": "object", "properties": {"filename": {"type": "string"}, "content": {"type": "string"}}, "required": ["filename", "content"]}}, {"name": "run_bash", "description": "Run tests", "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}], system=[{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}], messages=messages)
        if response.stop_reason != "tool_use":
            for block in response.content:
                if hasattr(block, "text") and block.text:
                    for line in block.text.splitlines():
                        if line.upper().startswith("FOUND:"): issues_found.append(line[6:].strip())
                        elif line.upper().startswith("FIXED:"): issues_fixed.append(line[6:].strip())
            break
        tool_results = []
        for tool_use in response.content:
            if tool_use.type == "tool_use":
                print(f"  → {tool_use.name}({tool_use.input})")
                result = getattr(tools, tool_use.name)(**tool_use.input)
                if tool_use.name == "write_code": files_changed.append(tool_use.input['filename'])
                if tool_use.name == "run_bash" and any(k in tool_use.input['command'] for k in ("npm test", "npm run test", "vitest", "jest")):
                    after_test_output = result
                tool_results.append({"type": "tool_result", "tool_use_id": tool_use.id, "content": _truncate_output(str(result))})
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})
        time.sleep(5)
    return list(set(files_changed)), issues_found, issues_fixed, after_test_output


def _phase3_code_review(original_diff, agent_diff, before_out, after_out):
    b_p, b_t = _parse_test_counts(before_out)
    a_p, a_t = _parse_test_counts(after_out)
    prompt = (
        "You are a PRAGMATIC senior engineer reviewing a pull request.\n\n"
        f"## Original diff:\n```diff\n{_chunk_diff(original_diff, 5000)}\n```\n\n"
        f"## AI Agent Fixes:\n```diff\n{_chunk_diff(agent_diff, 3000)}\n```\n\n"
        f"## Tests: {b_p}/{b_t} -> {a_p}/{a_t}\n\n"
        "## Your task: Write a concise review. 1. IGNORE file locations. 2. IGNORE theoretical shell edge cases. 3. ONLY flag: Security, Logic errors, Performance. If fixable, use ISSUE: <desc>."
    )
    response = _create_with_retry(client, model="claude-sonnet-4-6", max_tokens=1500, messages=[{"role": "user", "content": prompt}])
    review_text = response.content[0].text.strip()
    issues_to_fix = [l[6:].strip() for l in review_text.splitlines() if l.startswith("ISSUE:")]
    return review_text, issues_to_fix


def _phase4_review_fix_loop(review_issues, test_cmd):
    files_changed, issues_fixed, after_test_output = [], [], ""
    user_content = f"Fix these review issues: {'; '.join(review_issues)}. Verify with {test_cmd}."
    messages = [{"role": "user", "content": user_content}]
    system_prompt = "You are a specialist refiner. Fix ONLY the issues listed. DO NOT GREP. Read the files directly."
    for i in range(3):
        response = _create_with_retry(client, model="claude-sonnet-4-6", max_tokens=4096, tools=[{"name": "read_code", "description": "Read file", "input_schema": {"type": "object", "properties": {"filename": {"type": "string"}}, "required": ["filename"]}}, {"name": "write_code", "description": "Fix file", "input_schema": {"type": "object", "properties": {"filename": {"type": "string"}, "content": {"type": "string"}}, "required": ["filename", "content"]}}, {"name": "run_bash", "description": "Run tests", "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}], system=system_prompt, messages=messages)
        if response.stop_reason != "tool_use": break
        tool_results = []
        for tool_use in response.content:
            if tool_use.type == "tool_use":
                result = getattr(tools, tool_use.name)(**tool_use.input)
                if tool_use.name == "write_code": files_changed.append(tool_use.input['filename'])
                if tool_use.name == "run_bash" and any(k in tool_use.input['command'] for k in ("npm test", "npm run test", "vitest", "jest")):
                    after_test_output = result
                tool_results.append({"type": "tool_result", "tool_use_id": tool_use.id, "content": str(result)})
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})
        time.sleep(5)
    return list(set(files_changed)), issues_fixed, after_test_output


# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

def execute_review_fix() -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "w") as f: f.write("")

    original_branch = _resolve_branch()
    # GITHUB_BASE_REF is empty string (not missing) on push events — use `or` not default arg.
    base_branch = os.environ.get("GITHUB_BASE_REF") or "main"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    iteration = int(os.environ.get("ITERATION", "1"))
    github_token = os.environ.get("GITHUB_TOKEN", "")
    test_cmd = os.environ.get("NODE9_TEST_CMD", "npm test")
    fix_branch = f"node9/fix/{original_branch}"

    print(f"🤖 node9 CI Review: {original_branch} → {base_branch}")

    # 1. Baseline
    filtered_diff, before_out, diff_lines, skip_eng, tests_passed = _phase1_baseline(base_branch, original_branch, iteration, test_cmd)
    
    # 2. Engineering
    files_changed, issues_found, issues_fixed, after_out = [], [], [], before_out
    if not skip_eng:
        files_changed, issues_found, issues_fixed, after_out = _phase2_engineering(filtered_diff, before_out, original_branch, base_branch, test_cmd, tests_passed)

    # 3. Review
    agent_diff = tools._run_unprotected("git diff HEAD") if files_changed else ""
    review_text, review_issues = _phase3_code_review(filtered_diff, agent_diff, before_out, after_out)

    # 4. Final Refinement
    if review_issues:
        f_files, f_fixed, f_out = _phase4_review_fix_loop(review_issues, test_cmd)
        files_changed = list(set(files_changed + f_files))
        issues_fixed += f_fixed
        if f_out: after_out = f_out

    # --- SAFETY CHECK: Prevent the agent from pushing broken code ---
    if files_changed and tests_passed:
        print("  Verifying tests after AI changes...")
        cwd = tools.WORKSPACE_DIR if hasattr(tools, 'WORKSPACE_DIR') else os.getcwd()
        verify_proc = subprocess.run(test_cmd, shell=True, capture_output=True, text=True, cwd=cwd)
        
        if verify_proc.returncode != 0:
            print("  ❌ AI changes broke the tests! Reverting to prevent CI failure.")
            tools._run_unprotected("git reset --hard HEAD")
            tools._run_unprotected("git clean -fd")
            files_changed = []
            issues_fixed = ["Attempted fixes were reverted because they broke the test suite."]
            after_out = before_out

    # 5. Delivery
    tools._run_unprotected(f"git checkout -B {fix_branch}")
    
    if files_changed:
        tools._run_unprotected("git add -A")
        
    subprocess.run(["git", "commit", "-m", "node9 review", "--allow-empty"], cwd=tools.WORKSPACE_DIR if hasattr(tools, 'WORKSPACE_DIR') else os.getcwd())
    tools._run_unprotected(f"git push origin {fix_branch} --force")

    pr_num, pr_url = _open_or_find_draft_pr(fix_branch, base_branch, repo, github_token, "AI Review Complete")
    if pr_num and review_text:
        _post_pr_comment(pr_num, repo, github_token, review_text, issues_fixed)

    _write_github_summary(issues_found, issues_fixed, pr_url, before_out, after_out)
    print(f"✅ Review complete: {pr_url}")

if __name__ == "__main__":
    execute_review_fix()
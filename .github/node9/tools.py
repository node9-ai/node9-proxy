"""
Governed tools for the CI code review agent.

@protect wraps every agent-facing tool — each call is audited via node9.
Git plumbing (_run_unprotected) is intentionally excluded from audit.
DLP scanning and path safety run before anything touches disk.
"""
import os
import re
import subprocess

from node9 import protect, dlp_scan, safe_path

WORKSPACE_DIR = os.environ.get("GITHUB_WORKSPACE") or os.path.abspath("workspace")

# Files that add noise but no signal to a code review.
_SKIP_DIFF_RE = re.compile(
    r"diff --git a/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|.*\.lock"
    r"|.*migrations/.*|.*\.generated\.\w+|dist/|build/|.*\.min\.(js|css)|.*\.snap"
    r"|\.github/node9/|\.github/workflows/)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Governed tools — every call audited via node9
# ---------------------------------------------------------------------------

@protect("bash")
def run_bash(command: str) -> str:
    """Run a bash command in the workspace and return output."""
    try:
        result = subprocess.check_output(
            ["bash", "-c", command],
            stderr=subprocess.STDOUT,
            cwd=WORKSPACE_DIR,
            timeout=300,
        )
        return result.decode(errors="replace")
    except subprocess.CalledProcessError as e:
        return f"exit {e.returncode}:\n{e.output.decode(errors='replace')}"
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 300s"


@protect("write_code")
def write_code(filename: str, content: str) -> str:
    """Write content to a file after DLP scanning."""
    hit = dlp_scan(filename, content)
    if hit:
        return f"BLOCKED by DLP: {hit}. Do not write secrets to files."
    path = safe_path(filename, workspace=WORKSPACE_DIR)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return f"Written {filename} ({len(content)} bytes)"


@protect("read_code")
def read_code(filename: str) -> str:
    """Read a file or list a directory in the workspace."""
    # Normalise '.' and '' to the workspace root so safe_path doesn't reject them
    if not filename or filename in (".", "./"):
        filename = ""
        path = WORKSPACE_DIR
    else:
        try:
            path = safe_path(filename, workspace=WORKSPACE_DIR)
        except ValueError as e:
            return f"Error: {e}"
    if not os.path.exists(path):
        return f"Error: {filename} not found"
    if os.path.isdir(path):
        entries = sorted(os.listdir(path))
        lines = [f"Directory: {filename}/"]
        for e in entries:
            suffix = "/" if os.path.isdir(os.path.join(path, e)) else ""
            lines.append(f"  {e}{suffix}")
        return "\n".join(lines)
    with open(path, "r", errors="replace") as f:
        content = f.read()
    # Cap large files — model doesn't need the full 50k line file
    if len(content) > 20_000:
        content = content[:20_000] + f"\n\n... [truncated at 20k chars] ..."
    return content


# ---------------------------------------------------------------------------
# Internal helpers — git plumbing, not agent decisions
# ---------------------------------------------------------------------------

def _run_unprotected(command: str) -> str:
    """Run a git/shell command without audit logging."""
    try:
        result = subprocess.check_output(
            ["bash", "-c", command],
            stderr=subprocess.STDOUT,
            cwd=WORKSPACE_DIR,
        )
        return result.decode(errors="replace")
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode(errors='replace')}"


def get_diff(base_branch: str) -> str:
    """Get filtered diff from base branch to HEAD."""
    raw = _run_unprotected(f"git diff origin/{base_branch}...HEAD")
    return _filter_diff(raw)


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


# ---------------------------------------------------------------------------
# Tool specs — passed to Claude in the fix loop
# ---------------------------------------------------------------------------

TOOL_SPECS = [
    {
        "name": "read_code",
        "description": "Read a file or list a directory in the workspace.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Relative path to read"},
            },
            "required": ["filename"],
        },
    },
    {
        "name": "write_code",
        "description": "Write content to a file. Blocked if content contains secrets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Relative path to write"},
                "content": {"type": "string", "description": "File content"},
            },
            "required": ["filename", "content"],
        },
    },
    {
        "name": "run_bash",
        "description": "Run a bash command in the workspace (use for tests only).",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command to run"},
            },
            "required": ["command"],
        },
    },
]


_TOOL_ALLOWED_KEYS: dict[str, set[str]] = {
    "read_code":  {"filename"},
    "write_code": {"filename", "content"},
    "run_bash":   {"command"},
}


def dispatch(tool_name: str, tool_input: dict) -> str:
    allowed = _TOOL_ALLOWED_KEYS.get(tool_name)
    if allowed is None:
        return f"Unknown tool: {tool_name}"
    unexpected = set(tool_input.keys()) - allowed
    if unexpected:
        return f"Error: unexpected keys for {tool_name}: {sorted(unexpected)}"
    try:
        if tool_name == "read_code":
            return read_code(**tool_input)
        if tool_name == "write_code":
            return write_code(**tool_input)
        if tool_name == "run_bash":
            return run_bash(**tool_input)
    except (ValueError, TypeError) as e:
        return f"Error: {e}"
    return f"Unknown tool: {tool_name}"

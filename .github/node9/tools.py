import subprocess
import os
import sys

# Prefer the bundled node9 SDK over whatever pip installed — may be newer.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from node9 import evaluate, dlp_scan, safe_path  # type: ignore[import]

# In CI, GITHUB_WORKSPACE is the repo root; fall back to local "workspace/" for dev
WORKSPACE_DIR = os.environ.get("GITHUB_WORKSPACE") or os.path.abspath("workspace")


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def _audit(tool: str, args: dict) -> None:
    """Local audit entry — used when evaluate() is not called (read-only ops)."""
    arg_summary = ", ".join(f"{k}={str(v)[:80]!r}" for k, v in args.items())
    print(f"  [audit] {tool}({arg_summary})", flush=True)


def _node9_audit(tool_name: str, args: dict) -> None:
    """Forward to node9 SDK (cloud or offline). Never crashes the agent."""
    try:
        evaluate(tool_name, args)
    except Exception as e:
        print(f"  [node9] audit failed for {tool_name}: {e}", flush=True)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def run_bash(command: str) -> str:
    """Executes a bash command in the workspace. Audit-logged."""
    _node9_audit("bash", {"command": command})
    try:
        result = subprocess.check_output(
            ["bash", "-c", command],
            stderr=subprocess.STDOUT,
            cwd=WORKSPACE_DIR,
        )
        return result.decode()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"


def write_code(filename: str, content: str) -> str:
    """Writes a file after DLP scanning. Audit-logged."""
    hit = dlp_scan(filename, content)
    if hit:
        print(f"  🚨 DLP BLOCK: {hit}", flush=True)
        return f"BLOCKED by DLP: {hit}. Do not write secrets to files."

    _node9_audit("filesystem", {"filename": filename, "bytes": len(content)})

    path = safe_path(filename, workspace=WORKSPACE_DIR)
    with open(path, "w") as f:
        f.write(content)
    return f"Successfully updated {filename}"


def read_code(filename: str) -> str:
    """Reads a file or lists a directory for the agent to analyze."""
    _audit("filesystem", {"filename": filename, "op": "read"})
    path = safe_path(filename, workspace=WORKSPACE_DIR)
    if not os.path.exists(path):
        return "Error: File not found."
    if os.path.isdir(path):
        try:
            entries = sorted(os.listdir(path))
            lines = [f"Directory listing for {filename}/:"]
            for entry in entries:
                suffix = "/" if os.path.isdir(os.path.join(path, entry)) else ""
                lines.append(f"  {entry}{suffix}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error listing directory: {e}"
    with open(path, "r") as f:
        return f.read()


def _run_unprotected(command: str) -> str:
    """Run a git/infra command without audit logging. Use sparingly — only for agent scaffolding."""
    try:
        result = subprocess.check_output(
            ["bash", "-c", command],
            stderr=subprocess.STDOUT,
            cwd=WORKSPACE_DIR,
        )
        return result.decode()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"

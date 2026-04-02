import subprocess
import os
import sys

# Prefer the bundled node9 SDK (which has NODE9_API_KEY cloud routing) over
# whatever version pip installed from PyPI — the PyPI package may be older.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from node9 import protect

# In CI, GITHUB_WORKSPACE is the repo root; fall back to local "workspace/" for dev
WORKSPACE_DIR = os.environ.get("GITHUB_WORKSPACE") or os.path.abspath("workspace")

@protect("bash")
def run_bash(command: str):
    """Executes a bash command (tests, ls, etc) in the workspace."""
    try:
        result = subprocess.check_output(
            ["bash", "-c", command],
            stderr=subprocess.STDOUT,
            cwd=WORKSPACE_DIR,
        )
        return result.decode()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"

def _safe_path(filename: str) -> str:
    """Resolve path and verify it stays within WORKSPACE_DIR. Raises ValueError if not."""
    resolved = os.path.realpath(os.path.join(WORKSPACE_DIR, filename))
    workspace_root = os.path.realpath(WORKSPACE_DIR) + os.sep
    if not resolved.startswith(workspace_root):
        raise ValueError(f"Path traversal rejected: {filename!r} escapes workspace")
    return resolved


@protect("filesystem")
def write_code(filename: str, content: str):
    """Overwrites a file with a fix. Node9 takes a Shadow Snapshot first."""
    path = _safe_path(filename)
    with open(path, "w") as f:
        f.write(content)
    return f"Successfully updated {filename}"

def _run_unprotected(command: str) -> str:
    """Run a bash command without node9 interception (for git setup, staging, etc.)."""
    try:
        result = subprocess.check_output(
            ["bash", "-c", command],
            stderr=subprocess.STDOUT,
            cwd=WORKSPACE_DIR,
        )
        return result.decode()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"


@protect("filesystem")
def read_code(filename: str):
    """Reads the content of a file for Claude to analyze."""
    path = _safe_path(filename)
    if not os.path.exists(path):
        return "Error: File not found."
    with open(path, "r") as f:
        return f.read()

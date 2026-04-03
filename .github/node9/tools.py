import subprocess
import os
import re
import sys

# Prefer the bundled node9 SDK (which has NODE9_API_KEY cloud routing) over
# whatever version pip installed from PyPI — the PyPI package may be older.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from node9 import protect

# In CI, GITHUB_WORKSPACE is the repo root; fall back to local "workspace/" for dev
WORKSPACE_DIR = os.environ.get("GITHUB_WORKSPACE") or os.path.abspath("workspace")

# ---------------------------------------------------------------------------
# DLP — port of src/dlp.ts patterns
# Scans file content and paths for secrets before anything is written to disk.
# ---------------------------------------------------------------------------

_DLP_PATTERNS = [
    ("AWS Access Key ID",    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                          "block"),
    ("GitHub Token",         re.compile(r"\bgh[pous]_[A-Za-z0-9]{36}\b"),                  "block"),
    ("Slack Bot Token",      re.compile(r"\bxoxb-[0-9A-Za-z-]{20,100}\b"),                  "block"),
    ("OpenAI API Key",       re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),                      "block"),
    ("Stripe Secret Key",    re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b"),            "block"),
    ("Private Key (PEM)",    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "block"),
    ("GCP Service Account",  re.compile(r'"type"\s*:\s*"service_account"'),                   "block"),
    ("NPM Auth Token",       re.compile(r"_authToken\s*=\s*[A-Za-z0-9_\-]{20,}"),            "block"),
    ("Anthropic API Key",    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),                   "block"),
]

_SENSITIVE_PATH_RE = re.compile(
    r"([\\/]\.ssh[\\/]|[\\/]\.aws[\\/]|[\\/]\.config[\\/]gcloud[\\/]"
    r"|[\\/]\.azure[\\/]|[\\/]\.kube[\\/]config$|[\\/]\.env(\.|$)"
    r"|[\\/]\.git-credentials$|[\\/]\.npmrc$|[\\/]\.docker[\\/]config\.json$"
    r"|[\\/][^/\\]+\.(pem|key|p12|pfx)$|[\\/]credentials\.json$"
    r"|[\\/]id_(rsa|ed25519|ecdsa)$)",
    re.IGNORECASE,
)


def _dlp_scan(filename: str, content: str) -> str | None:
    """
    Returns a human-readable block reason if a secret is detected,
    or None if the content is clean.
    Checks: sensitive file paths + known secret patterns in content.
    """
    # 1. Sensitive path check
    normalized = filename.replace("\\", "/")
    if _SENSITIVE_PATH_RE.search(normalized):
        return f"sensitive file path blocked: {filename}"

    # 2. Secret pattern scan (first 100 KB only)
    text = content[:100_000]
    for name, pattern, _ in _DLP_PATTERNS:
        if pattern.search(text):
            return f"{name} detected in {filename}"

    return None


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def _safe_path(filename: str) -> str:
    """Resolve path and verify it stays within WORKSPACE_DIR. Raises ValueError if not."""
    resolved = os.path.realpath(os.path.join(WORKSPACE_DIR, filename))
    workspace_root = os.path.realpath(WORKSPACE_DIR) + os.sep
    if not resolved.startswith(workspace_root):
        raise ValueError(f"Path traversal rejected: {filename!r} escapes workspace")
    return resolved


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def run_bash(command: str):
    """Executes a bash command (tests, ls, etc) in the workspace — unprotected."""
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
def write_code(filename: str, content: str):
    """Writes a file after DLP scanning. Blocks if a secret is detected."""
    # DLP scan before anything touches disk
    hit = _dlp_scan(filename, content)
    if hit:
        print(f"  🚨 DLP BLOCK: {hit}", flush=True)
        return f"BLOCKED by DLP: {hit}. Do not write secrets to files."

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

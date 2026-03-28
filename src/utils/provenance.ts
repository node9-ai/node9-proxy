// src/utils/provenance.ts
// Binary provenance checker: resolves a command to its real on-disk path and
// classifies its trust level. A binary in /tmp (or world-writable) is suspect
// and triggers review even for tools that would normally be ignoredTools.
import fs from 'fs';
import path from 'path';
import os from 'os';

export type TrustLevel = 'system' | 'managed' | 'user' | 'suspect' | 'unknown';

export interface ProvenanceResult {
  resolvedPath: string;
  trustLevel: TrustLevel;
  reason: string;
}

const SYSTEM_PREFIXES = ['/usr/bin', '/usr/sbin', '/bin', '/sbin'];
const MANAGED_PREFIXES = ['/usr/local/bin', '/opt/homebrew', '/home/linuxbrew', '/nix/store'];
const USER_PREFIXES = [
  path.join(os.homedir(), 'bin'),
  path.join(os.homedir(), '.local', 'bin'),
  path.join(os.homedir(), '.cargo', 'bin'),
  path.join(os.homedir(), '.npm-global', 'bin'),
  path.join(os.homedir(), '.volta', 'bin'),
];
// Temp directories that should never contain trusted binaries
const SUSPECT_PREFIXES = ['/tmp', '/var/tmp', '/dev/shm'];

/** Walk PATH to find the first executable matching `cmd`. */
function findInPath(cmd: string): string | null {
  // Use POSIX semantics: shell commands always use forward-slash paths even on Windows (WSL, Git Bash).
  if (path.posix.isAbsolute(cmd)) return cmd;
  const pathEnv = process.env.PATH ?? '';
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const full = path.join(dir, cmd);
    try {
      fs.accessSync(full, fs.constants.X_OK);
      return full;
    } catch {
      // not in this dir — keep scanning
    }
  }
  return null;
}

/**
 * Pure path classification: given an already-resolved absolute path, returns
 * trust level and reason. No filesystem calls — safe to call from unit tests.
 *
 * @internal Exported for unit testing; production code should use checkProvenance.
 */
export function _classifyPath(
  resolved: string,
  cwd?: string
): { trustLevel: TrustLevel; reason: string } {
  // All prefix checks use '/' explicitly — these are always POSIX paths.
  // Using path.sep would break on Windows where it is '\\'.

  // Project-local binary
  if (cwd && resolved.startsWith(cwd + '/')) {
    return { trustLevel: 'user', reason: 'binary in project directory' };
  }

  // Temp / suspect directories
  const osTmp = os.tmpdir();
  const allSuspect = osTmp ? [...SUSPECT_PREFIXES, osTmp] : SUSPECT_PREFIXES;
  if (allSuspect.some((p) => resolved === p || resolved.startsWith(p + '/'))) {
    return { trustLevel: 'suspect', reason: `binary in temp directory: ${resolved}` };
  }

  // Well-known locations
  if (SYSTEM_PREFIXES.some((p) => resolved === p || resolved.startsWith(p + '/'))) {
    return { trustLevel: 'system', reason: '' };
  }
  if (MANAGED_PREFIXES.some((p) => resolved === p || resolved.startsWith(p + '/'))) {
    return { trustLevel: 'managed', reason: '' };
  }
  if (USER_PREFIXES.some((p) => resolved === p || resolved.startsWith(p + '/'))) {
    return { trustLevel: 'user', reason: '' };
  }

  return { trustLevel: 'unknown', reason: 'binary in unrecognized location' };
}

/**
 * Checks the provenance of a binary before execution.
 *
 * @param cmd  Command name (e.g. "curl") or absolute path (e.g. "/tmp/curl")
 * @param cwd  Optional project directory — binaries inside cwd get 'user' trust
 */
export function checkProvenance(cmd: string, cwd?: string): ProvenanceResult {
  // Strip ./ prefix for project-local scripts
  const bare = cmd.startsWith('./') ? cmd.slice(2) : cmd;

  // ── Early suspect check for absolute paths ────────────────────────────────
  // Check before realpathSync so /tmp/evil is caught even if the file doesn't
  // exist yet (or realpathSync fails). Temp-dir membership is determined by
  // the input path, not the symlink target — a binary accessed via /tmp/link
  // is suspect regardless of where the link points.
  if (path.posix.isAbsolute(bare)) {
    const early = _classifyPath(bare, cwd);
    if (early.trustLevel === 'suspect') {
      return { resolvedPath: bare, ...early };
    }
  }

  // ── 1. Resolve to real absolute path ──────────────────────────────────────
  let resolved: string;
  try {
    const found = findInPath(bare);
    if (!found) {
      return {
        resolvedPath: cmd,
        trustLevel: 'unknown',
        reason: 'binary not found in PATH',
      };
    }
    resolved = fs.realpathSync(found);
  } catch {
    return {
      resolvedPath: cmd,
      trustLevel: 'unknown',
      reason: 'binary not found in PATH',
    };
  }

  // ── 2. World-writable check ────────────────────────────────────────────────
  try {
    const stat = fs.statSync(resolved);
    // Mode bit 0o002: write permission for "other"
    if (stat.mode & 0o002) {
      return {
        resolvedPath: resolved,
        trustLevel: 'suspect',
        reason: 'binary is world-writable',
      };
    }
  } catch {
    return {
      resolvedPath: resolved,
      trustLevel: 'unknown',
      reason: 'could not stat binary',
    };
  }

  // ── 3. Classify by location ────────────────────────────────────────────────
  const classify = _classifyPath(resolved, cwd);
  return { resolvedPath: resolved, ...classify };
}

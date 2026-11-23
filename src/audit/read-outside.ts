// Reads outside the project (cases-session stage 2, change 6).
//
// File-tool reads (Read, read_file) take the ignoredTools fast path and leave
// no shipped row, so the cloud cannot tell which files a session read outside
// its project. The PostToolUse hook marks such a read on its own local row,
// in the shortened form only (the last two segments); the daemon collects the
// marks and sends them on the heartbeat. No audit row is added, so no call
// count anywhere changes.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { truncateBlastPath } from '@node9/policy-engine';

/** Longest shortened path sent; the cloud schema caps it at the same value. */
export const MAX_READ_OUTSIDE_PATH = 256;

/** Tools whose only effect is reading the file in its path argument. Grep and
 *  Glob are left out: their path is a directory to search, not a file read. */
function readTarget(tool: string, args: unknown): string | undefined {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return undefined;
  const a = args as Record<string, unknown>;
  const name = tool.toLowerCase();
  const isRead =
    name === 'read' ||
    name === 'read_file' ||
    (name === 'str_replace_based_edit_tool' && a.command === 'view');
  if (!isRead) return undefined;
  // `absolute_path`: Gemini CLI's read_file before it took `file_path`.
  for (const key of ['file_path', 'path', 'absolute_path']) {
    const v = a[key];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return undefined;
}

function within(target: string, root: string): boolean {
  const rel = path.relative(root, target);
  // `..` alone or as the first segment is outside; `..env` is a file name.
  return rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
}

/** Windows paths compare without case. */
function samePath(a: string, b: string): boolean {
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/** Scratch space an agent uses on purpose: never "outside the project". */
function isTemp(target: string): boolean {
  const roots = [os.tmpdir(), '/tmp', '/var/tmp', '/private/tmp', '/var/folders'];
  return roots.some((r) => within(target, r));
}

/**
 * The project a working directory belongs to: the nearest ancestor that holds
 * `.git`, so a session started in `repo/be` treats `repo/fe` as inside. The
 * home folder and the filesystem root never count, even when they hold
 * `.git`: a dotfiles repository would make every read "inside". Without a
 * repository the working directory itself is the project.
 */
export function projectRootOf(cwd: string): string {
  const home = os.homedir();
  let dir = cwd;
  for (let i = 0; i < 64; i++) {
    if (samePath(dir, home) || dir === path.dirname(dir)) break;
    try {
      if (fs.existsSync(path.join(dir, '.git'))) return dir;
    } catch {
      break;
    }
    dir = path.dirname(dir);
  }
  return cwd;
}

/**
 * The shortened path of a file read outside the session's project, or
 * undefined when the call is not a file read, the read is inside the project
 * or a temp folder, or the cwd is unusable.
 */
export function readOutsidePath(
  tool: string,
  args: unknown,
  cwd: string | undefined
): string | undefined {
  if (!cwd || !path.isAbsolute(cwd)) return undefined;
  const spelled = readTarget(tool, args);
  if (!spelled) return undefined;
  const target = path.resolve(cwd, spelled);
  if (within(target, projectRootOf(cwd)) || isTemp(target)) return undefined;
  const short = truncateBlastPath(target)
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f]+/g, ' ')
    .trim();
  return short && short.length <= MAX_READ_OUTSIDE_PATH ? short : undefined;
}

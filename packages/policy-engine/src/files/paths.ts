// Shared path vocabulary for operation-aware checks and legacy DLP compatibility.
export const SYSTEM_AUTH_FILES = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/group',
  '/etc/gshadow',
  '/etc/sudoers',
] as const;
// sudoers reads /etc/sudoers.d through its default includedir, so a file there is
// a sudoers change by another name.
export const SYSTEM_AUTH_DIRS = ['/etc/security', '/etc/pam.d', '/etc/sudoers.d'] as const;
export const PASSWORD_HASH_FILES = ['/etc/shadow', '/etc/gshadow'] as const;
export const STARTUP_NAMES = ['.bashrc', '.zshrc', '.profile', '.bash_profile'] as const;

/**
 * System directories: a write, a new file or a removal under one of them asks
 * for approval (files.system-dirs). /usr/local is where `make install` and
 * manual installs go; /usr/src/app is the working directory of the official
 * Node and Python container images, so a relative write there is ordinary
 * project work. /proc, /sys and /dev are kernel interfaces, not files an agent
 * installs into, and are left out of the mutation set.
 */
export const SYSTEM_DIRS = [
  '/usr',
  '/etc',
  '/boot',
  '/bin',
  '/sbin',
  '/lib',
  '/lib64',
  '/var/log',
] as const;
export const SYSTEM_DIRS_EXEMPT = ['/usr/local', '/usr/src'] as const;

/**
 * Files inside a project that run code or instruct the agent (fw#318 P4,
 * design 6). A write there after the session read outside content is held:
 * it is how an injected instruction persists past the session. Relative to
 * the project root; a directory entry covers everything under it.
 */
export const AGENT_INSTRUCTION_FILES = [
  '.gitlab-ci.yml',
  'CLAUDE.md',
  'AGENTS.md',
  '.cursorrules',
  '.mcp.json',
  '.vscode/settings.json',
  'package.json',
] as const;
export const AGENT_INSTRUCTION_DIRS = [
  '.github/workflows',
  '.claude',
  '.cursor',
  '.git/hooks',
  '.husky',
] as const;

/** Is `absPath` one of the agent-instruction files of the project at `root`? */
export function isAgentInstructionPath(absPath: string, root: string): boolean {
  const r = root.replace(/\/$/, '');
  if (!(absPath === r || absPath.startsWith(r + '/'))) return false;
  const rel = absPath.slice(r.length + 1);
  if ((AGENT_INSTRUCTION_FILES as readonly string[]).includes(rel)) return true;
  return AGENT_INSTRUCTION_DIRS.some((d) => rel === d || rel.startsWith(d + '/'));
}

/** `isInside(root, p)`: `p` is `root` or below it, lexically. */
export function isInside(root: string, p: string): boolean {
  const r = root.replace(/\/$/, '') || '/';
  return p === r || p.startsWith(r === '/' ? '/' : r + '/');
}
export const LEGACY_SYSTEM_PATH_RE = /^(?:[a-zA-Z]:)?\/etc\/(?:passwd|shadow|sudoers)$/;

export function isPasswordHashPath(p: string): boolean {
  return (PASSWORD_HASH_FILES as readonly string[]).includes(p);
}

/** Compatibility only: old callers do not tell DLP whether they read or write. */
export function isLegacySystemPath(p: string): boolean {
  return LEGACY_SYSTEM_PATH_RE.test(p);
}

/** Pure lexical normalization; host physical resolution keeps the original path. */
export function normalizeFilePath(p: string, cwd = '', home = '~'): string {
  // Join the working directory first: a tracked cwd may itself be spelled `~`.
  if (!p.startsWith('/') && !p.startsWith('~') && cwd) p = `${cwd}/${p}`;
  if (p === '~' || p.startsWith('~/')) p = home + p.slice(1);
  const rooted = p.startsWith('/');
  const parts: string[] = [];
  for (const part of p.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..' && parts.length && parts.at(-1) !== '..') parts.pop();
    else if (part !== '..' || !rooted) parts.push(part);
  }
  return (rooted ? '/' : '') + parts.join('/');
}

export interface FileAccess {
  operation: 'read' | 'write' | 'remove' | 'create';
  path: string;
  cwd?: string;
  /** Unquoted shell pattern. Quoted metacharacters are escaped in this value. */
  glob?: string;
  /** The pattern is find's, not the shell's: `*` also selects dotfiles. */
  dotGlob?: boolean;
  followFinal: boolean;
  recursive?: boolean;
  /** This basename-joined candidate applies only if this operand is a directory. */
  directoryTarget?: string;
  candidates?: string[];
  resolution?: 'resolved' | 'missing' | 'failed' | 'lexical';
}

export interface FileAccessContext {
  cwd?: string;
  homeDirs?: string[];
  accesses?: FileAccess[];
}

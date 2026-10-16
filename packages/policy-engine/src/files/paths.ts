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

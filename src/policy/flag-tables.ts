// src/policy/flag-tables.ts
// Per-binary table of flags that consume the next token as a value.
// Used to correctly separate positional args (network targets, file paths)
// from flag values — preventing a flag value like `-x proxy.com` from being
// mistaken for a destination host.
import path from 'path';

export const FLAGS_WITH_VALUES: Record<string, Set<string>> = {
  curl: new Set([
    '-H',
    '--header',
    '-A',
    '--user-agent',
    '-e',
    '--referer',
    '-x',
    '--proxy',
    '-u',
    '--user',
    '-d',
    '--data',
    '--data-raw',
    '--data-binary',
    '-o',
    '--output',
    '-F',
    '--form',
    '--connect-to',
    '--resolve',
    '--cacert',
    '--cert',
    '--key',
    '-m',
    '--max-time',
  ]),
  wget: new Set([
    '-O',
    '--output-document',
    '-P',
    '--directory-prefix',
    '-U',
    '--user-agent',
    '-e',
    '--execute',
    '--proxy',
    '--ca-certificate',
  ]),
  nc: new Set(['-x', '-p', '-s', '-w', '-W', '-I', '-O']),
  ncat: new Set(['-x', '-p', '-s', '--proxy', '--proxy-auth', '-w', '--wait']),
  netcat: new Set(['-x', '-p', '-s', '-w']),
  ssh: new Set([
    '-i',
    '-l',
    '-p',
    '-o',
    '-E',
    '-F',
    '-J',
    '-L',
    '-R',
    '-W',
    '-b',
    '-c',
    '-D',
    '-e',
    '-I',
    '-S',
  ]),
  scp: new Set(['-i', '-o', '-P', '-S']),
  rsync: new Set(['-e', '--rsh', '--rsync-path', '--password-file', '--log-file']),
  socat: new Set([]), // socat uses address syntax, not flags — no value-flags
};

/**
 * Given a list of already-tokenized arguments and the binary name,
 * returns only the positional (non-flag, non-flag-value) arguments.
 *
 * Handles:
 *   -x value        → skip both tokens
 *   --proxy=value   → skip (value embedded in token)
 *   -xvalue         → skip (fused short flag+value)
 *   @file           → skip (curl data-from-file)
 *   positional      → keep
 */
export function extractPositionalArgs(tokens: string[], binary: string): string[] {
  const binaryName = path.basename(binary).replace(/\.exe$/i, '');
  const flagsWithValues = FLAGS_WITH_VALUES[binaryName] ?? new Set();
  const positional: string[] = [];
  let skipNext = false;

  for (const token of tokens) {
    if (skipNext) {
      skipNext = false;
      continue;
    }

    // Long form with embedded value: --proxy=value
    if (token.startsWith('--') && token.includes('=')) continue;

    // Short flag that takes a separate next-token value: -x value
    if (token.startsWith('-') && token.length === 2 && flagsWithValues.has(token)) {
      skipNext = true;
      continue;
    }

    // Long flag without = that takes next-token value: --proxy value
    if (token.startsWith('--') && flagsWithValues.has(token)) {
      skipNext = true;
      continue;
    }

    // Fused short form: -xvalue (length > 2, starts with -, known flag)
    const shortFlag = token.slice(0, 2);
    if (token.startsWith('-') && token.length > 2 && flagsWithValues.has(shortFlag)) continue;

    // Any other flag (boolean flag, combined flags like -vn)
    if (token.startsWith('-')) continue;

    // curl @file syntax — skip
    if (token.startsWith('@')) continue;

    positional.push(token);
  }

  return positional;
}

/**
 * Extracts network target hostnames from a tokenized command.
 * Strips user@host → host and host:port → host (only strips :port when port is numeric).
 * Full URLs (https://...) are returned as-is.
 */
export function extractNetworkTargets(tokens: string[], binary: string): string[] {
  return extractPositionalArgs(tokens, binary)
    .map((t) => (t.includes('@') ? t.split('@')[1] : t))
    .map((t) => {
      // Don't strip :// (URL scheme separator)
      const colonIdx = t.indexOf(':');
      if (colonIdx === -1) return t;
      const afterColon = t.slice(colonIdx + 1);
      // Only strip if what follows ':' is a numeric port (not '//' or alphanumeric path)
      if (/^\d+$/.test(afterColon)) return t.slice(0, colonIdx);
      return t;
    })
    .filter(Boolean);
}

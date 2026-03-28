// src/policy/ssh-parser.ts
// Extracts ALL hosts from an ssh/scp/rsync command, including jump hosts
// specified via -J, ProxyJump, and ProxyCommand.
// Without this, `ssh -J evil.com user@safe.com` looks like it only touches
// safe.com — the real traffic route through evil.com is invisible.
import { extractNetworkTargets } from './flag-tables.js';

/** Minimal whitespace-aware shell tokenizer (no full POSIX quoting). */
function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (const ch of cmd) {
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if ((ch === ' ' || ch === '\t') && !inSingle && !inDouble) {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}

function parseHost(raw: string): string {
  // Strip user@ prefix and :port suffix
  return raw.split('@').pop()!.split(':')[0];
}

/**
 * Recursively extracts every host involved in an ssh/scp/rsync invocation,
 * including jump hosts from -J, ProxyJump=, and ProxyCommand=.
 *
 * @param tokens  Pre-tokenized argv (without the binary itself)
 * @returns       Deduplicated list of host strings
 */
export function extractAllSshHosts(tokens: string[]): string[] {
  const hosts = new Set<string>();

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    // -J hop1.com,hop2.com  (comma-separated jump chain)
    if (t === '-J' && tokens[i + 1]) {
      for (const hop of tokens[++i].split(',')) {
        const h = parseHost(hop);
        if (h) hosts.add(h);
      }
      continue;
    }

    // -o ProxyJump=hop1,hop2
    if (t === '-o' && tokens[i + 1]?.toLowerCase().startsWith('proxyjump=')) {
      const val = tokens[++i].split('=').slice(1).join('=');
      for (const hop of val.split(',')) {
        const h = parseHost(hop);
        if (h) hosts.add(h);
      }
      continue;
    }

    // -o ProxyCommand='nc evil.com 22'  → recurse into the sub-command
    if (t === '-o' && tokens[i + 1]?.toLowerCase().startsWith('proxycommand=')) {
      const raw = tokens[++i]
        .split('=')
        .slice(1)
        .join('=')
        .replace(/^['"]|['"]$/g, '');
      const subTokens = tokenize(raw);
      // Hosts in the sub-command itself (e.g. nc evil.com)
      const binary = subTokens[0] ?? '';
      extractNetworkTargets(subTokens.slice(1), binary).forEach((h) => hosts.add(h));
      // Recursive ssh in ProxyCommand
      extractAllSshHosts(subTokens.slice(1)).forEach((h) => hosts.add(h));
      continue;
    }

    // Positional: user@host or just host (non-flag tokens)
    if (!t.startsWith('-')) {
      const h = parseHost(t);
      if (h) hosts.add(h);
    }
  }

  return [...hosts].filter(Boolean);
}

/**
 * Top-level entry point: given the full command string (including the binary),
 * extracts all SSH hosts.
 */
export function parseAllSshHostsFromCommand(command: string): string[] {
  const tokens = tokenize(command);
  // Skip the binary itself (ssh, scp, rsync…)
  return extractAllSshHosts(tokens.slice(1));
}

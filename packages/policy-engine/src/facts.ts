// Facts of a tool call, for its audit row.
//
// The gate sees the whole call; the cloud sees a hash and the first 120
// characters of the main argument. So the gate records what the call does in
// small closed-vocabulary fields, computed from the full arguments, and the
// dashboard stops deriving meaning from a cut preview (measured on one live
// session: 2,304 of 2,419 commands reached the cloud cut).
//
// What a fact may hold: a host (never userinfo, a path or a query), a command
// shape built from subcommand words (`git push`, `gh pr merge`), an MCP
// server and tool name, a risk category, and a path cut to its last two
// segments. Never an argument value, a URL path or file content.
//
// Static, from the shared parse: no I/O, never throws.

import { classifyShellCalls, type ShellCall } from './exposure/shell';
import { analyzeShellCommand, detectDangerousShellExec } from './shell';
import { isBashTool } from './shell/tool-input';
import { matchSensitivePath, scanText } from './dlp';
import { extractToolDestinations } from './egress/destinations';
import { truncateBlastPath } from './blast';

/**
 * net      a host was contacted
 * upload   a body or a file was put on the wire to a host
 * push     code or a change went to a remote (`git push`, a gh write)
 * publish  a package or an image was released
 * send     an MCP tool that sends (a message, an email, a share)
 */
export const OUT_KINDS = ['net', 'upload', 'push', 'publish', 'send'] as const;
export type OutKind = (typeof OUT_KINDS)[number];
export interface OutFact {
  k: OutKind;
  /** A host, a command shape, or `<server>: <tool>` for an MCP send. */
  t: string;
}

export const RISK_CATEGORIES = [
  'secret-read',
  'egress',
  'destructive',
  'privilege',
  'remote-exec',
] as const;
export type RiskCategory = (typeof RISK_CATEGORIES)[number];
export interface RiskFact {
  c: RiskCategory;
  /** The host, or the path cut to its last two segments, behind it. */
  r?: string;
}

export interface CallFacts {
  out: OutFact[];
  risk: RiskFact[];
}

export const MAX_OUT_FACTS = 8;
export const MAX_RISK_FACTS = 5;
export const MAX_FACT_TEXT = 128;
/** Written when a network call names no host this analysis can read. */
export const UNKNOWN_HOST = 'unknown host';

const HOST_RE = /^[a-z0-9]([a-z0-9._:-]{0,251}[a-z0-9])?$/i;
const BODY_SENDERS = new Set([
  'curl',
  'wget',
  'iwr',
  'invoke-webrequest',
  'irm',
  'invoke-restmethod',
  'scp',
  'rsync',
]);
const CONNECTORS = new Set(['nc', 'ncat', 'netcat', 'ssh']);
const PUBLISHERS = new Set(['npm', 'pnpm', 'yarn', 'twine', 'cargo', 'gem', 'docker']);

const EGRESS_TOOLS = new Set(['curl', 'wget', 'scp', 'nc', 'ssh', 'rsync', 'gh']);
const DESTRUCT_TOOLS = new Set(['rm', 'dd', 'mkfs', 'shred']);
const PRIV_TOOLS = new Set(['sudo', 'su', 'doas', 'chmod', 'chown']);

/** A host as a fact carries it, or null when the text is not one. */
function hostFact(h: string | undefined): string | null {
  if (!h) return null;
  const v = h
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return HOST_RE.test(v) ? v : null;
}

/**
 * A host the source spells as a credential (`https://<key>.collect.example`,
 * the DNS way out). Hosts reach this file lowercased, and a detector that
 * knows a key by its uppercase shape no longer matches it there, so each
 * place the source names the host is scanned as it was written.
 */
function spelledAsSecret(source: string, host: string): boolean {
  if (!source || !host) return false;
  const hay = source.toLowerCase();
  for (let i = hay.indexOf(host); i >= 0; i = hay.indexOf(host, i + 1)) {
    if (scanText(source.slice(i, i + host.length)) !== null) return true;
  }
  return false;
}

/** Printable, single line, bounded. */
function clean(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text
    .replace(/[\x00-\x1f\x7f]+/g, ' ')
    .trim()
    .slice(0, MAX_FACT_TEXT);
}

function pathFact(p: string | undefined): string | undefined {
  if (!p) return undefined;
  const cut = clean(truncateBlastPath(p));
  return cut || undefined;
}

/** First argument that looks like a filesystem path (the rm or chmod target). */
function firstFsPath(paths: string[]): string | undefined {
  return paths.find(
    (p) => p.startsWith('/') || p.startsWith('~') || p.startsWith('./') || p.startsWith('../')
  );
}

function outOfCall(call: ShellCall): OutFact[] {
  const head = call.via.split(' ')[0];
  const hosts = call.hosts.map((h) => hostFact(h)).filter((h): h is string => h !== null);
  const toHosts = (k: OutKind): OutFact[] => hosts.map((t) => ({ k, t }));
  if (head === 'git') {
    // Pointing a remote at a url prepares a send; only the push leaves.
    if (call.via === 'git push' && call.sends) return [{ k: 'push', t: 'git push' }];
    return call.fetches ? toHosts('net') : [];
  }
  if (head === 'gh') return call.sends ? [{ k: 'push', t: call.via }] : toHosts('net');
  if (PUBLISHERS.has(head)) return call.sends ? [{ k: 'publish', t: call.via }] : [];
  // A network call whose host cannot be read, or may not be written, still
  // left the machine: it is recorded against an unknown host.
  const toHostsOrUnknown = (k: OutKind): OutFact[] =>
    hosts.length > 0 ? toHosts(k) : [{ k, t: UNKNOWN_HOST }];
  if (call.via === 'redirect') return toHostsOrUnknown('upload');
  if (BODY_SENDERS.has(head) || CONNECTORS.has(head)) {
    return toHostsOrUnknown(call.sends && BODY_SENDERS.has(head) ? 'upload' : 'net');
  }
  return toHosts(call.sends ? 'upload' : 'net');
}

function dedupe<T>(items: T[], key: (x: T) => string, max: number): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const it of items) {
    const k = key(it);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(it);
    if (out.length >= max) break;
  }
  return out;
}

/** The facts of one shell command. */
export function shellFacts(command: string): CallFacts {
  const none: CallFacts = { out: [], risk: [] };
  if (!command || typeof command !== 'string') return none;
  try {
    const calls = classifyShellCalls(command).map((c) => ({
      ...c,
      hosts: c.hosts.filter((h) => !spelledAsSecret(command, h.toLowerCase())),
    }));
    const out = dedupe(calls.flatMap(outOfCall), (o) => `${o.k}|${o.t}`, MAX_OUT_FACTS);
    // An upload to a host says more than a contact with it.
    const uploaded = new Set(out.filter((o) => o.k === 'upload').map((o) => o.t));
    const outFacts = out.filter((o) => !(o.k === 'net' && uploaded.has(o.t)));

    const { actions, paths } = analyzeShellCommand(command);
    const host = calls
      .flatMap((c) => c.hosts)
      .map((h) => hostFact(h))
      .find((h): h is string => h !== null);
    const risk: RiskFact[] = [];
    const add = (c: RiskCategory, r?: string) => risk.push(r ? { c, r } : { c });
    // A network binary at execution position, a `sh -c` payload's included.
    const networked =
      actions.some((a) => EGRESS_TOOLS.has(a)) ||
      calls.some((c) => EGRESS_TOOLS.has(c.via.split(' ')[0]));
    if (networked) add('egress', host);
    if (detectDangerousShellExec(command)) add('remote-exec', host);
    if (actions.some((a) => DESTRUCT_TOOLS.has(a)))
      add('destructive', pathFact(firstFsPath(paths)));
    if (actions.some((a) => PRIV_TOOLS.has(a))) add('privilege', pathFact(firstFsPath(paths)));
    const secret = paths.find((p) => matchSensitivePath(p, p));
    if (secret) add('secret-read', pathFact(secret));
    return { out: outFacts, risk: dedupe(risk, (r) => r.c, MAX_RISK_FACTS) };
  } catch {
    return none;
  }
}

export type McpToolKind = 'send' | 'write' | 'read' | 'other';

const SEND_VERBS = new Set([
  'send',
  'reply',
  'forward',
  'post',
  'publish',
  'share',
  'upload',
  'invite',
  'comment',
]);
const WRITE_VERBS = new Set([
  'create',
  'update',
  'delete',
  'trash',
  'remove',
  'write',
  'edit',
  'draft',
  'set',
  'add',
  'insert',
  'append',
  'rename',
  'move',
  'merge',
  'apply',
  'upsert',
  'patch',
  'put',
]);
const READ_VERBS = new Set([
  'get',
  'list',
  'read',
  'search',
  'find',
  'fetch',
  'query',
  'view',
  'status',
  'describe',
  'download',
]);

/** What an MCP tool does, from the verb in its name. `send` leaves the
 *  machine addressed to someone; `write` changes something on the service.
 *  The FIRST verb decides: `get_draft` reads, `create_draft` writes. */
export function mcpToolKind(tool: string): McpToolKind {
  const words = tool
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z]+/)
    .filter(Boolean);
  for (const w of words) {
    if (SEND_VERBS.has(w)) return 'send';
    if (WRITE_VERBS.has(w)) return 'write';
    if (READ_VERBS.has(w)) return 'read';
  }
  return 'other';
}

/** The arguments as text, bounded, to find how a host was written. */
function spelling(args: unknown): string {
  try {
    return (JSON.stringify(args) ?? '').slice(0, 65536);
  } catch {
    return '';
  }
}

const MCP_RE = /^mcp__([^_](?:[^_]|_(?!_))*?)__(.+)$/i;

export interface CallFactsOptions {
  /** The command the gate resolved for a shell-shaped tool. Without it a
   *  native Bash tool's `command` argument is read. */
  shellCommand?: string | null;
  /** The MCP server of a gateway call, whose tool name arrives bare. */
  mcpServer?: string;
}

/**
 * The facts of one tool call: a shell command by its parse, a tool that
 * declares a destination by its host, an MCP tool that sends by its name.
 */
export function callFacts(toolName: string, args: unknown, opts: CallFactsOptions = {}): CallFacts {
  try {
    const command =
      typeof opts.shellCommand === 'string'
        ? opts.shellCommand
        : isBashTool(toolName) && args && typeof args === 'object'
          ? (args as Record<string, unknown>).command
          : undefined;
    if (typeof command === 'string' && command) return shellFacts(command);

    const out: OutFact[] = [];
    const dests = extractToolDestinations(toolName, args);
    // Read only when the tool names a destination: where its host is spelled.
    const source = dests.length > 0 ? spelling(args) : '';
    for (const d of dests) {
      const h = hostFact(d.host);
      if (!h) continue;
      out.push({ k: 'net', t: spelledAsSecret(source, h) ? UNKNOWN_HOST : h });
    }
    const named = MCP_RE.exec(toolName);
    const server = named?.[1] ?? opts.mcpServer;
    const tool = named?.[2] ?? toolName;
    if (server && mcpToolKind(tool) === 'send') {
      out.push({ k: 'send', t: clean(`${server}: ${tool}`) });
    }
    return { out: dedupe(out, (o) => `${o.k}|${o.t}`, MAX_OUT_FACTS), risk: [] };
  } catch {
    return { out: [], risk: [] };
  }
}

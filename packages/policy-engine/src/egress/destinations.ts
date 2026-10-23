// The SSRF floor for tool calls that are not shell commands.
//
// Measured 2026-09-08: `curl http://<metadata>/` blocked, the same address
// through WebFetch or a browser tool did not, because ssrfFloor is called only
// inside the shell branch of evaluatePolicy. Design and the two adversarial
// corpora that shaped it: doc/roadmap/active/ssrf-nonshell-design.md.
//
// Two decisions are load-bearing here, and both came from measurement rather
// than from taste:
//
// 1. A CLOSED LIST of tool + argument paths, not a scan of arguments. There is
//    no placement in the orchestrator that reaches WebFetch without also
//    reaching Grep, Write and an Agent prompt, and a false-positive corpus
//    returned six families where nothing distinguishes "this argument IS a
//    destination" from "this argument CONTAINS the text" (free text being the
//    worst: quoting and instructing are the same bytes). A shape not on this
//    list is a deliberate false negative. The alternative blocks ordinary work
//    and then the whole mechanism gets switched off.
//
// 2. A value is judged by PARSING it as a URL and taking the host. Never by
//    searching for a substring. `http://169.254.169.254%2f@example.com/` looks
//    like the metadata address and really resolves to example.com; a substring
//    check blocks it wrongly. Parsing also removes the numeric-collision
//    family for free: under inet_aton the price 239.99 and roughly 6% of
//    32-bit hashes fold to protected addresses, and none of them is ever a URL
//    hostname.
import {
  classifySsrf,
  ssrfDisguisedReason,
  ssrfFloorDecision,
  ssrfReason,
  type SsrfMatch,
} from './ssrf';
import type { Destination } from './index';

/**
 * Tools whose named argument really is a destination the agent is about to
 * reach. Keyed on the BARE tool name (an `mcp__server__` prefix is stripped
 * before matching), because the browser tools arrive over MCP.
 *
 * Derived from real history, not imagination: walking 240,058 audit entries
 * produced exactly these argument paths. A tool is here because its network
 * semantics are declared by its name, not because it happens to carry a key
 * called `url` (founder call, 2026-09-08: ignore those).
 *
 * `[]` in a path means "every element of this array".
 */
export const DESTINATION_ARGS: ReadonlyMap<string, readonly string[]> = new Map([
  ['webfetch', ['url']],
  ['fetch', ['url', 'uri']],
  ['navigate', ['url']],
  ['preview_start', ['url']],
  ['browser_batch', ['actions[].input.url']],
]);

/** `mcp__Claude_Browser__navigate` -> `navigate`. */
function bareToolName(toolName: string): string {
  const parts = toolName.split('__');
  return (parts.length >= 3 ? parts.slice(2).join('__') : toolName).toLowerCase();
}

/** Resolve one path against the argument object, yielding every string it names. */
function valuesAt(args: unknown, path: string): string[] {
  let cursors: unknown[] = [args];
  for (const rawSegment of path.split('.')) {
    const isArray = rawSegment.endsWith('[]');
    const key = isArray ? rawSegment.slice(0, -2) : rawSegment;
    const next: unknown[] = [];
    for (const cursor of cursors) {
      if (cursor === null || typeof cursor !== 'object') continue;
      const child = (cursor as Record<string, unknown>)[key];
      if (isArray) {
        if (Array.isArray(child)) next.push(...child);
      } else if (child !== undefined) {
        next.push(child);
      }
    }
    cursors = next;
    if (cursors.length === 0) return [];
  }
  return cursors.filter((v): v is string => typeof v === 'string');
}

/** The host a value denotes, or null when the value is not a URL at all. */
function hostOf(value: string): string | null {
  try {
    // A bare host with no scheme is NOT accepted: on this path the value has
    // to look like a destination, and "239.99" must stay a price.
    // Any scheme with a real host counts. Restricting this to http(s) was
    // arbitrary and merely narrow: ssh:// or ftp:// to a protected address is
    // the same reach. A scheme that carries no host (data:, javascript:,
    // mailto:, file:///x) yields an empty hostname and falls out below, so
    // nothing new is caught by accident.
    const u = new URL(value);
    const h = u.hostname;
    return h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
  } catch {
    return null;
  }
}

/**
 * The hosts a non-shell tool call will reach, in the SAME shape the shell
 * extractor produces, so both feed one evaluateEgress (G10).
 *
 * Measured 2026-09-20 on dev e748b4a, egress { mode: 'block', allow: [] }:
 * `curl https://evil.example.com/` denied, the same URL through WebFetch, MCP
 * fetch and browser navigate allowed. The allowlist was shell-only, and an
 * agent that wants to exfiltrate does not need curl. The extraction below is
 * what the floor above already does; the policy was never applied to it.
 *
 * Same closed table, same helpers, for the same reason: a tool is covered
 * because it is LISTED, never because an argument looked like a URL. A tool
 * not in DESTINATION_ARGS yields [] and is invisible to the egress policy,
 * exactly as it is invisible to the floor. `binary` carries the tool name so
 * the reason string and the audit row say which carrier it was.
 *
 * Never throws: this runs on the hook path for every tool call.
 */
export function extractToolDestinations(toolName: string, args: unknown): Destination[] {
  try {
    const out: Destination[] = [];
    const paths = DESTINATION_ARGS.get(bareToolName(toolName)) ?? [];
    for (const path of paths) {
      for (const value of valuesAt(args, path)) {
        const host = hostOf(value);
        if (host) out.push({ host, binary: toolName, raw: value });
      }
    }
    // An MCP tool whose argument is NAMED as a place data goes (`destination`,
    // `endpoint`, `webhook`, `callback_url`) and holds a URL names where it
    // sends (`send_report(destination=...)`, fw#372 B8). This feeds the opt-in
    // egress policy only; the floor above keeps its closed list, and so does a
    // plain `url`: on `notes.save` it is the page being saved, not a
    // destination (founder call 2026-09-08, pinned by the carriers corpus).
    if (paths.length === 0 && /^mcp__/i.test(toolName) && args && typeof args === 'object') {
      for (const key of MCP_DESTINATION_KEYS) {
        const value = (args as Record<string, unknown>)[key];
        if (typeof value !== 'string') continue;
        const host = hostOf(value);
        if (host) out.push({ host, binary: toolName, raw: value });
      }
    }
    return out;
  } catch {
    return [];
  }
}

/** Top-level argument names that declare a destination on an MCP tool. */
const MCP_DESTINATION_KEYS = [
  'destination',
  'endpoint',
  'webhook',
  'webhook_url',
  'callback_url',
] as const;

export interface DestinationHit extends SsrfMatch {
  /** The path that carried it, for the message and the audit row. */
  argPath: string;
  host: string;
  reason: string;
  /** 'review' for a disguised spelling of a default-reachable address. */
  decision: 'block' | 'review';
}

/** The host as WRITTEN in a URL: the URL parser folds `0x7f000001` to
 *  `127.0.0.1`, which would hide the disguise the floor asks about. */
function writtenAuthority(value: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/i.exec(value);
  return m && m[1] ? m[1] : null;
}

/**
 * Judge a non-shell tool call. Returns the first protected destination, or
 * null. Never throws: this runs on the hook path, where an exception would
 * break every tool call on the machine.
 */
export function ssrfDestinationFloor(
  toolName: string,
  args: unknown,
  opts: { ssrfStrict?: boolean; ssrfAllow?: readonly string[]; allowPrivate?: boolean } = {}
): DestinationHit | null {
  try {
    const paths = DESTINATION_ARGS.get(bareToolName(toolName));
    if (!paths) return null;
    for (const path of paths) {
      for (const value of valuesAt(args, path)) {
        const host = hostOf(value);
        if (!host) continue;
        const m = classifySsrf(host);
        if (!m) continue;
        // The same questions the shell floor asks, asked of the same
        // function rather than re-expressed here. Two spellings of one rule is
        // how the parts of this feature drifted apart all day.
        const written = writtenAuthority(value) ?? host;
        const decision = ssrfFloorDecision(m, written, opts);
        if (decision === null) continue;
        const reason =
          decision === 'review' ? ssrfDisguisedReason(m, written) : ssrfReason(m, host);
        return { ...m, argPath: path, host, reason, decision };
      }
    }
    return null;
  } catch {
    return null;
  }
}

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
import { classifySsrf, isStrictGatedTier, ssrfReason, type SsrfMatch } from './ssrf';

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

export interface DestinationHit extends SsrfMatch {
  /** The path that carried it, for the message and the audit row. */
  argPath: string;
  host: string;
  reason: string;
}

/**
 * Judge a non-shell tool call. Returns the first protected destination, or
 * null. Never throws: this runs on the hook path, where an exception would
 * break every tool call on the machine.
 */
export function ssrfDestinationFloor(
  toolName: string,
  args: unknown,
  opts: { ssrfStrict?: boolean; ssrfAllow?: readonly string[] } = {}
): DestinationHit | null {
  try {
    const paths = DESTINATION_ARGS.get(bareToolName(toolName));
    if (!paths) return null;
    const exempt = new Set((opts.ssrfAllow ?? []).map((a) => classifySsrf(a)?.normalized ?? a));
    for (const path of paths) {
      for (const value of valuesAt(args, path)) {
        const host = hostOf(value);
        if (!host) continue;
        const m = classifySsrf(host);
        if (!m) continue;
        // The same two questions the shell floor asks, asked of the same
        // functions rather than re-expressed here. Two spellings of one rule is
        // how the parts of this feature drifted apart all day.
        if (isStrictGatedTier(m.tier) && !opts.ssrfStrict) continue;
        if (m.overridable && m.normalized && exempt.has(m.normalized)) continue;
        return { ...m, argPath: path, host, reason: ssrfReason(m, host) };
      }
    }
    return null;
  } catch {
    return null;
  }
}

// src/exposure/roles.ts
// What a tool IS for the exposure gate (fw#318, design 3.3): a SOURCE brings
// outside content into the session, an ACTION changes the world, a READ does
// neither. A tool may be both. Phase 1 decides from fixed lists and the
// user's `policy.untrustedContent.roles`; MCP annotations through the tool
// inventory are phase P2.

import type { Config } from '../config';
import fs from 'fs';
import { getMcpToolsFile, readMcpToolsConfig, type McpToolAnnotations } from '../daemon/mcp-tools';

/** The review label every surface shows for a held call. */
export const EXPOSURE_LABEL = '🛡️ Node9 Exposure';

export interface ToolRole {
  source: boolean;
  action: boolean;
  /** The server declared the tool destructive: held after exposure even with no destination. */
  destructive?: boolean;
}

/** Servers the agent itself provides (Claude Code's session, view and host
 *  tools): their results are the agent's own state, not outside content, and
 *  their calls change nothing outside the machine. Read, not source or action.
 *  Server-name prefixes, lower-cased. */
const AGENT_INTERNAL_PREFIXES = ['ccd_', 'visualize'];

/** Claude Code folds characters outside [A-Za-z0-9_-] in a server name. */
function foldServerName(name: string): string {
  return name.replace(/[^A-Za-z0-9_-]/g, '_').toLowerCase();
}

let inventoryCache: Map<string, Map<string, McpToolAnnotations | null>> | null = null;
let inventoryStamp: string | null = null;

/** The inventory file's mtime and size, or '' when it is missing. */
function inventoryFileStamp(): string {
  try {
    const st = fs.statSync(getMcpToolsFile());
    return `${st.mtimeMs}:${st.size}`;
  } catch {
    return '';
  }
}

/**
 * The annotations the inventory holds for `server`/`tool`, or null: no
 * record, no annotations, or two records sharing the name (ambiguous, so
 * unannotated). The inventory is reread when the file changes (the gateway
 * lives for the whole agent session while servers are discovered) and matched
 * on the gateway's config name after the same folding the agent applies to
 * its server names.
 */
export function resolveToolAnnotations(server: string, tool: string): McpToolAnnotations | null {
  const stamp = inventoryFileStamp();
  if (inventoryCache === null || stamp !== inventoryStamp) {
    inventoryStamp = stamp;
    inventoryCache = new Map();
    try {
      const seen = new Map<string, number>();
      for (const cfg of Object.values(readMcpToolsConfig())) {
        if (!cfg?.name) continue;
        const key = foldServerName(cfg.name);
        seen.set(key, (seen.get(key) ?? 0) + 1);
        const tools = new Map<string, McpToolAnnotations | null>();
        for (const t of cfg.tools ?? []) tools.set(t.name, t.annotations ?? null);
        inventoryCache.set(key, tools);
      }
      for (const [key, n] of seen) if (n > 1) inventoryCache.delete(key);
    } catch {
      /* no inventory: unannotated */
    }
  }
  return inventoryCache.get(foldServerName(server))?.get(tool) ?? null;
}

export function _resetRolesCache(): void {
  inventoryCache = null;
  inventoryStamp = null;
}

/** Built-in tools that return content from outside the machine. Bare,
 *  lower-cased names: the browser tools arrive as `mcp__<server>__navigate`. */
const BUILTIN_SOURCES = new Set([
  'webfetch',
  'websearch',
  'web_fetch',
  'web_search',
  'fetch',
  'navigate',
  'browser_batch',
  'get_page_text',
  'read_page',
  'find',
  'read_console_messages',
  'read_network_requests',
  // Claude Code reads MCP resources through two built-ins, not through the
  // server's own tools: an email read as a resource is still an email.
  'readmcpresourcetool',
  'listmcpresourcestool',
]);

const MCP_RE = /^mcp__([^_](?:[^_]|_(?!_))*?)__(.+)$/i;

/** `mcp__gmail__send_email` -> { server: 'gmail', bare: 'send_email' }. */
export function splitMcpToolName(toolName: string): { server: string; bare: string } | null {
  const m = toolName.match(MCP_RE);
  return m ? { server: m[1], bare: m[2] } : null;
}

/**
 * The role of a tool as the hook names it.
 *
 * - a `roles[server][tool]` entry wins outright;
 * - a namespaced MCP tool with no entry is a source AND an action (the MCP
 *   spec's defaults for an unannotated tool: not read-only, open world);
 * - a built-in source is a source; everything else is neither here (writes
 *   and shell sends are judged by their own gates).
 */
export function toolRole(toolName: string, policy: Config['policy']['untrustedContent']): ToolRole {
  const mcp = splitMcpToolName(toolName);
  const bare = (mcp ? mcp.bare : toolName).toLowerCase();
  if (mcp) {
    const configured = policy.roles[mcp.server]?.[mcp.bare] ?? policy.roles[mcp.server]?.[bare];
    if (configured === 'source') return { source: true, action: false };
    if (configured === 'action') return { source: false, action: true };
    if (configured === 'read') return { source: false, action: false };
    const serverLower = mcp.server.toLowerCase();
    if (AGENT_INTERNAL_PREFIXES.some((p) => serverLower.startsWith(p)))
      return { source: false, action: false };
    if (BUILTIN_SOURCES.has(bare)) return { source: true, action: false };
    // Annotations add caution only (P2 decision 9.1): a declared
    // destructiveHint makes the call destructive; readOnlyHint or
    // openWorldHint:false never relax by themselves.
    const ann = resolveToolAnnotations(mcp.server, mcp.bare);
    return { source: true, action: true, destructive: ann?.destructiveHint === true };
  }
  return { source: BUILTIN_SOURCES.has(bare), action: false };
}

/**
 * The injection scanner's origin, from the source decision (fw#328, review
 * F6). With untrustedContent on, a source read is outside content to the
 * scanner too, and a tool the admin marked `read` is trusted by it (no
 * outside-origin booster, whatever its name says). Anything else, and
 * everything with untrustedContent off, is left to the scanner's own list.
 */
export function injectionOrigin(
  toolName: string,
  policy: Config['policy']['untrustedContent'] | undefined,
  sourceRead: boolean
): { untrusted?: boolean } {
  if (!policy?.enabled) return {};
  if (sourceRead) return { untrusted: true };
  const mcp = splitMcpToolName(toolName);
  if (!mcp) return {};
  const configured =
    policy.roles[mcp.server]?.[mcp.bare] ?? policy.roles[mcp.server]?.[mcp.bare.toLowerCase()];
  return configured === 'read' ? { untrusted: false } : {};
}

/** The word for what a shell fetch read, from the classifier's fetch kinds. */
export function shellSourceWord(kinds: readonly string[]): string {
  if (kinds.some((k) => /^gh (issue|pr)/.test(k))) return 'issue';
  if (kinds.some((k) => k.startsWith('git ') || k === 'gh repo')) return 'repository';
  return 'web page';
}

/** The word the frame and the prompt use for what was read. */
export function sourceWord(toolName: string): string {
  const mcp = splitMcpToolName(toolName);
  const bare = (mcp ? mcp.bare : toolName).toLowerCase();
  const server = (mcp?.server ?? '').toLowerCase();
  if (/mail|message|inbox|thread/.test(bare) || /mail|slack|teams|chat/.test(server))
    return 'email';
  if (/issue|ticket|pull|pr\b|comment/.test(bare) || /github|gitlab|jira|linear/.test(server))
    return 'issue';
  if (BUILTIN_SOURCES.has(bare) || /browser|web|http|search/.test(server)) return 'web page';
  return 'tool result';
}

// src/exposure/roles.ts
// What a tool IS for the exposure gate (fw#318, design 3.3): a SOURCE brings
// outside content into the session, an ACTION changes the world, a READ does
// neither. A tool may be both. Phase 1 decides from fixed lists and the
// user's `policy.untrustedContent.roles`; MCP annotations through the tool
// inventory are phase P2.

import type { Config } from '../config';

/** The review label every surface shows for a held call. */
export const EXPOSURE_LABEL = '🛡️ Node9 Exposure';

export interface ToolRole {
  source: boolean;
  action: boolean;
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
    if (BUILTIN_SOURCES.has(bare)) return { source: true, action: false };
    return { source: true, action: true };
  }
  return { source: BUILTIN_SOURCES.has(bare), action: false };
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

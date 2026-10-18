// src/exposure/source.ts
// One way to record that a session read outside content (fw#318 review F3).
//
// Every path that sees a source result (the PostToolUse hook in Mode A and
// Mode B, the MCP gateway) calls this, so each read leaves the same trail:
// an informational audit row with an eid (the source of the edge a held send
// draws back to this read), the per-session marker the hot path checks, and
// the daemon's exposure record with the destinations the content named.
//
// The row stays in the local audit log; the shipper skips it (review F2).
// Best-effort, never throws: a failed record must not fail the hook or the
// gateway's forward.

import { appendLocalAudit, appendToLog, HOOK_DEBUG_LOG } from '../audit';
import { notifySessionExposure } from '../auth/daemon';
import { markSessionExposed } from './marker';

export interface ExposureSourceRead {
  /** The tool as node9 names it (canonical, or the gateway's bare name). */
  tool: string;
  args: unknown;
  sessionId: string;
  /** The MCP server the read came through, for the prompt's "through X". */
  server?: string;
  /** What was read ('web page', 'issue'), when the tool name does not say. */
  word?: string;
  destinations: string[];
  agent?: string;
  agentToolName?: string;
  mcpServer?: string;
  hashArgs: boolean;
}

/** Record a read of outside content; returns the row's eid, or undefined. */
export async function recordExposureSource(read: ExposureSourceRead): Promise<string | undefined> {
  if (!read.sessionId) return undefined;
  let eid: string | undefined;
  try {
    eid = appendLocalAudit(
      read.tool,
      read.args,
      'allow',
      'exposure-source',
      {
        ...(read.agent ? { agent: read.agent } : {}),
        ...(read.mcpServer ? { mcpServer: read.mcpServer } : {}),
        sessionId: read.sessionId,
        ...(read.agentToolName && read.agentToolName !== read.tool
          ? { agentToolName: read.agentToolName }
          : {}),
        exposure: { kind: 'source', destinations: read.destinations.length },
      },
      read.hashArgs
    );
  } catch (err) {
    // The marker and the daemon record below still mark the session, but the
    // held send loses its edge to this read: say so (CLAUDE.md, audit trail).
    appendToLog(HOOK_DEBUG_LOG, {
      ts: new Date().toISOString(),
      event: 'exposure-source-row-fail',
      tool: read.tool,
      error: err instanceof Error ? err.message : String(err),
    });
  }
  markSessionExposed(read.sessionId);
  await notifySessionExposure(
    read.sessionId,
    {
      tool: read.tool,
      ...(read.server ? { server: read.server } : {}),
      ...(read.word ? { word: read.word } : {}),
      ...(eid ? { eid } : {}),
    },
    read.destinations
  );
  return eid;
}

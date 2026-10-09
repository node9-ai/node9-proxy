// src/tool-output.ts
// The text a tool returned, read from whatever shape the agent sent.
//
// Each agent and each tool has its own `tool_response` shape: Claude Code's
// Bash sends `{ stdout, stderr, ... }`, its Read sends `{ file: { content } }`,
// an MCP result sends `content[].text`, the OpenCode and Pi shims send
// `{ output }`, Codex declares the field as any JSON. The response-channel
// scan used to read one field (`output`) and so saw nothing on Claude Code.
//
// This walks every string leaf instead. No per-tool table: a tool whose shape
// was never captured is still scanned, and a new field is never missed. The
// cost is a few bytes of non-text noise (a file path, a type tag) the scanners
// ignore.
import { DLP_SCAN_LIMITS } from './dlp';

export interface ToolOutputText {
  /** Every string leaf, in document order, joined with newlines. */
  text: string;
  /** True when the bound cut the walk short: the scan is partial, not clean. */
  truncated: boolean;
  /** How many string leaves contributed at least one character. */
  fields: number;
}

const MAX_DEPTH = 8;

export function collectToolOutputText(
  toolResponse: unknown,
  opts: { maxBytes?: number } = {}
): ToolOutputText {
  const maxBytes = opts.maxBytes ?? DLP_SCAN_LIMITS.maxStringBytes;
  const parts: string[] = [];
  let size = 0;
  let fields = 0;
  let truncated = false;

  const push = (s: string): boolean => {
    if (s.length === 0) return true;
    const room = maxBytes - size;
    if (s.length > room) {
      if (room > 0) {
        parts.push(s.slice(0, room));
        fields++;
      }
      size = maxBytes;
      truncated = true;
      return false;
    }
    parts.push(s);
    fields++;
    size += s.length + 1;
    return true;
  };

  const walk = (v: unknown, depth: number): boolean => {
    if (typeof v === 'string') return push(v);
    if (depth >= MAX_DEPTH || v === null || typeof v !== 'object') return true;
    const children = Array.isArray(v) ? v : Object.values(v as Record<string, unknown>);
    for (const child of children) if (!walk(child, depth + 1)) return false;
    return true;
  };

  walk(toolResponse, 0);
  return { text: parts.join('\n'), truncated, fields };
}

/**
 * The streams a shell tool produced, for test-result detection: Claude Code's
 * Bash sends `stdout` and `stderr`; any other shape falls back to every leaf.
 */
export function shellOutputText(toolResponse: unknown): string {
  if (toolResponse && typeof toolResponse === 'object' && !Array.isArray(toolResponse)) {
    const r = toolResponse as Record<string, unknown>;
    if (typeof r.stdout === 'string' || typeof r.stderr === 'string') {
      return [r.stdout, r.stderr].filter((s): s is string => typeof s === 'string').join('\n');
    }
  }
  return collectToolOutputText(toolResponse).text;
}

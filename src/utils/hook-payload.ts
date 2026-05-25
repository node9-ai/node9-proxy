// src/utils/hook-payload.ts
// Pure extractors for the agent-hook stdin JSON payload.
//
// Agents disagree on field names: Claude Code sends `tool_name` /
// `tool_input`, Gemini CLI sends `name` / `args`. Centralising the
// fallback chain keeps the check and log handlers in lockstep when a
// new agent ships a new alias — otherwise the two paths drift and a
// payload variant gets handled correctly in one place but not the other.
//
// No runtime dependencies. No sanitisation, no normalisation — callers
// keep responsibility for their own validation and downstream defaults.

/**
 * Minimal shape understood by the extractors. Real payloads carry many
 * more fields (session_id, cwd, hook_event_name, …); this interface only
 * declares the ones the helpers themselves read so unrelated payload
 * variants stay assignable without casts at the call site.
 */
export interface HookPayloadToolFields {
  tool_name?: string;
  /** Gemini CLI alias for `tool_name`. */
  name?: string;
  tool_input?: unknown;
  /** Gemini CLI alias for `tool_input`. */
  args?: unknown;
}

/**
 * Read the tool name from a hook payload, falling back across the known
 * agent dialects. Returns `defaultValue` when no field is present.
 *
 * Lookup order: Claude (`tool_name`) → Gemini (`name`) → default.
 */
export function extractToolName(payload: HookPayloadToolFields, defaultValue = ''): string {
  return payload.tool_name ?? payload.name ?? defaultValue;
}

/**
 * Read the tool arguments from a hook payload, falling back across the
 * known agent dialects. Returns an empty object when no field is present.
 *
 * Lookup order: Claude (`tool_input`) → Gemini (`args`) → `{}`.
 */
export function extractToolInput(payload: HookPayloadToolFields): unknown {
  return payload.tool_input ?? payload.args ?? {};
}

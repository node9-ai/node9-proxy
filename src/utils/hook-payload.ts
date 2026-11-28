// src/utils/hook-payload.ts
// Pure extractors for the agent-hook stdin JSON payload.
//
// Agents disagree on field names: Claude Code sends `tool_name` /
// `tool_input`, Gemini CLI sends `name` / `args`. Centralising the
// fallback chain keeps the check and log handlers in lockstep when a
// new agent ships a new alias — otherwise the two paths drift and a
// payload variant gets handled correctly in one place but not the other.
//
// No runtime dependencies. `inspectablePayload` makes a parsed payload safe to
// walk and coerce; beyond that, callers keep responsibility for their own
// validation and downstream defaults.

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
  /**
   * Antigravity (agy) nests both under `toolCall`. Verified against agy
   * 1.0.6 spy-hook captures (doc/roadmap/antigravity-target.md §0.3):
   * PostToolUse also fires with `toolCall: null` on non-tool steps
   * (planner responses) — callers must treat that as "no tool".
   */
  toolCall?: { name?: string; args?: unknown } | null;
}

/**
 * Read the tool name from a hook payload, falling back across the known
 * agent dialects. Returns `defaultValue` when no field is present.
 *
 * Lookup order: Claude (`tool_name`) → Gemini (`name`) →
 * Antigravity (`toolCall.name`) → default.
 */
export function extractToolName(payload: HookPayloadToolFields, defaultValue = ''): string {
  // Only a string is a tool name: a number or an object here made every later
  // string operation throw, and the hook's error path let the call run.
  for (const name of [payload.tool_name, payload.name, payload.toolCall?.name]) {
    if (typeof name === 'string') return name;
  }
  return defaultValue;
}

/**
 * Deepest nesting an inspected payload keeps. Past it a subtree becomes one
 * text value (see {@link inspectablePayload}). Real tool arguments nest a few
 * levels; node9's own walkers are recursive and overflow the stack at a few
 * thousand.
 */
export const MAX_PAYLOAD_DEPTH = 64;

/** Own keys that shadow the methods `String(obj)` calls: with a non-function
 *  there, coercing the object throws. JSON can only put a non-function there. */
const COERCION_KEYS = new Set(['toString', 'valueOf']);

/** Text of a subtree: its keys and leaves in document order, one per line. No recursion. */
function subtreeText(root: object): string {
  const out: string[] = [];
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const v = stack.pop();
    if (v === null || typeof v !== 'object') {
      out.push(typeof v === 'string' ? v : JSON.stringify(v));
      continue;
    }
    const children: unknown[] = [];
    if (Array.isArray(v)) {
      for (const item of v) children.push(item);
    } else {
      for (const [k, item] of Object.entries(v)) {
        out.push(k);
        children.push(item);
      }
    }
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
  }
  return `[node9: nested deeper than ${MAX_PAYLOAD_DEPTH} levels]\n` + out.join('\n');
}

function inspectableValue(value: unknown, depth: number): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (depth >= MAX_PAYLOAD_DEPTH) return subtreeText(value);
  if (Array.isArray(value)) return value.map((v) => inspectableValue(v, depth + 1));
  const entries: [string, unknown][] = [];
  const taken = new Set(Object.keys(value));
  for (const [k, v] of Object.entries(value)) {
    let key = k;
    if (COERCION_KEYS.has(k)) {
      do key += '_';
      while (taken.has(key));
      taken.add(key);
    }
    entries.push([key, inspectableValue(v, depth + 1)]);
  }
  // fromEntries defines own properties: a `__proto__` key stays a key.
  return Object.fromEntries(entries);
}

/**
 * The copy of a parsed hook payload that node9 inspects. The agent's tool
 * arguments are data a model wrote; two shapes of them made node9's own code
 * throw, and a hook that throws lets the call run (node9Firewall#383, step 0):
 *
 *  - nesting thousands of levels deep overflows every recursive walker;
 *  - an object with its own `toString` or `valueOf` key cannot be coerced to
 *    a string.
 *
 * Nothing is dropped, so no check loses sight of a value: a subtree past
 * {@link MAX_PAYLOAD_DEPTH} is kept as one text value listing its keys and
 * leaves, and a shadowing key is kept under the same name with `_` appended.
 * A payload that is not a JSON object becomes an empty one, which the hook
 * already reports as unrecognised. The call itself is not changed: this is
 * only what node9 reads.
 *
 * `check` and `log` both use it, so the two hooks derive the same keys.
 */
export function inspectablePayload(parsed: unknown): Record<string, unknown> {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  return inspectableValue(parsed, 0) as Record<string, unknown>;
}

/**
 * The same safe copy for one call's arguments, for the callers that never see
 * a hook payload: the MCP gateway, the proxy and the SDK hand their arguments
 * straight to `authorizeHeadless`, which applies this at its entry. Copying an
 * already safe value changes nothing.
 */
export function inspectableArgs(args: unknown): unknown {
  return inspectableValue(args, 0);
}

/**
 * Read the tool arguments from a hook payload, falling back across the
 * known agent dialects. Returns an empty object when no field is present.
 *
 * Lookup order: Claude (`tool_input`) → Gemini (`args`) →
 * Antigravity (`toolCall.args`) → `{}`.
 */
export function extractToolInput(payload: HookPayloadToolFields): unknown {
  return payload.tool_input ?? payload.args ?? payload.toolCall?.args ?? {};
}

/**
 * Translate an agent-native tool name to the canonical Claude vocabulary.
 *
 * Different agents call the same conceptual tool different things:
 * Claude says `Bash`, Hermes says `terminal`, Gemini says
 * `run_shell_command`. Canonicalising at the hook-payload boundary means
 * the rest of node9 (shields, smart-rules, snapshot config, audit log
 * schema) only needs to know Claude's vocabulary — every other agent's
 * payloads get normalised on entry.
 *
 * Unknown names pass through unchanged: MCP tools (`mcp__server__tool`),
 * agent-specific tools (`delegate_task`, `vision_analyze`, `browser_*`),
 * and any future name we haven't mapped yet stay as-is so they remain
 * grep-able and don't silently become `Bash`.
 */
export function canonicalToolName(name: string): string {
  switch (name) {
    // Hermes Agent
    case 'terminal':
      return 'Bash';
    case 'write_file':
      return 'Write';
    case 'patch':
      return 'Edit';
    case 'read_file':
      return 'Read';
    case 'search_files':
      return 'Grep';
    // Antigravity (agy) — shell tool renamed from Gemini's run_shell_command
    case 'run_command':
      return 'Bash';
    default:
      return name;
  }
}

/**
 * Map a `--agent` flag value (set by node9's own hook registrations,
 * e.g. `node9 check --agent antigravity`) to the canonical agent label
 * used by agent detection in check/log. Trusted like a Layer-0
 * meta.agent tag: node9 wrote the hook entry, so the flag is
 * deterministic where payload fingerprints could drift across agent
 * versions. Unknown values are ignored (fall back to fingerprinting)
 * rather than trusted verbatim — the label selects block-response
 * shapes, so an arbitrary string is unsafe.
 *
 * `copilot` is essential here, not just convenient: the GitHub Copilot
 * CLI PascalCase payload is byte-identical to Claude Code's
 * (`hook_event_name: "PreToolUse"`, `tool_name`, `tool_input`), so it
 * cannot be told apart by fingerprint — the flag is the only reliable
 * signal.
 *
 * `codex` is for Codex's SessionStart hook: that payload has no `turn_id`
 * (the Codex fingerprint) and does have `permission_mode`, so it would be
 * fingerprinted as Claude Code (node9Firewall#473 follow-up, session notice).
 */
export function agentLabelFromFlag(flag: unknown): string | undefined {
  if (typeof flag !== 'string') return undefined;
  switch (flag.toLowerCase()) {
    case 'antigravity':
    case 'agy':
      return 'Antigravity';
    case 'copilot':
      return 'GitHub Copilot';
    case 'codex':
      return 'Codex';
    default:
      return undefined;
  }
}

/**
 * Translate agent-native tool arguments to the canonical Claude shape.
 *
 * Antigravity's `run_command` args carry the shell command as
 * `CommandLine` and the working directory as `Cwd` (PascalCase) —
 * verified against agy 1.0.6 spy-hook captures. Downstream consumers
 * (shields, DLP `toolInspection`, snapshot, audit `args.command`
 * readers) all expect Claude's `{ command, cwd }`, so we rewrite at the
 * boundary, mirroring what {@link canonicalToolName} does for names.
 *
 * Non-`run_command` tools and non-object inputs pass through unchanged.
 * Agy-specific metadata fields (`toolAction`, `toolSummary`,
 * `WaitMsBeforeAsync`, …) are preserved as-is so they stay visible in
 * the audit log. (GitHub Copilot CLI needs no mapping — its `bash` tool
 * args are already `{ command, description }`.)
 */
export function canonicalToolInput(rawToolName: string, input: unknown): unknown {
  if (rawToolName !== 'run_command') return input;
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return input;

  const args = input as Record<string, unknown>;
  if (typeof args.CommandLine !== 'string') return input;

  const { CommandLine, Cwd, ...rest } = args;
  const canonical: Record<string, unknown> = { ...rest, command: CommandLine };
  if (typeof Cwd === 'string' && Cwd.length > 0) canonical.cwd = Cwd;
  return canonical;
}

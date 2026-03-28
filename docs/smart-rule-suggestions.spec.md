# Smart Rule Suggestions — Feature Spec

**Status:** Draft
**Author:** node9 team
**Date:** 2026-03-28

---

## Problem

When an AI agent is working on a legitimate task (e.g., refactoring a component folder), Node9 blocks the same tool repeatedly. The user clicks "Allow" 5–10 times. This is friction without security benefit — the user has already decided to trust the operation, they're just not aware they can make it permanent.

The naive fix — letting the AI call a `node9_propose_rule` tool — is **not safe**. A malicious document (prompt injection) could instruct the AI to propose a rule that grants it broad permissions. The AI cannot be trusted to initiate config changes on its own.

## Solution: Daemon-Side Pattern Detection

The **daemon** (not the AI) watches for repeated blocks and surfaces a suggestion in the UI. The human approves. The AI never touches the flow.

```
AI calls write_file → blocked (1)
AI calls write_file → blocked (2)
AI calls write_file → blocked (3)
                          ↓
                    Daemon detects pattern
                          ↓
             Browser/terminal: "write_file blocked 3×
              in /src/components/ — create a rule?"
                          ↓
                    Human clicks Apply
                          ↓
              config.json updated atomically
```

The AI's behavior doesn't change. The suggestion engine is entirely out-of-band.

---

## Threat Model

| Attack                                            | Mitigated? | How                                                            |
| ------------------------------------------------- | ---------- | -------------------------------------------------------------- |
| Prompt injection → AI proposes broad rule         | ✓          | AI never calls any proposal tool                               |
| Malicious upstream suggests rule via MCP response | ✓          | Suggestion engine only reads daemon block log, not MCP content |
| User rubber-stamps without reading                | Partial    | UI shows exact JSON diff before apply                          |
| Rule created for wrong path (false pattern)       | Partial    | User can edit the generated rule before applying               |
| Daemon compromised → auto-apply rules             | ✓          | Apply always requires explicit human POST                      |

---

## Scope (v1)

**In scope:**

- Track blocks per tool per session in daemon memory
- After N=3 blocks for the same tool, generate a suggestion
- Surface suggestion via SSE (`suggestion:new` event) and daemon REST API
- Browser dashboard shows suggestion card with preview and Apply/Dismiss
- On Apply: atomically patch `~/.node9/config.json` (or project `node9.config.json`)
- On Dismiss: suppress for the rest of the session
- `node9 tail` surfaces suggestions in terminal

**Out of scope (v1):**

- AI-initiated proposals
- Suggestions for `smartRules` (only `ignoredTools` and simple allow rules in v1)
- Cross-session persistence of suggestion history
- Cloud/SaaS suggestion sync
- Undo for applied suggestions (use existing undo engine)

---

## Architecture

### Components

```
node9-proxy/
  src/
    daemon/
      suggestion-tracker.ts   ← NEW: tracks blocks, generates suggestions
      suggestions.ts           ← NEW: REST routes + SSE broadcast
      server.ts                ← MODIFIED: mount suggestion routes
      state.ts                 ← MODIFIED: add suggestions to shared state
    config/
      patch.ts                 ← NEW: atomic config.json patch writer
    auth/
      orchestrator.ts          ← MODIFIED: notify tracker on each block

node9Firewall/fe/
  src/
    components/
      SuggestionCard.tsx       ← NEW: dashboard card UI
    hooks/
      useSuggestions.ts        ← NEW: SSE listener for suggestions
```

---

## Data Model

### `BlockEvent`

```typescript
interface BlockEvent {
  toolName: string; // "write_file"
  mcpServer?: string; // "filesystem" (from mcp__filesystem__write_file)
  args: Record<string, unknown>; // { path: "/src/components/Button.tsx" }
  blockedAt: number; // Date.now()
  source: 'gateway' | 'hook'; // which interceptor caught it
  configPath?: string; // which config.json applies (project vs global)
}
```

### `Suggestion`

```typescript
interface Suggestion {
  id: string; // uuid
  toolName: string; // "write_file"
  mcpServer?: string; // "filesystem"
  blockCount: number; // 3
  firstBlockAt: number;
  lastBlockAt: number;
  commonPathPrefix?: string; // "/src/components/" (extracted from args)
  suggestedRule: SuggestedRule; // what to write to config
  previewDiff: string; // human-readable: what changes in config.json
  configTarget: 'global' | 'project'; // which file will be patched
  configPath: string; // absolute path to the config file
  status: 'pending' | 'applied' | 'dismissed';
}

type SuggestedRule =
  | { type: 'ignoredTool'; toolName: string }
  | { type: 'smartRule'; rule: SmartRule };
```

### Rule Generation Logic

```
Given N blocks of the same tool:

Case 1: No path argument detectable
  → Add toolName to ignoredTools
  → Label: "Always allow [tool] without asking"

Case 2: Path argument present, all blocks share a common prefix
  (e.g., /src/components/Button.tsx, /src/components/Modal.tsx)
  → Generate smartRule:
    { tool, conditions: [{ field: "path", op: "matchesGlob", value: "/src/components/**" }], verdict: "allow" }
  → Label: "Allow [tool] in /src/components/**"

Case 3: Path arguments diverge (no common prefix > 3 chars)
  → Fall back to Case 1 (ignoredTools)
  → Add note: "Arguments vary — suggesting global allow"
```

Path prefix extraction:

```typescript
function commonPrefix(paths: string[]): string {
  if (paths.length === 0) return '';
  let prefix = path.dirname(paths[0]);
  for (const p of paths.slice(1)) {
    while (!p.startsWith(prefix) && prefix.length > 1) {
      prefix = path.dirname(prefix);
    }
  }
  // Only use prefix if it's meaningful (not just "/" or "")
  return prefix.length > 3 ? prefix : '';
}
```

---

## API

### REST Endpoints (daemon)

```
GET  /suggestions
     → { suggestions: Suggestion[] }
     Returns all pending suggestions for this session.

POST /suggestions/:id/apply
     Body: { configTarget?: 'global' | 'project' }
     → { ok: true, suggestion: Suggestion }
     Applies the rule to config.json. Broadcasts suggestion:resolved via SSE.
     409 if already applied/dismissed.

POST /suggestions/:id/dismiss
     → { ok: true }
     Marks dismissed. Will not resurface this session.
     Broadcasts suggestion:resolved via SSE.

PATCH /suggestions/:id/rule
     Body: { rule: SuggestedRule }   // user edits before applying
     → { ok: true, suggestion: Suggestion }
     Lets user modify the generated rule before applying.
```

### SSE Events

```
suggestion:new      { suggestion: Suggestion }
suggestion:resolved { id: string, status: 'applied' | 'dismissed' }
```

---

## Trigger Threshold

Default: **3 blocks** of the same `toolName` in a session.

Configurable via `~/.node9/config.json`:

```json
{
  "settings": {
    "suggestionThreshold": 3, // 0 = disable suggestions entirely
    "suggestionEnabled": true
  }
}
```

A "session" is defined as: daemon process uptime. Daemon restart resets counters.
This is intentional — suggestions should reflect active work, not historical patterns.

---

## Config Patch (Atomic Write)

To avoid corrupting the config file on crash:

```typescript
async function patchConfig(configPath: string, patch: ConfigPatch): Promise<void> {
  const tmp = configPath + '.node9-suggestion-tmp';
  const existing = JSON.parse(await fs.readFile(configPath, 'utf8'));
  const patched = applyPatch(existing, patch);
  // Validate with Zod before writing
  ConfigSchema.parse(patched);
  await fs.writeFile(tmp, JSON.stringify(patched, null, 2), 'utf8');
  await fs.rename(tmp, configPath); // atomic on POSIX
}
```

`applyPatch` for `ignoredTools`:

```typescript
policy.ignoredTools = [...new Set([...policy.ignoredTools, toolName])];
```

`applyPatch` for `smartRule`:

```typescript
policy.smartRules = [newRule, ...policy.smartRules];
// Prepend so it takes precedence over less-specific rules
```

---

## Terminal UI (`node9 tail`)

When a suggestion arrives via SSE, `node9 tail` shows:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💡 SUGGESTION  write_file blocked 3×
   Suggested rule: Allow write_file in /src/components/**
   Apply? [a]pply  [d]ismiss  [e]dit  [?]preview
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

`[?]preview` shows the exact JSON diff that will be written.

---

## Browser Dashboard UI

New `SuggestionCard` component, shown above the pending requests list:

```
┌─────────────────────────────────────────────────────┐
│ 💡 Smart Rule Suggestion                             │
│                                                     │
│ write_file was blocked 3 times in /src/components/  │
│                                                     │
│ Suggested rule:                                     │
│   Allow write_file when path matches                │
│   /src/components/**                                │
│                                                     │
│ Config change preview:                              │
│   + "smartRules": [                                 │
│   +   { "tool": "write_file",                       │
│   +     "conditions": [{"field":"path",             │
│   +       "op":"matchesGlob",                       │
│   +       "value":"/src/components/**"}],           │
│   +     "verdict": "allow" }                        │
│   + ]                                               │
│                                                     │
│  [Apply Rule]  [Dismiss]  [Edit Rule]               │
│                                                     │
│  ○ Global config  ● Project config (recommended)    │
└─────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1 — Daemon core (node9-proxy)

**Step 1.1**: `src/daemon/suggestion-tracker.ts`

- `SuggestionTracker` class
- `recordBlock(event: BlockEvent): Suggestion | null` — returns suggestion when threshold hit
- `getSuggestions(): Suggestion[]`
- `dismiss(id): void`
- Path prefix extraction
- Rule generation (ignoredTools vs smartRule)
- In-memory only, no persistence needed in v1

**Step 1.2**: `src/config/patch.ts`

- `patchConfig(configPath, patch)` — atomic write with Zod validation
- `previewPatch(existing, patch): string` — returns diff string for UI

**Step 1.3**: `src/daemon/suggestions.ts`

- Express router: GET /suggestions, POST /suggestions/:id/apply, POST /suggestions/:id/dismiss, PATCH /suggestions/:id/rule
- CSRF protection on state-mutating routes (same as existing /settings)

**Step 1.4**: `src/daemon/server.ts`

- Mount suggestion router
- Add `SuggestionTracker` to shared state
- Broadcast `suggestion:new` via SSE when tracker returns a suggestion

**Step 1.5**: `src/auth/orchestrator.ts`

- After a block decision, call `tracker.recordBlock(event)`
- If returns a suggestion, broadcast via daemon state

**Step 1.6**: Tests

- Unit: suggestion-tracker (threshold, path prefix extraction, rule generation)
- Unit: config patch (atomic write, Zod validation, rollback on invalid)
- Integration: daemon API routes (apply, dismiss, preview)

### Phase 2 — Terminal UI (node9-proxy)

**Step 2.1**: `src/cli/commands/tail.ts`

- Handle `suggestion:new` SSE event
- Show suggestion prompt with keypress handler (a/d/e/?)
- POST to /suggestions/:id/apply or /dismiss on keypress

### Phase 3 — Browser Dashboard (node9Firewall)

**Step 3.1**: `fe/src/hooks/useSuggestions.ts`

- Subscribe to `suggestion:new` and `suggestion:resolved` SSE events
- Maintain `suggestions` state array
- Expose `apply(id, target)`, `dismiss(id)`, `editRule(id, rule)` actions

**Step 3.2**: `fe/src/components/SuggestionCard.tsx`

- Render suggestion with config diff preview
- Global/Project config toggle
- Apply/Dismiss/Edit buttons
- Collapsed by default if no suggestions; expanded with badge count otherwise

**Step 3.3**: Wire into dashboard layout above pending requests

**Step 3.4**: Tests (Vitest + RTL)

- Smoke: renders without crashing
- Shows suggestion content when suggestions array is non-empty
- Apply/Dismiss call correct hook actions
- Config target toggle works

### Phase 4 — Docs

**Step 4.1**: Update `node9Firewall/fe/src/pages/resources/DocsTab.tsx`

- Add "Smart Suggestions" section to Mission Control docs

**Step 4.2**: Update `node9-proxy/README.md`

- Add section explaining suggestion threshold config

---

## Open Questions

1. **Project vs global config**: When the gateway is running without a project config (global only), all suggestions go to global. When a project config exists, default to project. Need to pass `configPath` through the block event. Currently `authorizeHeadless` doesn't surface which config was used.

2. **Multiple agents**: If two Claude instances are running simultaneously and both trigger the threshold, two suggestions for the same tool could appear. Dedup by `toolName` in the tracker — second hit updates the existing suggestion's count rather than creating a new one.

3. **Undo integration**: Applied suggestions write to config.json. Should the undo engine snapshot config.json before applying? Probably yes — use existing snapshot infrastructure.

4. **Shields interaction**: If the block came from a Shield (not a user-written rule), the suggestion might conflict with the Shield. The suggestion UI should note "This tool is currently blocked by [Shield Name]" and warn that the rule may be overridden.

---

## Success Metrics

- User clicks "Allow" fewer than 3 times for the same tool in a session
- Suggestions are accepted (not dismissed) in >50% of cases (signal: generated rules are accurate)
- Zero cases of a rule being applied that the user didn't intend (correctness)
- Config file never corrupted after a suggestion apply (atomic write)

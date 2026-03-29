// src/daemon/suggestion-tracker.ts
// Tracks repeated human-allowed reviews for the same tool. After `threshold`
// consecutive allows, generates a suggested smart rule or ignoredTool entry
// to eliminate the friction permanently.
// Only the daemon calls this — the suggestion list is in-memory per session.
import { randomUUID } from 'crypto';
import type { SmartRule } from '../config/index.js';

// ── Types ─────────────────────────────────────────────────────────────────────

export type SuggestedRulePayload =
  | { type: 'smartRule'; rule: SmartRule }
  | { type: 'ignoredTool'; toolName: string };

export interface Suggestion {
  id: string;
  toolName: string;
  allowCount: number;
  suggestedRule: SuggestedRulePayload;
  status: 'pending' | 'applied' | 'dismissed';
  createdAt: number;
  /** Up to 3 example arg objects shown in the UI card */
  exampleArgs: unknown[];
}

interface AllowEvent {
  args: unknown;
  ts: number;
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/**
 * Extracts a file path from a tool args object.
 * Checks common field names used across MCP and built-in tools.
 */
export function extractPath(args: unknown): string | null {
  if (!args || typeof args !== 'object') return null;
  const a = args as Record<string, unknown>;
  for (const key of ['path', 'file_path', 'filename', 'filepath', 'dest', 'destination']) {
    if (typeof a[key] === 'string' && a[key]) return a[key] as string;
  }
  return null;
}

/**
 * Returns the longest common directory prefix across a list of file paths.
 * e.g. ["/src/a/B.tsx", "/src/a/C.tsx"] → "/src/a/"
 * Returns null if fewer than 2 paths or no common prefix beyond root.
 */
export function commonPathPrefix(paths: string[]): string | null {
  if (paths.length < 2) return null;

  // Split each path into directory segments (ignore filename)
  const dirParts = paths.map((p) => {
    const lastSlash = p.lastIndexOf('/');
    return lastSlash > 0 ? p.slice(0, lastSlash + 1) : '/';
  });

  const first = dirParts[0].split('/');
  const common: string[] = [];

  for (let i = 0; i < first.length; i++) {
    if (dirParts.every((d) => d.split('/')[i] === first[i])) {
      common.push(first[i]);
    } else {
      break;
    }
  }

  // Need at least one real directory segment beyond root
  const prefix = common.join('/').replace(/\/?$/, '/');
  return prefix.length > 1 ? prefix : null;
}

// ── SuggestionTracker ─────────────────────────────────────────────────────────

export class SuggestionTracker {
  private events = new Map<string, AllowEvent[]>();
  private readonly threshold: number;

  constructor(threshold = 3) {
    this.threshold = threshold;
  }

  /**
   * Record a human-allowed review for a tool.
   * Returns a Suggestion when the threshold is reached, null otherwise.
   */
  recordAllow(toolName: string, args: unknown): Suggestion | null {
    const events = this.events.get(toolName) ?? [];
    events.push({ args, ts: Date.now() });
    this.events.set(toolName, events);

    if (events.length >= this.threshold) {
      this.events.delete(toolName); // reset so we don't re-trigger immediately
      return this.generateSuggestion(toolName, events);
    }
    return null;
  }

  /**
   * Reset the counter for a tool (e.g. when the user clicks Deny —
   * don't suggest allowing something they just blocked).
   */
  resetTool(toolName: string): void {
    this.events.delete(toolName);
  }

  /** Current allow count for a tool (for tests). */
  getCount(toolName: string): number {
    return this.events.get(toolName)?.length ?? 0;
  }

  private generateSuggestion(toolName: string, events: AllowEvent[]): Suggestion {
    const paths = events
      .map((e) => extractPath(e.args))
      .filter((p): p is string => typeof p === 'string' && p.length > 0);

    const prefix = commonPathPrefix(paths);

    const suggestedRule: SuggestedRulePayload = prefix
      ? {
          type: 'smartRule',
          rule: {
            name: `allow-${toolName}-${prefix
              .replace(/[^a-z0-9]/gi, '-')
              .replace(/-+/g, '-')
              .replace(/^-|-$/g, '')}`,
            tool: toolName,
            conditions: [{ field: 'path', op: 'matchesGlob', value: `${prefix}**` }],
            verdict: 'allow',
            reason: `Auto-suggested: ${toolName} allowed ${events.length}× in ${prefix}`,
          },
        }
      : { type: 'ignoredTool', toolName };

    return {
      id: randomUUID(),
      toolName,
      allowCount: events.length,
      suggestedRule,
      status: 'pending',
      createdAt: Date.now(),
      exampleArgs: events.slice(0, 3).map((e) => e.args),
    };
  }
}

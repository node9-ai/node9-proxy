// src/config-schema.ts
// Zod schemas for node9 config.json validation.
// Validates each config layer before it is merged into the running config,
// so bad user configs produce a clear error instead of silently using defaults.

import { z } from 'zod';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Rejects strings that contain literal newline characters (breaks JSON). */
const noNewlines = z.string().refine((s) => !s.includes('\n') && !s.includes('\r'), {
  message: 'Value must not contain literal newline characters (use \\n instead)',
});

// ── Smart Rules ───────────────────────────────────────────────────────────────

const SmartConditionSchema = z
  .object({
    field: z.string().min(1, 'Condition field must not be empty'),
    op: z.enum(
      [
        'matches',
        'notMatches',
        'contains',
        'notContains',
        'exists',
        'notExists',
        'matchesGlob',
        'notMatchesGlob',
      ],
      {
        // zod 4 replaced errorMap with `error`. The wording is kept verbatim:
        // it is what a user sees when their config is rejected.
        error: () =>
          'op must be one of: matches, notMatches, contains, notContains, exists, notExists, matchesGlob, notMatchesGlob',
      }
    ),
    value: z.string().optional(),
    flags: z.string().optional(),
  })
  .refine(
    (c) => {
      if (c.op === 'matchesGlob' || c.op === 'notMatchesGlob') return c.value !== undefined;
      return true;
    },
    { message: 'matchesGlob and notMatchesGlob conditions require a value field' }
  );

export const SmartRuleSchema = z.object({
  name: z.string().optional(),
  tool: z.string().min(1, 'Smart rule tool must not be empty'),
  conditions: z.array(SmartConditionSchema).min(1, 'Smart rule must have at least one condition'),
  conditionMode: z.enum(['all', 'any']).optional(),
  verdict: z.enum(['allow', 'review', 'block'], {
    error: () => 'verdict must be one of: allow, review, block',
  }),
  reason: z.string().optional(),
  description: z.string().optional(),
  // Unknown predicate names are filtered out rather than failing the whole rule.
  // Failing the whole z.array() would cause sanitizeConfig to drop the entire
  // `policy` top-level key, silently disabling ALL smart rules in the config.
  dependsOnState: z
    .array(z.string())
    .transform((arr) =>
      arr.filter(
        (p): p is 'no_test_passed_since_last_edit' => p === 'no_test_passed_since_last_edit'
      )
    )
    .optional(),
  recoveryCommand: z.string().optional(),
});

// ── Top-level Config ─────────────────────────────────────────────────────────

export const ConfigFileSchema = z
  .object({
    version: z.string().optional(),
    settings: z
      .object({
        mode: z.enum(['standard', 'strict', 'audit', 'observe']).optional(),
        autoStartDaemon: z.boolean().optional(),
        // enableUndo / policy.snapshot: removed with the undo feature. The
        // schema strips undeclared keys silently (plain zod object — no
        // .strict(), no .passthrough()), so a config still carrying them stays
        // valid and simply loses them. Keeping the fields would instead make
        // `node9_config_get` advertise a removed feature as a live knob.
        enableHookLogDebug: z.boolean().optional(),
        approvalTimeoutMs: z.number().nonnegative().optional(),
        approvalTimeoutSeconds: z.number().nonnegative().optional(),
        flightRecorder: z.boolean().optional(),
        approvers: z
          .object({
            native: z.boolean().optional(),
            browser: z.boolean().optional(),
            cloud: z.boolean().optional(),
            terminal: z.boolean().optional(),
          })
          .optional(),
        environment: z.string().optional(),
        slackEnabled: z.boolean().optional(),
        enableTrustSessions: z.boolean().optional(),
        allowGlobalPause: z.boolean().optional(),
        auditHashArgs: z.boolean().optional(),
        agentPolicy: z.enum(['require_approval', 'block_on_rules']).optional(),
        // Where a `review` verdict's prompt is rendered: 'ask' = the agent's own
        // inline approve/deny prompt (Claude Code / GitHub Copilot); 'approver' =
        // node9's own approver (terminal/native/cloud). Unset → default ASK for
        // ask-capable agents (v2: cloud no longer disables inline — the outcome
        // ships to the dashboard as audit; admins force routing via managed
        // reviewChannel, which outranks the local --ask flag).
        reviewChannel: z.enum(['ask', 'approver']).optional(),
        // When true, agents may call WEAKENING node9 MCP tools (shield_disable,
        // approver_set). Default (unset/false): those tools refuse over MCP — a human
        // must run them from the CLI. node9's threat model is the agent itself.
        mcpAllowWeakening: z.boolean().optional(),
        // Auto-wire reconciler (P3 2.6): auto-wrap new ungoverned MCP servers vs
        // nudge-only (default), and the scan cadence in minutes.
        mcpAutoWrap: z.boolean().optional(),
        mcpReconcileIntervalMinutes: z.number().positive().optional(),
        mcpStaleAfterDays: z.number().min(0).optional(),
        cloudSyncIntervalHours: z.number().positive().optional(),
        // Seconds-granular override for the cloud policy sync cadence. Wins over
        // cloudSyncIntervalHours when set. Lets you opt into fast apply (e.g. 20)
        // for an incident; clamped to a 15s floor so it can't hammer the API.
        // Unset → falls back to hours, then the 5h default.
        cloudSyncIntervalSeconds: z.number().positive().optional(),
        // Outbox shipper (audit.log → SaaS batch ingest). enabled defaults
        // to true; set false to fall back to local-only auditing.
        shipper: z
          .object({
            enabled: z.boolean().optional(),
            intervalSeconds: z.number().min(5).optional(),
          })
          .optional(),
      })
      .optional(),
    policy: z
      .object({
        sandboxPaths: z.array(z.string()).optional(),
        dangerousWords: z.array(noNewlines).optional(),
        ignoredTools: z.array(z.string()).optional(),
        toolInspection: z.record(z.string(), z.string()).optional(),
        smartRules: z.array(SmartRuleSchema).optional(),
        dlp: z
          .object({
            enabled: z.boolean().optional(),
            scanIgnoredTools: z.boolean().optional(),
            pii: z.enum(['off', 'block']).optional(),
            reviewAction: z.enum(['review', 'block']).optional(),
          })
          .optional(),
        // Command-checks governance. Class-B keys (evalDynamic, pipeChainHigh)
        // deliberately exclude 'off' — tighten-only.
        commandChecks: z
          .object({
            inlineExec: z.enum(['off', 'review', 'block']).optional(),
            rmAdvisory: z.enum(['off', 'review', 'block']).optional(),
            chmod: z.enum(['off', 'review', 'block']).optional(),
            sqlDdl: z.enum(['off', 'review', 'block']).optional(),
            evalDynamic: z.enum(['review', 'block']).optional(),
            pipeChainHigh: z.enum(['review', 'block']).optional(),
          })
          .optional(),
        egress: z
          .object({
            enabled: z.boolean().optional(),
            mode: z.enum(['off', 'review', 'block']).optional(),
            allow: z.array(z.string()).optional(),
            deny: z.array(z.string()).optional(),
            allowPrivate: z.boolean().optional(),
            // SSRF floor. `ssrfAllow` exempts OVERRIDABLE tiers only; a tier-1
            // entry is dropped with a warning at load, never silently honoured.
            ssrfAllow: z.array(z.string()).optional(),
            ssrfStrict: z.boolean().optional(),
          })
          .optional(),
        loopDetection: z
          .object({
            enabled: z.boolean().optional(),
            threshold: z.number().min(2).optional(),
            windowSeconds: z.number().min(10).optional(),
          })
          .optional(),
        injectionScan: z
          .object({
            enabled: z.boolean().optional(),
            minConfidence: z.enum(['medium', 'high']).optional(),
            allow: z.array(z.string()).optional(),
          })
          .optional(),
        skillPinning: z
          .object({
            enabled: z.boolean().optional(),
            mode: z.enum(['warn', 'block']).optional(),
            roots: z.array(z.string()).optional(),
          })
          .optional(),
      })
      .optional(),
    environments: z
      .record(z.string(), z.object({ requireApproval: z.boolean().optional() }))
      .optional(),
  })
  // zod 4: .strict() takes no parameters. The message moves onto the object
  // itself, which is where zod 4 reports an unrecognised key.
  .strict();

export type ConfigFileInput = z.input<typeof ConfigFileSchema>;

/** One line per issue: `  • path: message`, with a root issue labelled 'root'. */
function formatIssues(issues: ReadonlyArray<{ path: PropertyKey[]; message: string }>): string {
  const lines = issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.map(String).join('.') : 'root';
    return `  • ${path}: ${issue.message}`;
  });
  return `Invalid config:\n${lines.join('\n')}`;
}

/**
 * Validates a parsed config object. Returns a formatted error string on failure,
 * or null if valid.
 */
export function validateConfig(raw: unknown, filePath: string): string | null {
  const result = ConfigFileSchema.safeParse(raw);
  if (result.success) return null;

  const lines = result.error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : 'root';
    return `  • ${path}: ${issue.message}`;
  });

  return `Invalid config at ${filePath}:\n${lines.join('\n')}`;
}

/**
 * Delete the given paths from a config object, deepest first so that removing a
 * child cannot invalidate the index of a sibling still queued for removal.
 * Array elements are spliced out rather than left as holes. Returns whether
 * anything was actually removed, which is how the caller detects a path it
 * cannot act on (a missing required field, say) and stops looping.
 */
function prunePaths(root: Record<string, unknown>, paths: Array<Array<string | number>>): boolean {
  let removed = false;
  // Measured 2026-09-08 over 211 configs: this ordering, and the pass count in
  // the caller, are EQUIVALENT to their opposites — the retry loop reaches the
  // same result either way, so mutating them changes nothing observable. They
  // are kept because they get there in fewer passes, not because correctness
  // rests on them. Do not add a test that pretends otherwise.
  const ordered = [...paths].sort((x, y) => {
    if (y.length !== x.length) return y.length - x.length;
    const xi = x[x.length - 1];
    const yi = y[y.length - 1];
    return typeof xi === 'number' && typeof yi === 'number' ? yi - xi : 0;
  });
  for (const path of ordered) {
    let cur: unknown = root;
    for (const key of path.slice(0, -1)) {
      if (cur === null || typeof cur !== 'object') {
        cur = undefined;
        break;
      }
      cur = (cur as Record<string | number, unknown>)[key];
    }
    if (cur === null || typeof cur !== 'object') continue;
    const last = path[path.length - 1];
    if (Array.isArray(cur)) {
      const i = Number(last);
      if (Number.isInteger(i) && i >= 0 && i < cur.length) {
        cur.splice(i, 1);
        removed = true;
      }
      continue;
    }
    const obj = cur as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(obj, String(last))) {
      delete obj[String(last)];
      removed = true;
    }
  }
  return removed;
}

/**
 * Like validateConfig, but also returns a sanitized copy of the config with
 * invalid fields removed, so a broken value cannot override a valid one from a
 * higher-priority config layer.
 *
 * What gets removed is the FIELD that failed, not the top-level block it sits
 * in. Dropping the block was fail-open in the direction that matters: `policy`
 * carries egress, DLP, the jail and the smart rules, so one mistyped boolean
 * anywhere under it silently took all of them and left the machine running
 * with far less enforcement than its owner wrote down. Measured before this
 * change: of 202 single-field mutations, 151 erased a whole top-level block,
 * 108 of them `policy`.
 *
 * Removing a field can expose a new issue underneath it, so the prune runs
 * until the config parses or stops making progress, bounded. Anything still
 * failing after that falls back to the old block-level drop, which keeps this
 * strictly better than the previous behaviour and never worse.
 */
export function sanitizeConfig(raw: unknown): {
  sanitized: Record<string, unknown>;
  error: string | null;
} {
  const result = ConfigFileSchema.safeParse(raw);
  if (result.success) {
    return { sanitized: result.data as Record<string, unknown>, error: null };
  }

  // A root that is not an object at all has no fields to save.
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { sanitized: {}, error: formatIssues(result.error.issues) };
  }

  const working = structuredClone(raw) as Record<string, unknown>;
  // Remove the smallest thing that makes the config parse, escalating outward
  // only when the smaller removal cannot work. A REQUIRED field with a wrong
  // value is the case that forces this: deleting the field leaves it missing,
  // which fails again, so the fix has to be to drop the smart rule that
  // contains it — not, as it was, every policy the user wrote.
  for (let level = 0; level < 6; level++) {
    for (let pass = 0; pass < 5; pass++) {
      const attempt = ConfigFileSchema.safeParse(working);
      if (attempt.success) break;
      const paths = attempt.error.issues
        .flatMap((issue) => {
          const at = issue.path as Array<string | number>;
          // An unrecognised key is reported ON THE OBJECT, with the offending
          // names in `keys`, so it has no path of its own to prune. Without
          // this it survived into the merge and the sanitizer's output did not
          // itself validate.
          if (issue.code === 'unrecognized_keys') {
            return (issue as unknown as { keys: string[] }).keys.map((k) => [...at, k]);
          }
          return [at.slice(0, -level || undefined)];
        })
        .filter((path) => path.length > 0);
      // Only root-level complaints left (an unrecognised top-level key), or a
      // path we cannot act on: stop rather than spin.
      if (paths.length === 0 || !prunePaths(working, paths)) break;
    }
    if (ConfigFileSchema.safeParse(working).success) break;
  }

  // Floor: anything the prune could not fix loses its top-level block, exactly
  // as before. This bounds the change to "keeps more, never less".
  //
  // Escalation reaches a path of length 1, which removes the top-level key
  // itself, so no corpus input gets this far and a mutation that disables it
  // survives. It stays as the last line of defence for a schema shape nobody
  // has written yet: the alternative is returning data that does not validate,
  // which is the one thing this function must never do.
  const after = ConfigFileSchema.safeParse(working);
  const sanitized: Record<string, unknown> = {};
  const invalidTopLevelKeys = after.success
    ? new Set<string>()
    : new Set(
        after.error.issues
          .filter((issue) => issue.path.length > 0)
          .map((issue) => String(issue.path[0]))
      );
  for (const [key, value] of Object.entries(working)) {
    if (!invalidTopLevelKeys.has(key)) sanitized[key] = value;
  }

  return {
    sanitized,
    // The message names what the USER should fix, so it is built from the
    // original parse, not from whatever survived the prune.
    error: formatIssues(result.error.issues),
  };
}

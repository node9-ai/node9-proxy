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
        errorMap: () => ({
          message:
            'op must be one of: matches, notMatches, contains, notContains, exists, notExists, matchesGlob, notMatchesGlob',
        }),
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
    errorMap: () => ({ message: 'verdict must be one of: allow, review, block' }),
  }),
  reason: z.string().optional(),
});

// ── Top-level Config ─────────────────────────────────────────────────────────

export const ConfigFileSchema = z
  .object({
    version: z.string().optional(),
    settings: z
      .object({
        mode: z.enum(['standard', 'strict', 'audit']).optional(),
        autoStartDaemon: z.boolean().optional(),
        enableUndo: z.boolean().optional(),
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
      })
      .optional(),
    policy: z
      .object({
        sandboxPaths: z.array(z.string()).optional(),
        dangerousWords: z.array(noNewlines).optional(),
        ignoredTools: z.array(z.string()).optional(),
        toolInspection: z.record(z.string()).optional(),
        smartRules: z.array(SmartRuleSchema).optional(),
        snapshot: z
          .object({
            tools: z.array(z.string()).optional(),
            onlyPaths: z.array(z.string()).optional(),
            ignorePaths: z.array(z.string()).optional(),
          })
          .optional(),
        dlp: z
          .object({
            enabled: z.boolean().optional(),
            scanIgnoredTools: z.boolean().optional(),
          })
          .optional(),
      })
      .optional(),
    environments: z.record(z.object({ requireApproval: z.boolean().optional() })).optional(),
  })
  .strict({ message: 'Config contains unknown top-level keys' });

export type ConfigFileInput = z.input<typeof ConfigFileSchema>;

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
 * Like validateConfig, but also returns a sanitized copy of the config with
 * invalid fields removed. Top-level fields that fail validation are dropped so
 * they cannot override valid values from a higher-priority config layer.
 */
export function sanitizeConfig(raw: unknown): {
  sanitized: Record<string, unknown>;
  error: string | null;
} {
  const result = ConfigFileSchema.safeParse(raw);
  if (result.success) {
    return { sanitized: result.data as Record<string, unknown>, error: null };
  }

  // Build the set of top-level keys that have at least one validation error
  const invalidTopLevelKeys = new Set(
    result.error.issues
      .filter((issue) => issue.path.length > 0)
      .map((issue) => String(issue.path[0]))
  );

  // Keep only the top-level keys that had no errors
  const sanitized: Record<string, unknown> = {};
  if (typeof raw === 'object' && raw !== null) {
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      if (!invalidTopLevelKeys.has(key)) {
        sanitized[key] = value;
      }
    }
  }

  const lines = result.error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : 'root';
    return `  • ${path}: ${issue.message}`;
  });

  return {
    sanitized,
    error: `Invalid config:\n${lines.join('\n')}`,
  };
}

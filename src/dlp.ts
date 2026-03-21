// src/dlp.ts
// Content Scanner — DLP (Data Loss Prevention) engine.
// Scans tool call arguments for known secret patterns before policy evaluation.
// Returns only a redacted match object — the full secret never leaves this module.

export interface DlpMatch {
  patternName: string;
  fieldPath: string;
  redactedSample: string;
  severity: 'block' | 'review';
}

interface DlpPattern {
  name: string;
  regex: RegExp;
  severity: 'block' | 'review';
}

export const DLP_PATTERNS: DlpPattern[] = [
  { name: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/, severity: 'block' },
  { name: 'GitHub Token', regex: /\bgh[pous]_[A-Za-z0-9]{36}\b/, severity: 'block' },
  { name: 'Slack Bot Token', regex: /\bxoxb-[0-9A-Za-z-]+\b/, severity: 'block' },
  { name: 'OpenAI API Key', regex: /\bsk-[a-zA-Z0-9_-]{20,}\b/, severity: 'block' },
  { name: 'Stripe Secret Key', regex: /\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b/, severity: 'block' },
  {
    name: 'Private Key (PEM)',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'block',
  },
  { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/i, severity: 'review' },
];

/**
 * Masks a matched secret: keeps 4-char prefix + 4-char suffix, replaces the
 * middle with asterisks.  e.g. "AKIA1234567890ABCD" → "AKIA**********ABCD"
 */
function maskSecret(raw: string, pattern: RegExp): string {
  const match = raw.match(pattern);
  if (!match) return '****';
  const secret = match[0];
  if (secret.length < 8) return '****';
  const prefix = secret.slice(0, 4);
  const suffix = secret.slice(-4);
  const stars = '*'.repeat(Math.min(secret.length - 8, 12));
  return `${prefix}${stars}${suffix}`;
}

const MAX_DEPTH = 5;
const MAX_STRING_BYTES = 100_000; // don't scan more than 100 KB of a single field
const MAX_JSON_PARSE_BYTES = 10_000; // only attempt JSON parse on small strings

/**
 * Recursively scans an args value for known secret patterns.
 * Handles nested objects, arrays, and JSON-encoded strings.
 * Returns the first match found, or null if clean.
 */
export function scanArgs(args: unknown, depth = 0, fieldPath = 'args'): DlpMatch | null {
  if (depth > MAX_DEPTH || args === null || args === undefined) return null;

  if (Array.isArray(args)) {
    for (let i = 0; i < args.length; i++) {
      const match = scanArgs(args[i], depth + 1, `${fieldPath}[${i}]`);
      if (match) return match;
    }
    return null;
  }

  if (typeof args === 'object') {
    for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
      const match = scanArgs(value, depth + 1, `${fieldPath}.${key}`);
      if (match) return match;
    }
    return null;
  }

  if (typeof args === 'string') {
    const text = args.length > MAX_STRING_BYTES ? args.slice(0, MAX_STRING_BYTES) : args;

    for (const pattern of DLP_PATTERNS) {
      if (pattern.regex.test(text)) {
        return {
          patternName: pattern.name,
          fieldPath,
          redactedSample: maskSecret(text, pattern.regex),
          severity: pattern.severity,
        };
      }
    }

    // Try JSON-in-string: agents sometimes pass stringified JSON objects as a
    // single string field (e.g. tool call content or a bash -c argument).
    if (text.length < MAX_JSON_PARSE_BYTES) {
      const trimmed = text.trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
          const parsed: unknown = JSON.parse(text);
          const inner = scanArgs(parsed, depth + 1, fieldPath);
          if (inner) return inner;
        } catch {
          // not valid JSON — skip
        }
      }
    }
  }

  return null;
}

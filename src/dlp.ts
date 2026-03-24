// src/dlp.ts
// Content Scanner — DLP (Data Loss Prevention) engine.
// Scans tool call arguments for known secret patterns before policy evaluation.
// Returns only a redacted match object — the full secret never leaves this module.

import fs from 'fs';
import path from 'path';

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
  // GCP service account JSON (detects the type field that uniquely identifies it)
  {
    name: 'GCP Service Account',
    regex: /"type"\s*:\s*"service_account"/,
    severity: 'block',
  },
  // NPM auth token in .npmrc format
  {
    name: 'NPM Auth Token',
    regex: /_authToken\s*=\s*[A-Za-z0-9_\-]{20,}/,
    severity: 'block',
  },
  { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/i, severity: 'review' },
];

// ── Sensitive File Path Blocklist ─────────────────────────────────────────────
// Blocks access attempts to credential/key files before their content is read.
const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /[/\\]\.ssh[/\\]/i,
  /[/\\]\.aws[/\\]/i,
  /[/\\]\.config[/\\]gcloud[/\\]/i,
  /[/\\]\.azure[/\\]/i,
  /[/\\]\.kube[/\\]config$/i,
  /[/\\]\.env($|\.)/i, // .env, .env.local, .env.production — not .envoy
  /[/\\]\.git-credentials$/i,
  /[/\\]\.npmrc$/i,
  /[/\\]\.docker[/\\]config\.json$/i,
  /[/\\][^/\\]+\.pem$/i,
  /[/\\][^/\\]+\.key$/i,
  /[/\\][^/\\]+\.p12$/i,
  /[/\\][^/\\]+\.pfx$/i,
  /^\/etc\/passwd$/,
  /^\/etc\/shadow$/,
  /^\/etc\/sudoers$/,
  /[/\\]credentials\.json$/i,
  /[/\\]id_rsa$/i,
  /[/\\]id_ed25519$/i,
  /[/\\]id_ecdsa$/i,
];

/**
 * Checks whether a file path argument targets a sensitive credential file.
 * Resolves symlinks (if the file exists) before checking, to prevent symlink
 * escape attacks where a safe-looking path points to a protected file.
 *
 * Returns a DlpMatch if the path is sensitive, null if clean.
 */
export function scanFilePath(filePath: string, cwd = process.cwd()): DlpMatch | null {
  if (!filePath) return null;

  let resolved: string;
  try {
    const absolute = path.resolve(cwd, filePath);
    // Call native() unconditionally — no existsSync pre-check.
    // Skipping existsSync eliminates the TOCTOU window between the check and
    // the native() call. Missing files throw ENOENT, which is caught below and
    // treated as unresolvable (safe — a non-existent file can't be read).
    resolved = fs.realpathSync.native(absolute);
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      // File doesn't exist yet (e.g. new file being written) — use raw path.
      // A non-existent file can't be a symlink, so no symlink escape is possible.
      resolved = path.resolve(cwd, filePath);
    } else {
      // Any other error (EACCES, unexpected throw, possible TOCTOU remnant) —
      // fail-closed: block rather than risk allowing a sensitive file.
      return {
        patternName: 'Sensitive File Path',
        fieldPath: 'file_path',
        redactedSample: filePath,
        severity: 'block',
      };
    }
  }

  // Normalise to forward slashes for cross-platform pattern matching
  const normalised = resolved.replace(/\\/g, '/');

  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (pattern.test(normalised)) {
      return {
        patternName: 'Sensitive File Path',
        fieldPath: 'file_path',
        redactedSample: filePath, // show original path in alert, not resolved
        severity: 'block',
      };
    }
  }

  return null;
}

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

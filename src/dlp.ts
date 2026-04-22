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
  /** Lowercase keyword substrings — if none found in the string, skip regex entirely. */
  keywords?: string[];
}

// ── Stop Words ────────────────────────────────────────────────────────────────
// If the matched secret contains any of these (case-insensitive), suppress the
// finding — it's a placeholder, template variable, or documentation example.
const DLP_STOPWORDS: string[] = [
  'example',
  'placeholder',
  'changeme',
  'your_key',
  'your_token',
  'your_secret',
  'replace_me',
  'insert_key',
  'put_your',
  'fake',
  'dummy',
  'sample',
  'xxxxxxxx',
  'aaaaaa',
  'bbbbbb',
  '00000000',
  '${',
  '{{',
  '%{',
  '<your',
  'test_key',
  'test_token',
];

export const DLP_PATTERNS: DlpPattern[] = [
  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    name: 'AWS Access Key ID',
    regex: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/,
    severity: 'block',
    keywords: ['akia', 'asia', 'abia', 'acca', 'a3t'],
  },

  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    name: 'GitHub Token',
    regex: /\bgh[pous]_[A-Za-z0-9]{36}\b/,
    severity: 'block',
    keywords: ['ghp_', 'gho_', 'ghu_', 'ghs_'],
  },
  {
    name: 'GitHub Fine-Grained PAT',
    regex: /\bgithub_pat_\w{82}\b/,
    severity: 'block',
    keywords: ['github_pat_'],
  },

  // ── Slack ─────────────────────────────────────────────────────────────────
  {
    name: 'Slack Bot Token',
    // Real tokens are ~50–80 chars; lower bound 20 avoids false negatives on partial tokens
    regex: /\bxoxb-[0-9A-Za-z-]{20,100}\b/,
    severity: 'block',
    keywords: ['xoxb-'],
  },

  // ── Anthropic ─────────────────────────────────────────────────────────────
  // Listed before OpenAI — Anthropic keys start with sk-ant- which would also
  // match the broader OpenAI sk- pattern; more specific rules must come first.
  {
    name: 'Anthropic API Key',
    regex: /\bsk-ant-api03-[a-zA-Z0-9_-]{93}AA\b/,
    severity: 'block',
    keywords: ['sk-ant-api03'],
  },
  {
    name: 'Anthropic Admin Key',
    regex: /\bsk-ant-admin01-[a-zA-Z0-9_-]{93}AA\b/,
    severity: 'block',
    keywords: ['sk-ant-admin01'],
  },

  // ── OpenAI ────────────────────────────────────────────────────────────────
  {
    name: 'OpenAI API Key',
    regex: /\bsk-[a-zA-Z0-9_-]{20,}\b/,
    severity: 'block',
    keywords: ['sk-'],
  },

  // ── Stripe ────────────────────────────────────────────────────────────────
  {
    name: 'Stripe Secret Key',
    regex: /\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b/,
    severity: 'block',
    keywords: ['sk_live_', 'sk_test_'],
  },

  // ── GCP ───────────────────────────────────────────────────────────────────
  {
    name: 'GCP API Key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: 'block',
    keywords: ['aiza'],
  },
  {
    name: 'GCP Service Account',
    regex: /"type"\s*:\s*"service_account"/,
    severity: 'block',
    keywords: ['service_account'],
  },

  // ── Azure ─────────────────────────────────────────────────────────────────
  // Pattern: 3 alphanum chars + digit + Q~ + 31-34 alphanum chars
  {
    name: 'Azure AD Client Secret',
    regex: /(?:^|[\s>=:(,])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\s<),])/,
    severity: 'block',
    keywords: ['q~'],
  },

  // ── Databricks ────────────────────────────────────────────────────────────
  {
    name: 'Databricks API Token',
    regex: /\bdapi[a-f0-9]{32}(?:-\d)?\b/,
    severity: 'block',
    keywords: ['dapi'],
  },

  // ── DigitalOcean ──────────────────────────────────────────────────────────
  {
    name: 'DigitalOcean PAT',
    regex: /\bdop_v1_[a-f0-9]{64}\b/,
    severity: 'block',
    keywords: ['dop_v1_'],
  },
  {
    name: 'DigitalOcean Access Token',
    regex: /\bdoo_v1_[a-f0-9]{64}\b/,
    severity: 'block',
    keywords: ['doo_v1_'],
  },

  // ── Doppler ───────────────────────────────────────────────────────────────
  {
    name: 'Doppler Token',
    regex: /\bdp\.pt\.[a-z0-9]{43}\b/i,
    severity: 'block',
    keywords: ['dp.pt.'],
  },

  // ── HashiCorp Vault ───────────────────────────────────────────────────────
  {
    name: 'HashiCorp Vault Service Token',
    regex: /\bhvs\.[\w-]{90,120}\b/,
    severity: 'block',
    keywords: ['hvs.'],
  },
  {
    name: 'HashiCorp Vault Batch Token',
    regex: /\bhvb\.[\w-]{138,300}\b/,
    severity: 'block',
    keywords: ['hvb.'],
  },

  // ── Hugging Face ──────────────────────────────────────────────────────────
  { name: 'HuggingFace Token', regex: /\bhf_[A-Za-z]{34}\b/, severity: 'block', keywords: ['hf_'] },

  // ── Postman ───────────────────────────────────────────────────────────────
  {
    name: 'Postman API Token',
    regex: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/i,
    severity: 'block',
    keywords: ['pmak-'],
  },

  // ── Pulumi ────────────────────────────────────────────────────────────────
  {
    name: 'Pulumi Access Token',
    regex: /\bpul-[a-f0-9]{40}\b/,
    severity: 'block',
    keywords: ['pul-'],
  },

  // ── SendGrid ──────────────────────────────────────────────────────────────
  {
    name: 'SendGrid API Key',
    regex: /\bSG\.[a-zA-Z0-9=_.-]{66}\b/,
    severity: 'block',
    keywords: ['sg.'],
  },

  // ── Private keys (PEM) ────────────────────────────────────────────────────
  {
    name: 'Private Key (PEM)',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'block',
    keywords: ['-----begin'],
  },

  // ── NPM ───────────────────────────────────────────────────────────────────
  {
    name: 'NPM Auth Token',
    regex: /_authToken\s*=\s*[A-Za-z0-9_-]{20,}/,
    severity: 'block',
    keywords: ['_authtoken'],
  },

  // ── JWT ───────────────────────────────────────────────────────────────────
  // review (not block): JWTs appear legitimately in API calls; flag for human approval
  {
    name: 'JWT',
    regex: /\bey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/_-]{17,}\.[a-zA-Z0-9\/_-]{10,}={0,2}\b/,
    severity: 'review',
    keywords: ['eyj'],
  },

  // ── Stripe (extended — adds restricted key rk_ prefix) ──────────────────
  {
    name: 'Stripe Restricted Key',
    regex: /\brk_(?:live|test|prod)_[0-9a-zA-Z]{10,99}\b/,
    severity: 'block',
    keywords: ['rk_live_', 'rk_test_', 'rk_prod_'],
  },

  // ── Slack (app token) ─────────────────────────────────────────────────────
  {
    name: 'Slack App Token',
    regex: /\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+\b/,
    severity: 'block',
    keywords: ['xapp-'],
  },

  // ── GitLab ────────────────────────────────────────────────────────────────
  { name: 'GitLab PAT', regex: /\bglpat-[\w-]{20}\b/, severity: 'block', keywords: ['glpat-'] },
  {
    name: 'GitLab Deploy Token',
    regex: /\bgldt-[0-9a-zA-Z_-]{20}\b/,
    severity: 'block',
    keywords: ['gldt-'],
  },
  {
    name: 'GitLab CI Job Token',
    regex: /\bglcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}\b/,
    severity: 'block',
    keywords: ['glcbt-'],
  },

  // ── npm (publish token) ───────────────────────────────────────────────────
  {
    name: 'npm Access Token',
    regex: /\bnpm_[a-zA-Z0-9]{36}\b/,
    severity: 'block',
    keywords: ['npm_'],
  },

  // ── Shopify ───────────────────────────────────────────────────────────────
  {
    name: 'Shopify Access Token',
    regex: /\bshpat_[a-fA-F0-9]{32}\b/,
    severity: 'block',
    keywords: ['shpat_'],
  },
  {
    name: 'Shopify Custom Access Token',
    regex: /\bshpca_[a-fA-F0-9]{32}\b/,
    severity: 'block',
    keywords: ['shpca_'],
  },
  {
    name: 'Shopify Private App Token',
    regex: /\bshppa_[a-fA-F0-9]{32}\b/,
    severity: 'block',
    keywords: ['shppa_'],
  },
  {
    name: 'Shopify Shared Secret',
    regex: /\bshpss_[a-fA-F0-9]{32}\b/,
    severity: 'block',
    keywords: ['shpss_'],
  },

  // ── Linear ────────────────────────────────────────────────────────────────
  {
    name: 'Linear API Key',
    regex: /\blin_api_[a-zA-Z0-9]{40}\b/,
    severity: 'block',
    keywords: ['lin_api_'],
  },

  // ── PlanetScale ───────────────────────────────────────────────────────────
  {
    name: 'PlanetScale API Token',
    regex: /\bpscale_tkn_[\w.-]{32,64}\b/,
    severity: 'block',
    keywords: ['pscale_tkn_'],
  },
  {
    name: 'PlanetScale Password',
    regex: /\bpscale_pw_[\w.-]{32,64}\b/,
    severity: 'block',
    keywords: ['pscale_pw_'],
  },

  // ── Sentry ────────────────────────────────────────────────────────────────
  {
    name: 'Sentry User Token',
    regex: /\bsntryu_[a-f0-9]{64}\b/,
    severity: 'block',
    keywords: ['sntryu_'],
  },

  // ── Grafana ───────────────────────────────────────────────────────────────
  {
    name: 'Grafana Service Account Token',
    regex: /\bglsa_[a-zA-Z0-9]{32}_[a-f0-9]{8}\b/,
    severity: 'block',
    keywords: ['glsa_'],
  },

  // ── Heroku ────────────────────────────────────────────────────────────────
  {
    name: 'Heroku API Key',
    regex: /\bHRKU-AA[0-9a-zA-Z_-]{58}\b/,
    severity: 'block',
    keywords: ['hrku-aa'],
  },

  // ── PyPI ──────────────────────────────────────────────────────────────────
  {
    name: 'PyPI Upload Token',
    regex: /\bpypi-[A-Za-z0-9_-]{50,}\b/,
    severity: 'block',
    keywords: ['pypi-'],
  },

  // ── Bearer Token ─────────────────────────────────────────────────────────
  {
    name: 'Bearer Token',
    regex: /Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*/i,
    severity: 'review',
    keywords: ['bearer'],
  },
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
  /^(?:[a-zA-Z]:)?\/etc\/passwd$/,
  /^(?:[a-zA-Z]:)?\/etc\/shadow$/,
  /^(?:[a-zA-Z]:)?\/etc\/sudoers$/,
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
    const textLower = text.toLowerCase();

    for (const pattern of DLP_PATTERNS) {
      // Keyword prefilter: if the pattern declares keywords, at least one must
      // appear in the string before we invoke the regex engine.
      if (
        pattern.keywords &&
        !pattern.keywords.some((kw) => textLower.includes(kw.toLowerCase()))
      ) {
        continue;
      }

      if (pattern.regex.test(text)) {
        // Stopword check: suppress common placeholders / template variables
        const matchedValue = (text.match(pattern.regex)?.[0] ?? '').toLowerCase();
        if (DLP_STOPWORDS.some((sw) => matchedValue.includes(sw))) continue;

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

/** Scan a plain text string (e.g. Claude response prose) for DLP patterns. */
export function scanText(text: string): DlpMatch | null {
  const t = text.length > MAX_STRING_BYTES ? text.slice(0, MAX_STRING_BYTES) : text;
  const tLower = t.toLowerCase();
  for (const pattern of DLP_PATTERNS) {
    if (pattern.keywords && !pattern.keywords.some((kw) => tLower.includes(kw.toLowerCase()))) {
      continue;
    }
    if (pattern.regex.test(t)) {
      const matchedValue = (t.match(pattern.regex)?.[0] ?? '').toLowerCase();
      if (DLP_STOPWORDS.some((sw) => matchedValue.includes(sw))) continue;
      return {
        patternName: pattern.name,
        fieldPath: 'response-text',
        redactedSample: maskSecret(t, pattern.regex),
        severity: pattern.severity,
      };
    }
  }
  return null;
}

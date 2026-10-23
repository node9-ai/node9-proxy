// @node9/policy-engine/dlp — Content Scanner (DLP).
//
// Scans strings, args, and resolved paths for known secret patterns. Pure
// functions only — no fs/path imports. The proxy wraps matchSensitivePath()
// with a symlink-resolving wrapper since that's I/O.
//
// This module returns only a redacted match object — the full secret value
// never leaves the module.

import safeRegex from 'safe-regex2';
import { findMnemonic, type MnemonicBudget } from './mnemonic';
import { secretViews, newSecretViewBudget } from './secret-views';
import { isLegacySystemPath, LEGACY_SYSTEM_PATH_RE } from '../files/paths';
import { validateWif, validateXprv, validateGithubToken, validateCask } from '../scan/checksums';
import type { DlpMatch } from '../types';
export type { DlpMatch } from '../types';

// gap1 v2 — indirect-injection detector for tool output (sibling module).
export {
  scanInjection,
  type InjectionMatch,
  type InjectionContext,
  type InjectionConfidence,
} from './injection';
export {
  stripInvisible,
  foldHomoglyphs,
  normalizeForScan,
  decodeEmbeddedBase64,
  decodeEmbeddedHex,
  scanViews,
  type ScanView,
} from './normalize';

interface DlpPattern {
  name: string;
  regex: RegExp;
  severity: 'block' | 'review';
  /** Lowercase keyword substrings — if none found in the string, skip regex entirely. */
  keywords?: string[];
  /**
   * When true, a 'review' finding is promoted to 'block' if the string is in
   * assignment context (e.g. export TOKEN=..., password: ..., api_key = ...).
   */
  contextBoost?: boolean;
  /**
   * Minimum Shannon entropy (bits/char) the matched token must have.
   * Suppresses obvious placeholders and sequential values (e.g. sk-aaaaaaaaaa…).
   * Only set on broad patterns where the regex alone can't distinguish real secrets.
   */
  minEntropy?: number;
  /**
   * Structural validator run on the matched token (checksum, version byte).
   * When present it DECIDES: a passing validator accepts the match outright,
   * skipping the stopword and entropy heuristics (a checksum-valid token that
   * happens to contain a stopword substring is a real secret, roughly 1 in
   * 3,000 real WIF keys); a failing one rejects it. Must never throw; a throw
   * is treated as "not suppressed" so a validator bug cannot hide a match.
   * `before` is up to 64 characters of the text ahead of the match, for a
   * validator that reads the variable name the value is assigned to.
   */
  validate?: (raw: string, before?: string) => boolean;
  /** When the regex consumes delimiters around the secret, the capture group
   *  that holds the secret itself; redactText replaces only that group. Any
   *  other capture group (a scheme, a prefix) is NOT the secret, so the field
   *  is explicit rather than "group 1 if present". */
  redactGroup?: number;
  /**
   * Only the bounded tool-argument gate (matchArgumentText, reached through
   * inspectArgumentSecrets / scanArgumentSecrets) uses this pattern. The raw
   * scanners skip it: scanArgs (prompts, tool output, history scans, audit
   * attribution), scanText (response text) and redactText (output
   * redaction). For the broad, context-based patterns that name a secret by
   * its variable or query key: a review on a tool call is cheap, a hard block
   * on a prompt or a rewrite of every file an agent reads is not.
   */
  argumentsOnly?: boolean;
}

// Matches variable assignment or config-file patterns that indicate a secret
// is being set rather than just referenced or searched.
// Examples: export API_KEY=..., password: ..., TOKEN = ..., "secret": "..."
const ASSIGNMENT_CONTEXT_RE =
  /\b(?:password|passwd|secret|token|api[_-]?key|auth(?:_key|_token)?|credential|private[_-]?key|access[_-]?key|client[_-]?secret)\s*[=:]\s*/i;

function isAssignmentContext(text: string): boolean {
  return ASSIGNMENT_CONTEXT_RE.test(text);
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
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
  'your',
  'here',
];

// ── Context validators (node9Firewall#348) ────────────────────────────────────
// Shared by the two name-based patterns. A value is "generated-looking" when
// it is not a placeholder, not a reference to a variable or a call, not an
// identifier or a word, and has enough entropy for its length.

/** The value a name-based pattern captured, or null when the regex did not. */
function capturedValue(raw: string, pattern: RegExp): string | null {
  const m = raw.match(pattern);
  return m?.[1] ?? null;
}

/** A reference, not a value: `$VAR`, `@ivar`, `%ENV`, `process.env.X`, `os.environ`, `config.x`. */
const REFERENCE_VALUE_RE =
  /^[$@%]|^(?:process\.env|os\.environ|env|config|settings|self|this|opts?|options|params|cfg)\b/i;
/** Letters, dots, dashes and underscores only: an identifier or a word, not a generated value. */
const IDENTIFIER_VALUE_RE = /^[A-Za-z_.-]+$/;
/** `/home/u/app`, `./src`, `~/dev`, `../x`: a path, not a secret. */
const PATH_VALUE_RE = /^(?:\/|\.{1,2}\/|~\/)/;
/** `jwtConstants.secretKey2024`, `cfg.auth.token`: a property reference. */
const DOTTED_REFERENCE_RE = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;
/** `'+secrets.token_hex(16)`: the right side of a string concatenation, code. */
const CONCATENATION_RE = /^\+[A-Za-z_$][\w$]*\./;
/** An email address next to a password is the login, not the secret. */
const EMAIL_VALUE_RE = /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/;

/** `long-random-phrase`, `my_secret_value_2`: joined words in one case, digits aside. */
function looksLikeJoinedWords(value: string): boolean {
  const segments = value.replace(/[0-9]/g, '').split(/[-_.]/);
  return (
    segments.length >= 2 &&
    segments.every((seg) => /^[a-z]{2,}$/.test(seg) || /^[A-Z]{2,}$/.test(seg))
  );
}

/** `0123456789abcdef`, `ABCDEFGHIJKLMNOP`: eight or more consecutive code points in a row. */
function hasSequentialRun(value: string): boolean {
  let run = 1;
  for (let i = 1; i < value.length; i++) {
    run = value.charCodeAt(i) === value.charCodeAt(i - 1) + 1 ? run + 1 : 1;
    if (run >= 8) return true;
  }
  return false;
}

/**
 * A value in a vendor shape whose checksum fails (a `ghp_` token with the
 * wrong CRC, a WIF key with a bad hash) is a look-alike node9 allows on
 * purpose; the context patterns must not reverse that decision.
 */
function rejectedByStructuredValidator(value: string): boolean {
  for (const p of DLP_PATTERNS) {
    if (!p.validate || p.argumentsOnly) continue;
    const m = value.match(p.regex);
    if (m && !p.validate(m[0])) return true;
  }
  return false;
}

function looksGenerated(
  value: string,
  minLength: number,
  minEntropy: number,
  lettersOnlyAllowed = false
): boolean {
  if (value.length < minLength) return false;
  const lower = value.toLowerCase();
  if (DLP_STOPWORDS.some((sw) => lower.includes(sw))) return false;
  if (REFERENCE_VALUE_RE.test(value)) return false;
  if (!lettersOnlyAllowed && IDENTIFIER_VALUE_RE.test(value)) return false;
  if (EMAIL_VALUE_RE.test(value)) return false;
  if (looksLikeJoinedWords(value) || hasSequentialRun(value)) return false;
  if (PATH_VALUE_RE.test(value) || DOTTED_REFERENCE_RE.test(value)) return false;
  if (CONCATENATION_RE.test(value)) return false;
  if (rejectedByStructuredValidator(value)) return false;
  return shannonEntropy(value) >= minEntropy;
}

/**
 * The variable or key the value is assigned to. A name that says fixture
 * (`FAKE_TOKEN`, `mockSecret`) or that names a derivative (`token_hash`,
 * `password_length`, `secret_id`) is not holding a credential.
 */
// `PUBLIC_KEY`, `publicToken`: a name that says public holds no credential (fw#372 B4).
const FIXTURE_NAME_RE = /(?:fake|dummy|example|sample|mock|stub|placeholder|test)|^public/i;
const DERIVATIVE_NAME_RE =
  /(?:hash|digest|fingerprint|thumbprint|checksum|id|type|name|url|uri|path|file|len|length|count|size|ttl|expires?|expiry|age|date|time|format|field|header|param)$/i;

function nameHoldsCredential(name: string): boolean {
  return !FIXTURE_NAME_RE.test(name) && !DERIVATIVE_NAME_RE.test(name);
}

const QUERY_CREDENTIAL_VALUE_RE = /=([A-Za-z0-9%+/_.~-]{8,512}={0,2})$/;
const OTP_SECRET_RE = /^[A-Z2-7]{16,}=*$/i;

/**
 * The OTP secrets that tutorials and library READMEs print (pyotp, otplib,
 * speakeasy and Google's own documentation use the first; the second is the
 * base32 of "1234567890"). An agent writing such a README is not leaking a
 * secret, in either the otpauth URI or the constructor form.
 */
const OTP_DOC_SECRETS = new Set(['JBSWY3DPEHPK3PXP', 'GEZDGNBVGY3TQOJQ']);

function isOtpDocSecret(value: string): boolean {
  return OTP_DOC_SECRETS.has(value.replace(/=+$/, '').toUpperCase());
}

function validateQueryCredential(raw: string): boolean {
  const value = capturedValue(raw, QUERY_CREDENTIAL_VALUE_RE);
  if (value === null) return false;
  // An otpauth secret is base32: letters and digits 2-7, often letters only.
  if (OTP_SECRET_RE.test(value))
    return !isOtpDocSecret(value) && looksGenerated(value, 16, 3.0, true);
  // Anything else must mix letters and digits and be at least 12 long, so a
  // fixture such as `?token=qtoken789` or a slug is not a finding.
  if (!/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) return false;
  return looksGenerated(value, 12, 3.0);
}

const ASSIGNED_SECRET_VALUE_RE =
  /(?::=|=>|[:=])[ \t]{0,8}\\?["'`]?((?:[A-Za-z0-9+/_.!@#$%^*~|-]|\\\/){12,512}={0,2})$/;

const ASSIGNED_SECRET_NAME_RE = /^([A-Za-z0-9_]+)/;

// `pass` comes after the longer words that start with it, so `password` is
// read as `password`. In the pattern itself `pass` must start a word or follow
// an underscore and end the name part (`\bpass(?![A-Za-z0-9])`,
// `_pass(?![A-Za-z0-9])`): a bare `pass` matched inside `PASSPORT_`, `bypass_`
// or `COMPASS_`, and the rejected match hid the real keyword after it
// (`PASSPORT_CLIENT_SECRET`), because a rejected match resumes after itself. The names added after node9Firewall#348 (consumer and
// app keys, signing, encryption and master keys, a WeChat `jsapi_ticket`, a
// `*_PASS` variable) are the shapes CredData's public split showed the gate
// missing.
const NAME_KEYWORD_RE =
  /^(?:password|passphrase|passwd|pwd|secret|token|api[_-]?key|auth[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|consumer[_-]?key|app[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|aes[_-]?key|cipher[_-]?key|subscription[_-]?key|jsapi[_-]?ticket|pass)/i;

/**
 * The keyword must end the name or be followed by a new part of it: `_`,
 * `-`, a digit, or an uppercase letter after a lowercase keyword
 * (`secretKey`). `tokenizer`, `passwords`, `TOKENIZER` are other words.
 */
function keywordEndsAPart(name: string): boolean {
  const keyword = name.match(NAME_KEYWORD_RE)?.[0];
  if (!keyword) return false;
  const next = name.charAt(keyword.length);
  if (next === '' || /[_\-0-9]/.test(next)) return true;
  const lastIsLower = /[a-z]/.test(keyword.charAt(keyword.length - 1));
  return lastIsLower && /[A-Z]/.test(next);
}

/** `arn:aws:secretsmanager:...:secret:prod/x`: an ARN segment, not an assignment. */
const ARN_CONTEXT_RE = /\barn:[A-Za-z0-9-]*:[^\s"'`]*$/i;

function validateAssignedSecret(raw: string, before = ''): boolean {
  const value = capturedValue(raw, ASSIGNED_SECRET_VALUE_RE);
  // `_pass` matches from its underscore (`JENKINS_PASS`): the name is what follows it.
  const name = capturedValue(raw, ASSIGNED_SECRET_NAME_RE)?.replace(/^_+/, '') ?? null;
  if (value === null || name === null) return false;
  if (!keywordEndsAPart(name)) return false;
  if (ARN_CONTEXT_RE.test(before)) return false;
  // The match starts at the keyword; the rest of the name (`FAKE_` in
  // `FAKE_TOKEN`, `mock` in `mockSecret`) is in the text just before it.
  const prefix = (before.match(/[A-Za-z0-9_]*$/)?.[0] ?? '') + (raw.startsWith('_') ? '_' : '');
  if (!nameHoldsCredential(prefix + name)) return false;
  // A value that mixes letters and digits is already unlike a word; 3.0 bits
  // per character is the floor the URL-query rule uses for the same reason.
  // Letters alone keep the 3.5 floor (fw#372 B4).
  if (isOtpDocSecret(value)) return false;
  const mixed = /[0-9]/.test(value) && /[A-Za-z]/.test(value);
  return looksGenerated(value, 12, mixed ? 3.0 : 3.5);
}

const CIPHER_KEY_NAME_RE = /^([A-Za-z_][\w.]{0,40})/;
const CIPHER_KEY_VALUE_RE = /([A-Za-z0-9+/]{22}==)$/;

/**
 * `cipherKey = "kPH+bIxk5D2deZiIxcaaaA=="`: a base64 literal that decodes to
 * exactly 16 bytes, assigned under a name ending in `key`. That is an AES-128
 * key written into code (the Shiro rememberMe class of leaks). The name must
 * not say public, and the literal must mix cases and carry a digit, as a
 * random key does (fw#372 B4).
 */
function validateCipherKeyLiteral(raw: string): boolean {
  const name = capturedValue(raw, CIPHER_KEY_NAME_RE);
  const value = capturedValue(raw, CIPHER_KEY_VALUE_RE);
  if (name === null || value === null) return false;
  if (/pub/i.test(name) || !nameHoldsCredential(name)) return false;
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 16 && bytes.toString('base64') === value;
}

const LARAVEL_KEY_VALUE_RE = /base64:([A-Za-z0-9+/]{43}=)$/;

/** Laravel `APP_KEY=base64:<32 bytes>`: the application key, whose leak is remote code execution. */
function validateLaravelAppKey(raw: string): boolean {
  const value = capturedValue(raw, LARAVEL_KEY_VALUE_RE);
  if (value === null) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 32 && bytes.toString('base64') === value && shannonEntropy(value) >= 3.0;
}

const SQL_PASSWORD_VALUE_RE = /['"]([^'"\s]{8,128})['"]$/;

/** `IDENTIFIED BY 'x'`, `WITH PASSWORD 'x'`: the password of a database account, unless a placeholder. */
function validateSqlPassword(raw: string): boolean {
  const value = capturedValue(raw, SQL_PASSWORD_VALUE_RE);
  if (value === null) return false;
  const lower = value.toLowerCase();
  if (DLP_STOPWORDS.some((sw) => lower.includes(sw)) || REFERENCE_VALUE_RE.test(value))
    return false;
  if (/^[a-z]+$/i.test(value) && value.length < 12) return false; // a word
  return shannonEntropy(value) >= 2.5 && !hasSequentialRun(value);
}

const GRAFANA_KEY_VALUE_RE = /(eyJrIjoi[A-Za-z0-9+/]{20,}={0,2})$/;

/** A Grafana API key: base64 of `{"k":"...","n":"...","id":N}`. */
function validateGrafanaApiKey(raw: string): boolean {
  const value = capturedValue(raw, GRAFANA_KEY_VALUE_RE);
  if (value === null) return false;
  const text = Buffer.from(value, 'base64').toString('utf8');
  return /^\{"k":"[A-Za-z0-9]{16,}"/.test(text);
}

const BASIC_VALUE_RE = /([A-Za-z0-9+/]{8,512}={0,2})$/;
const BASIC_PAIR_RE = /^([^:\s]{1,128}):(\S{8,256})$/;

/** `Basic <b64>`: a canonical base64 of UTF-8 `user:password`, the password generated. */
function validateBasicCredential(raw: string): boolean {
  const b64 = capturedValue(raw, BASIC_VALUE_RE);
  if (b64 === null) return false;
  const bare = b64.replace(/=+$/, '');
  if (bare.length % 4 === 1) return false;
  const bytes = Buffer.from(b64, 'base64');
  // A word that only looks like base64 does not survive the round trip.
  if (bytes.toString('base64').replace(/=+$/, '') !== bare) return false;
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) return false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false; // a control character: binary, not a credential
  }
  const pair = BASIC_PAIR_RE.exec(text);
  if (!pair) return false;
  const password = pair[2];
  if (!/[0-9]/.test(password) || !/[A-Za-z]/.test(password)) return false;
  // Not looksGenerated: its joined-words rule strips digits first, so a
  // random token with dashes ("x7k2…-44v9…-7kvu…") reads as words. A password
  // already mixes letters and digits here; it must not be a placeholder, a
  // sequential run or low in entropy.
  const lower = password.toLowerCase();
  if (DLP_STOPWORDS.some((sw) => lower.includes(sw)) || hasSequentialRun(password)) return false;
  return shannonEntropy(password) >= 3.0;
}

const OTP_CAPTURE_RE = /["']([A-Z2-7]{16,128}=*)["']$/i;

const DB_URL_PASSWORD_RE = /:\/\/[^:/\s@]*:([^@\s]{4,})@/;

/**
 * A connection string is a placeholder when its PASSWORD is one, not when its
 * host is: `postgres://app:<real>@db.example-corp.internal` was suppressed by
 * the stopword `example` in the host (fw#372 A6). The entropy floor stays on
 * the whole match, as it was.
 */
function validateDbConnectionString(raw: string): boolean {
  const password = capturedValue(raw, DB_URL_PASSWORD_RE);
  if (password === null) return false;
  const lower = password.toLowerCase();
  if (DLP_STOPWORDS.some((sw) => lower.includes(sw))) return false;
  return shannonEntropy(raw) >= 3.0;
}

/** A base32 constructor secret: not a documentation secret, not a run, generated. */
function validateOtpSecret(raw: string): boolean {
  const secret = capturedValue(raw, OTP_CAPTURE_RE);
  if (secret === null || isOtpDocSecret(secret)) return false;
  return looksGenerated(secret.replace(/=+$/, ''), 16, 3.0, true);
}

export const DLP_PATTERNS: DlpPattern[] = [
  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    name: 'AWS Access Key ID',
    regex: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/,
    severity: 'block',
    keywords: ['akia', 'asia', 'abia', 'acca', 'a3t'],
  },

  // ── GitHub ────────────────────────────────────────────────────────────────
  // Classic tokens end in a CRC32 checksum (scan/checksums.ts). The validator
  // DECIDES: a matching checksum is a token GitHub issued (block); a mismatch
  // is a lookalike — a fixture, a hash, sample text — and is left alone. It
  // replaces the entropy floor, which the checksum makes redundant.
  {
    name: 'GitHub Token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36}\b/,
    severity: 'block',
    keywords: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'],
    validate: validateGithubToken,
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
    minEntropy: 3.5,
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
    minEntropy: 3.0,
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
    redactGroup: 1,
  },

  // ── Microsoft CASK (Common Annotated Security Key) ────────────────────────
  // Fixed layout, no checksum (scan/checksums.ts, validateCask). The key
  // alphabet includes '-', so a `\b` anchor misses a key that starts or ends
  // with one: the regex consumes one LEADING delimiter (lookbehind fails
  // safe-regex2) and only LOOKS AHEAD at the trailing one, so two keys
  // separated by a single space are both matched. The key is capture group 1,
  // the only part redactText replaces. The 5..45 run covers the provider kind + signature
  // and 0..10 optional 4-character data segments; the validator pins the exact
  // lengths and the timestamp ranges.
  {
    name: 'Microsoft CASK Secret',
    regex:
      /(?:^|[^A-Za-z0-9_-])((?:[A-Za-z0-9_-]{44}|[A-Za-z0-9_-]{88})QJJQA[BC][A-K][A-Za-z0-9_-]{5,45}AA[A-Za-z0-9_-]{6})(?=$|[^A-Za-z0-9_-])/,
    severity: 'block',
    keywords: ['qjjq'],
    validate: validateCask,
    redactGroup: 1,
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
  {
    name: 'HuggingFace Token',
    regex: /\bhf_[A-Za-z]{34}\b/,
    severity: 'block',
    keywords: ['hf_'],
    minEntropy: 3.0,
  },

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

  // ── Cryptocurrency private keys (base58check-validated) ───────────────────
  // Both are anchored with \b on each side: unanchored, `[KL][base58]{51}`
  // matches INSIDE any longer base58 blob (an xprv, a Solana keypair, a
  // Monero address). Lookbehind fails safe-regex2; \b is the house style
  // (see the card regexes). Mainnet only, matching validateWif / validateXprv;
  // testnet (WIF 0xEF, tprv) is deferred. Cost was measured: the WIF regex
  // runs on every string (first keyword-less pattern) at 0.024 ms per 100 KB
  // of prose, so no prefilter is warranted.
  {
    name: 'Bitcoin WIF Private Key',
    regex: /\b(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})\b/,
    severity: 'block',
    validate: validateWif,
  },
  {
    name: 'Extended Private Key',
    regex: /\b[xyz]prv[1-9A-HJ-NP-Za-km-z]{107}\b/,
    severity: 'block',
    keywords: ['xprv', 'yprv', 'zprv'],
    validate: validateXprv,
  },
  // ── Private keys (PEM) ────────────────────────────────────────────────────
  {
    name: 'Private Key (PEM)',
    // DSA and ENCRYPTED headers, and a PGP private key block (node9Firewall#385).
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/,
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
  // contextBoost: promoted to block when assigned (e.g. TOKEN=eyJ...)
  {
    name: 'JWT',
    regex: /\bey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/_-]{17,}\.[a-zA-Z0-9\/_-]{10,}={0,2}\b/,
    severity: 'review',
    keywords: ['eyj'],
    contextBoost: true,
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
    minEntropy: 3.0,
  },

  // ── Bearer Token ─────────────────────────────────────────────────────────
  // contextBoost: promoted to block when assigned (e.g. AUTH_TOKEN=Bearer eyJ...)
  {
    name: 'Bearer Token',
    regex: /Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*/i,
    severity: 'review',
    keywords: ['bearer'],
    contextBoost: true,
    minEntropy: 3.0,
  },

  // ── HTTP Basic credential ─────────────────────────────────────────────────
  // `Authorization: Basic <base64 of user:password>`, or the bare scheme in a
  // config list. The validator decodes the value and accepts only a
  // `user:password` whose password looks generated (letters and digits, 8+
  // characters, the query-credential rule), so prose ("Basic authentication")
  // and documentation pairs (`admin:changeme`, `user:pass1234`) stay allowed.
  // review: the same weight as a bare Bearer token.
  {
    name: 'HTTP Basic Credential',
    regex: /\bBasic[ \t]{1,8}([A-Za-z0-9+/]{8,512}={0,2})/i,
    severity: 'review',
    keywords: ['basic'],
    validate: validateBasicCredential,
    redactGroup: 1,
    argumentsOnly: true,
  },

  // ── Resend ────────────────────────────────────────────────────────────────
  {
    name: 'Resend API Key',
    regex: /\bre_[a-zA-Z0-9]{24}\b/,
    severity: 'block',
    keywords: ['re_'],
  },

  // ── Telegram ──────────────────────────────────────────────────────────────
  {
    name: 'Telegram Bot Token',
    regex: /\b[0-9]{7,10}:AA[a-zA-Z0-9_-]{33}\b/,
    severity: 'block',
    keywords: [':aa'],
  },

  // ── Mapbox ────────────────────────────────────────────────────────────────
  {
    name: 'Mapbox Access Token',
    regex: /\bpk\.eyJ1[a-zA-Z0-9._-]{20,}\b/,
    severity: 'block',
    keywords: ['pk.eyj1'],
    minEntropy: 3.0,
  },

  // ── Notion ────────────────────────────────────────────────────────────────
  {
    name: 'Notion Integration Token',
    regex: /\bsecret_[a-zA-Z0-9]{43}\b/,
    severity: 'block',
    keywords: ['secret_'],
  },

  // ── Square ────────────────────────────────────────────────────────────────
  {
    name: 'Square Access Token',
    regex: /\bsq0atp-[0-9A-Za-z_-]{22}\b/,
    severity: 'block',
    keywords: ['sq0atp-'],
  },
  {
    name: 'Square OAuth Secret',
    regex: /\bsq0csp-[0-9A-Za-z_-]{43}\b/,
    severity: 'block',
    keywords: ['sq0csp-'],
  },

  // ── Typeform ──────────────────────────────────────────────────────────────
  {
    name: 'Typeform Token',
    regex: /\btfp_[a-zA-Z0-9_]{59}\b/,
    severity: 'block',
    keywords: ['tfp_'],
  },

  // ── Cloudinary ────────────────────────────────────────────────────────────
  {
    name: 'Cloudinary URL',
    regex: /\bcloudinary:\/\/[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+/,
    severity: 'block',
    keywords: ['cloudinary://'],
  },

  // ── Airtable ──────────────────────────────────────────────────────────────
  // New PAT format: pat + 14 alphanum + . + 64 alphanum
  {
    name: 'Airtable PAT',
    regex: /\bpat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}\b/,
    severity: 'block',
    keywords: ['pat'],
  },

  // ── RubyGems ──────────────────────────────────────────────────────────────
  {
    name: 'RubyGems API Key',
    regex: /\brubygems_[a-f0-9]{48}\b/,
    severity: 'block',
    keywords: ['rubygems_'],
  },

  // ── Shippo ────────────────────────────────────────────────────────────────
  {
    name: 'Shippo Token',
    regex: /\bshippo_(?:live|test)_[a-f0-9]{40}\b/,
    severity: 'block',
    keywords: ['shippo_'],
  },

  // ── Plaid ─────────────────────────────────────────────────────────────────
  {
    name: 'Plaid Access Token',
    regex:
      /\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/,
    severity: 'block',
    keywords: ['access-sandbox', 'access-development', 'access-production'],
  },

  // ── Age ───────────────────────────────────────────────────────────────────
  {
    name: 'Age Identity Key',
    regex: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JNLH]{58}\b/,
    severity: 'block',
    keywords: ['age-secret-key-'],
  },

  // ── Database connection strings ───────────────────────────────────────────
  // Universal <scheme>://[user]:<password>@<host> shape. Covers the gap
  // vendor-prefix patterns (AWS / GitHub / Stripe / …) leave open. Matches
  // the whole URL so maskSecret produces `<scheme>...:****@...<host>` —
  // the password value never appears in the redacted sample.
  //
  // Schemes covered: redis, rediss (TLS), postgres, postgresql,
  // mongodb, mongodb+srv, mysql, mariadb, amqp, amqps, kafka,
  // clickhouse, cassandra. HTTP(S) / FTP / SSH are intentionally
  // excluded — they're not database URLs and adding them would
  // create false positives on every basic-auth URL in the wild.
  //
  // Requires `:password@` (4+ char password) so user-only URLs like
  // `redis://user@host` don't match. Stopwords ('your', '${', '<your',
  // 'placeholder', 'changeme', etc.) keep doc/README scans clean.
  {
    name: 'Database Connection String',
    // `[a-z0-9+]*` after the base name accepts the TLS spelling (`rediss`,
    // `amqps`), `postgresql`, and a driver suffix (`mongodb+srv`,
    // `mysql+pymysql`, `postgresql+psycopg2`) in one star-height-1 shape.
    regex:
      /\b((?:redis|postgres|mongodb|mysql|mariadb|amqp|kafka|clickhouse|cassandra)[a-z0-9+]*):\/\/[^:/\s@]*:[^@\s]{4,}@[^\s/]+/i,
    severity: 'block',
    keywords: [
      'redis',
      'postgres',
      'mongodb',
      'mysql',
      'mariadb',
      'amqp',
      'kafka://',
      'clickhouse',
      'cassandra',
    ],
    validate: validateDbConnectionString,
  },

  // ── Credential in a URL query value ───────────────────────────────────────
  // A query parameter whose key names a secret (`?secret=`, `&apiKey=`,
  // `&sig=`, the `secret` of an `otpauth://` URI). The value itself has no
  // vendor shape, so the validator decides: a placeholder, a word, a bare
  // identifier or a short value is left alone. review, not block: a
  // fixture token in a test URL is common (node9Firewall#348, item 1).
  {
    name: 'Credential in URL Query',
    regex:
      /(?:^|[?&;])(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|auth[_-]?token|private[_-]?key|secret|token|apikey|password|passwd|pwd|auth|sig|signature)=([A-Za-z0-9%+/_.~-]{8,512}={0,2})/i,
    severity: 'review',
    keywords: ['secret', 'token', 'key', 'password', 'passwd', 'pwd', 'auth', 'sig'],
    validate: validateQueryCredential,
    argumentsOnly: true,
  },

  // ── OTP secret in a constructor ───────────────────────────────────────────
  // `ROTP::TOTP.new('<base32>')`, `pyotp.TOTP("<base32>")`, `new HOTP('...')`:
  // the shared secret of a one-time-password generator written as a literal.
  // The otpauth URI form is `Credential in URL Query`. review.
  {
    name: 'OTP Secret',
    regex:
      /\b(?:TOTP|HOTP|OTP)(?:\.new|\.create)?[ \t]{0,8}\(?[ \t]{0,8}["']([A-Z2-7]{16,128}=*)["']/i,
    severity: 'review',
    keywords: ['otp'],
    validate: validateOtpSecret,
    redactGroup: 1,
    argumentsOnly: true,
  },

  // ── Shapes from the CredData review (fw#372 B4, node9Firewall#385) ────────
  // All review and argumentsOnly, like Assigned Secret: the live gate asks,
  // the raw scanners stay as they were.
  {
    name: 'Cipher Key Literal',
    regex:
      /\b([A-Za-z_][\w.]{0,40}key)[ \t]{0,8}(?::=|=>|[:=])[ \t]{0,8}\\?["'`]?([A-Za-z0-9+/]{22}==)/i,
    severity: 'review',
    keywords: ['key'],
    validate: validateCipherKeyLiteral,
    redactGroup: 2,
    argumentsOnly: true,
  },
  {
    name: 'Laravel App Key',
    regex: /\bAPP_KEY[ \t]{0,8}=[ \t]{0,8}["']?(base64:[A-Za-z0-9+/]{43}=)/,
    severity: 'review',
    keywords: ['app_key'],
    validate: validateLaravelAppKey,
    redactGroup: 1,
    argumentsOnly: true,
  },
  {
    // `key-` plus 32 hex characters, Mailgun's legacy private key shape.
    name: 'Mailgun API Key',
    regex: /\bkey-[0-9a-f]{32}\b/,
    severity: 'review',
    keywords: ['key-'],
    argumentsOnly: true,
  },
  {
    // A kubeadm bootstrap token, named as one by its flag or key.
    name: 'Kubeadm Bootstrap Token',
    regex: /(?:--token[= ]|\btoken:[ \t]{0,8}|--discovery-token[= ])([a-z0-9]{6}\.[a-z0-9]{16})\b/,
    severity: 'review',
    keywords: ['token'],
    redactGroup: 1,
    argumentsOnly: true,
  },
  {
    // `CREATE USER ... IDENTIFIED BY 'x'` (MySQL, Oracle), `WITH PASSWORD 'x'` (Postgres).
    name: 'SQL Account Password',
    regex: /\b(?:IDENTIFIED\s+BY|WITH\s+PASSWORD)\s*['"]([^'"\s]{8,128})['"]/i,
    severity: 'review',
    keywords: ['identified by', 'with password'],
    validate: validateSqlPassword,
    redactGroup: 1,
    argumentsOnly: true,
  },
  {
    // The provisioned (legacy) Grafana API key: base64 of a JSON object with k, n and id.
    name: 'Grafana API Key',
    regex: /\b(eyJrIjoi[A-Za-z0-9+/]{20,}={0,2})/,
    severity: 'block',
    keywords: ['eyjrijoi'],
    validate: validateGrafanaApiKey,
    redactGroup: 1,
  },
  // ── Secret assigned to a telling name ─────────────────────────────────────
  // `password: ...`, `JWT_SECRET=...`, `api_key = "..."`. The name alone is
  // not a finding: most such lines hold a reference (`process.env.X`), a
  // placeholder or a word. The validator accepts only a value that looks
  // generated: 12+ characters, not an identifier, Shannon entropy of 3.5
  // bits per character or more. review, never block (node9Firewall#348,
  // item 4). Tuned on CredData's public split; its look-alike lines are the
  // negative control. A quote may be escaped (`\"access_token\":\"...\"`):
  // JSON written inside a string literal. The two optional quotes after the
  // name are written out, not as a counted group, to keep star height 1.
  {
    name: 'Assigned Secret',
    // fw#372 B4: `aes_key`, `cipher_key`, `subscription_key` join the names; a
    // backtick may close the name; `|` and `\` may occur in the value
    // (`\/` is how JSON escapes a slash).
    regex:
      /(?:password|passphrase|passwd|pwd|secret|token|api[_-]?key|auth[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|consumer[_-]?key|app[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|aes[_-]?key|cipher[_-]?key|subscription[_-]?key|jsapi[_-]?ticket|\bpass(?![A-Za-z0-9])|_pass(?![A-Za-z0-9]))[A-Za-z0-9_]{0,40}\\?["'\]`]?\\?["'\]`]?[ \t]{0,8}(?::=|=>|[:=])[ \t]{0,8}\\?["'`]?((?:[A-Za-z0-9+/_.!@#$%^*~|-]|\\\/){12,512}={0,2})/i,
    severity: 'review',
    keywords: ['pass', 'pwd', 'secret', 'token', 'key', 'ticket'],
    validate: validateAssignedSecret,
    argumentsOnly: true,
  },
];

// Pre-compiled global versions of each DLP pattern regex, built once at module
// load time from the static DLP_PATTERNS list. Used by redactText to avoid
// constructing RegExp objects at call time (which would be a footgun if
// DLP_PATTERNS ever became configurable).
const DLP_PATTERNS_GLOBAL: Array<{ pattern: DlpPattern; globalRegex: RegExp }> = DLP_PATTERNS.map(
  (p) => ({
    pattern: p,
    globalRegex: new RegExp(
      p.regex.source,
      p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g'
    ),
  })
);

// ── Sensitive File Path Blocklist ─────────────────────────────────────────────
// Blocks access attempts to credential/key files before their content is read.
const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /[/\\]\.ssh([/\\]|$)/i,
  /[/\\]\.aws([/\\]|$)/i,
  /[/\\]\.config[/\\]gcloud[/\\]/i,
  /[/\\]\.azure[/\\]/i,
  /[/\\]\.kube[/\\]config$/i,
  // ⚠️ ONE SEMANTIC, FOUR COPIES. This is the AST tier's `.env` rule verbatim
  // (shell/index.ts SENSITIVE_PATH_RULES), whose reasoning is documented there:
  // structural suffix chain rather than a hand-written list, `example|sample|
  // template` exempt because a fixture stays a fixture whatever follows, and
  // `.test` anchored because `test` names an ENVIRONMENT -- `.env.test` is the
  // committed template, `.env.test.local` is gitignored and holds real values.
  //
  // It was previously `[/\\]\.env($|\.)` with NO exemptions, so `Read .env.example`
  // blocked while `cat .env.example` allowed: the same file, opposite verdicts,
  // decided only by which tool asked. See src/__tests__/jail-both-doors.test.ts,
  // which is the contract that now holds these copies in step, and stage 5 of
  // doc/credential-jail-architecture.md, which replaces them with one generated
  // source.
  // ⚠️ The `.local` branch comes FIRST and takes no exemption. A fixture stays a
  // fixture whatever follows it -- `.env.example.md` is documentation -- but
  // `.env.example.local` is gitignored by the `.env*.local` convention and holds
  // real values, exactly the reasoning that anchors `(?!\.test$)` rather than
  // using `\b`. Without this branch the fixture exemption also bought a two-step
  // bypass: `cp .env .env.sample`, then read the copy.
  /[/\\]\.env(?![\w-])(?:[\w.-]*\.local$|(?!\.(?:example|sample|template)\b)(?!\.test$)[\w.-]*$)/i, // .env + any suffix chain; fixtures exempt unless .local
  /[/\\]\.git-credentials$/i,
  /[/\\]\.npmrc$/i,
  /[/\\]\.docker[/\\]config\.json$/i,
  /[/\\][^/\\]+\.pem$/i,
  /[/\\][^/\\]+\.key$/i,
  /[/\\][^/\\]+\.p12$/i,
  /[/\\][^/\\]+\.pfx$/i,
  /[/\\]credentials\.json$/i,
  /[/\\]id_rsa$/i,
  /[/\\]id_ed25519$/i,
  /[/\\]id_ecdsa$/i,
];

/**
 * Pure: tests an already-resolved absolute path against the sensitive-file
 * blocklist. Symlink resolution is the host's job — it's I/O and lives in
 * the proxy's scanFilePath wrapper.
 *
 * @param resolvedPath  Absolute path, ideally with symlinks resolved by the host.
 * @param originalPath  The path as the user/agent wrote it. Used in the
 *                      redactedSample so alerts show the original spelling.
 * @returns A DlpMatch with severity 'block' if the path is sensitive, else null.
 */
export function matchSensitivePath(
  resolvedPath: string,
  originalPath: string,
  options: { systemAccessHandled?: boolean } = {}
): DlpMatch | null {
  // Normalise to forward slashes for cross-platform pattern matching.
  const normalised = resolvedPath.replace(/\\/g, '/');
  if (!options.systemAccessHandled && isLegacySystemPath(normalised))
    return sensitivePathMatch(originalPath);

  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (pattern.test(normalised)) {
      return {
        patternName: 'Sensitive File Path',
        fieldPath: 'file_path',
        redactedSample: originalPath,
        severity: 'block',
      };
    }
  }

  return null;
}

/** Exposed so the proxy's I/O wrapper can build the same fail-closed match. */
export function sensitivePathMatch(originalPath: string): DlpMatch {
  return {
    patternName: 'Sensitive File Path',
    fieldPath: 'file_path',
    redactedSample: originalPath,
    severity: 'block',
  };
}

/** Exposed so the proxy can apply the same patterns directly if needed. */
export const SENSITIVE_PATH_REGEXES: readonly RegExp[] = [
  ...SENSITIVE_PATH_PATTERNS,
  LEGACY_SYSTEM_PATH_RE,
];

// ── Builtin pattern safety check (runs at module load) ────────────────────
// Every regex shipped in this package is run against scanArgs / scanText on
// every tool call, so a single ReDoS-vulnerable pattern would let an
// attacker hang the proxy with a crafted argument. We already require this
// of *user*-supplied regexes via getCompiledRegex; this guard extends the
// same standard to our own builtins. Throws at import time if any pattern
// fails — fail-loud in dev/CI rather than fail-silently at runtime.
function assertBuiltinPatternsAreSafe(): void {
  for (const p of DLP_PATTERNS) {
    if (!safeRegex(p.regex.source)) {
      throw new Error(
        `[node9 engine] Builtin DLP pattern '${p.name}' is vulnerable to ReDoS: ${p.regex.source}`
      );
    }
  }
  for (const re of SENSITIVE_PATH_PATTERNS) {
    if (!safeRegex(re.source)) {
      throw new Error(
        `[node9 engine] Builtin sensitive-path pattern is vulnerable to ReDoS: ${re.source}`
      );
    }
  }
}
assertBuiltinPatternsAreSafe();

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
 * The bounds scanArgs works within, published so callers can tell "scanned
 * clean" apart from "never looked". A caller that must FAIL CLOSED on an
 * unscanned value (e.g. the audit writer, which would otherwise persist an
 * unexamined credential in plaintext) needs these to decide whether the scan
 * actually covered its input. Exported rather than duplicated at the call
 * site so the two can never drift apart.
 */
export const DLP_SCAN_LIMITS = {
  /** Max characters examined per individual string field; the remainder of an
   *  oversized string is NOT scanned. */
  maxStringBytes: MAX_STRING_BYTES,
  /** Max nesting depth walked; anything deeper is NOT scanned. */
  maxDepth: MAX_DEPTH,
} as const;

/**
 * Recursively scans an args value for known secret patterns.
 * Handles nested objects, arrays, and JSON-encoded strings.
 * Returns the first match found, or null if clean.
 */
/**
 * Should this matched token be suppressed? Single source of truth for the
 * three DLP entrypoints (scanArgs, scanText, redactText); they used to carry
 * three copies of the stopword + entropy sequence, and redactText had no test.
 */
function suppressed(pattern: DlpPattern, raw: string, before = ''): boolean {
  if (pattern.validate) {
    let ok: boolean;
    try {
      ok = pattern.validate(raw, before);
    } catch {
      ok = true; // a crashing validator must not hide a block-severity match
    }
    return !ok;
  }
  if (DLP_STOPWORDS.some((sw) => raw.toLowerCase().includes(sw))) return true;
  if (pattern.minEntropy !== undefined && shannonEntropy(raw) < pattern.minEntropy) return true;
  return false;
}

/**
 * First regex match of `pattern` in `text` that survives suppression, or null.
 * OVERLAPPING: on rejection the scan resumes at match.index + 1, not after the
 * rejected window. Otherwise a decoy that fails the validator and sits right in
 * front of a real secret swallows it (the card-detector lesson, commit A). A
 * fresh /g copy per call: no module-level lastIndex to leak.
 */
function firstAcceptedMatch(pattern: DlpPattern, text: string): string | null {
  const flags = pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g';
  const re = new RegExp(pattern.regex.source, flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex = m.index + 1; // progress guard; these patterns never match empty
      continue;
    }
    if (!suppressed(pattern, m[0], text.slice(Math.max(0, m.index - 64), m.index))) return m[0];
    // On rejection, exec's own lastIndex advance (to the end of the match) is
    // sufficient: the vendor patterns are \b-anchored and separator-free, so a
    // valid match can never begin INSIDE a rejected one. The two context
    // patterns (argumentsOnly) start at a keyword or a query separator; a
    // rejected one can hide a later assignment on the same run only when the
    // two overlap, an accepted limit for a review-level heuristic. No overlap resume is
    // needed here (unlike hasValidCard / hasValidIban, whose tokens contain
    // spaces and keep their own resume, witnessed by the card and IBAN specs).
  }
  return null;
}

/** Shared accepted-token matcher for bounded argument views. */
export function matchArgumentText(
  text: string,
  fieldPath: string,
  budget?: MnemonicBudget
): DlpMatch | null {
  const lower = text.toLowerCase();
  const assignment = isAssignmentContext(text);
  let best: DlpMatch | null = null;
  for (const pattern of DLP_PATTERNS) {
    if (pattern.keywords && !pattern.keywords.some((kw) => lower.includes(kw.toLowerCase())))
      continue;
    const raw = firstAcceptedMatch(pattern, text);
    if (raw === null) continue;
    const severity = pattern.contextBoost && assignment ? 'block' : pattern.severity;
    const match: DlpMatch = {
      patternName: pattern.name,
      fieldPath,
      redactedSample: maskSecret(raw, pattern.regex),
      severity,
    };
    if (severity === 'block') return match;
    best ??= match;
  }
  if (findMnemonic(text, budget)) {
    return {
      patternName: 'BIP-39 Recovery Phrase',
      fieldPath,
      redactedSample: '[recovery phrase]',
      severity: 'block',
    };
  }
  return best;
}

/**
 * Fragments are joined with a newline for the prefilter: a newline is a word
 * boundary for every pattern, so no token is invented across fragments.
 */
const BATCH_SEPARATOR = '\n';

/**
 * Match decoded fragments: the batch is a prefilter, the match is exact. Each
 * pattern runs once over the joined text with `m` added (so `^` and `$` also
 * hold at every fragment edge, a superset of the per-fragment matches); only a
 * pattern that hits there is run on the fragments one by one, with the same
 * semantics as matching each fragment alone. Ordinary decoded text hits few
 * patterns, so the cost stays linear in decoded bytes, which is what lets
 * first-level decoding run without a count limit (fw#338 stage B).
 */
export function matchArgumentBatch(
  fragments: string[],
  fieldPath: string,
  budget?: MnemonicBudget
): DlpMatch | null {
  if (!fragments.length) return null;
  const text = fragments.join(BATCH_SEPARATOR);
  const lower = text.toLowerCase();
  let best: DlpMatch | null = null;
  for (const pattern of DLP_PATTERNS) {
    if (pattern.keywords && !pattern.keywords.some((kw) => lower.includes(kw.toLowerCase())))
      continue;
    const flags = pattern.regex.flags.replace(/[gmy]/g, '');
    if (!new RegExp(pattern.regex.source, flags + 'm').test(text)) continue;
    for (const fragment of fragments) {
      if (firstAcceptedMatch(pattern, fragment) === null) continue;
      const severity =
        pattern.contextBoost && isAssignmentContext(fragment) ? 'block' : pattern.severity;
      if (severity === 'block')
        return {
          patternName: pattern.name,
          fieldPath,
          redactedSample: '[encoded secret]',
          severity,
        };
      best ??= {
        patternName: pattern.name,
        fieldPath,
        redactedSample: '[encoded secret]',
        severity,
      };
      // Only a context boost can make a later fragment stronger than this one.
      if (!pattern.contextBoost) break;
    }
  }
  if (findMnemonic(text, budget)) {
    return {
      patternName: 'BIP-39 Recovery Phrase',
      fieldPath,
      redactedSample: '[recovery phrase]',
      severity: 'block',
    };
  }
  return best;
}

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
    const assignmentCtx = isAssignmentContext(text);

    for (const pattern of DLP_PATTERNS) {
      // Context patterns belong to the bounded argument gate only.
      if (pattern.argumentsOnly) continue;
      // Keyword prefilter: if the pattern declares keywords, at least one must
      // appear in the string before we invoke the regex engine.
      if (
        pattern.keywords &&
        !pattern.keywords.some((kw) => textLower.includes(kw.toLowerCase()))
      ) {
        continue;
      }

      const raw = firstAcceptedMatch(pattern, text);
      if (raw === null) continue;

      // Assignment context: promote review → block when the secret appears
      // in an assignment (export TOKEN=..., password: ..., api_key = ...).
      const severity = pattern.contextBoost && assignmentCtx ? 'block' : pattern.severity;

      return {
        patternName: pattern.name,
        fieldPath,
        // Mask the ACCEPTED token, not the first regex hit in the field.
        redactedSample: maskSecret(raw, pattern.regex),
        severity,
      };
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

/** The raw scanners' patterns over one text, as written. */
function scanTextOnce(t: string, redactedSample?: string): DlpMatch | null {
  const tLower = t.toLowerCase();
  for (const pattern of DLP_PATTERNS) {
    if (pattern.argumentsOnly) continue;
    if (pattern.keywords && !pattern.keywords.some((kw) => tLower.includes(kw.toLowerCase()))) {
      continue;
    }
    const raw = firstAcceptedMatch(pattern, t);
    if (raw === null) continue;
    return {
      patternName: pattern.name,
      fieldPath: 'response-text',
      redactedSample: redactedSample ?? maskSecret(raw, pattern.regex),
      severity: pattern.severity,
    };
  }
  return null;
}

/**
 * Scan a plain text string (tool output, Claude response prose) for DLP
 * patterns. The text as written first; then its decoded views (base64, hex,
 * percent, the bounded set the argument gate reads), so a credential a tool
 * returns encoded is still a finding (fw#372 B7). The first-level decoding is
 * proportional to the text and nested layers are budgeted, as in the gate.
 */
export function scanText(text: string): DlpMatch | null {
  const t = text.length > MAX_STRING_BYTES ? text.slice(0, MAX_STRING_BYTES) : text;
  const direct = scanTextOnce(t);
  if (direct) return direct;
  try {
    for (const view of secretViews(t, newSecretViewBudget())) {
      const m = scanTextOnce(view.text, '[encoded secret]');
      if (m) return m;
    }
  } catch {
    /* a decoding failure must not turn a clean scan into an error */
  }
  return null;
}

// Replaces all DLP pattern matches in text with [node9-redacted:<PatternName>].
// Returns the redacted string and a list of pattern names that were found.
//
// The WHOLE text, with no truncation and no chunking. Every caller replaces
// the content it passed in with `result` (the MCP gateway, the redact-output
// shim path, `node9 mask`), so the old MAX_STRING_BYTES slice silently dropped
// everything past 100 KB and left a secret there unredacted. Chunking stays
// rejected (a secret split across a boundary would be missed). The cost is
// linear: every pattern passes safe-regex2 and is keyword-prefiltered.
//
// A pattern that declares `redactGroup` (one that consumes a leading
// delimiter, like Azure and CASK) redacts only that group, so the quote, `=`
// or space survives. Any other capture group is left alone: the connection
// string pattern captures its SCHEME, and replacing only that would hand the
// model the password.
export function redactText(text: string): { result: string; found: string[] } {
  let result = text;
  const found: string[] = [];
  const lower = text.toLowerCase();

  for (const { pattern, globalRegex } of DLP_PATTERNS_GLOBAL) {
    if (pattern.argumentsOnly) continue;
    if (pattern.keywords && !pattern.keywords.some((kw) => lower.includes(kw.toLowerCase()))) {
      continue;
    }
    result = result.replace(globalRegex, (match: string, ...rest: unknown[]) => {
      if (suppressed(pattern, match)) return match; // leave the text intact
      if (!found.includes(pattern.name)) found.push(pattern.name);
      const marker = `[node9-redacted:${pattern.name}]`;
      const group =
        pattern.redactGroup !== undefined && typeof rest[pattern.redactGroup - 1] === 'string'
          ? (rest[pattern.redactGroup - 1] as string)
          : undefined;
      return group ? match.replace(group, marker) : marker;
    });
  }
  return { result, found };
}

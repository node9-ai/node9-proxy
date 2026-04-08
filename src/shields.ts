import type { SmartRule } from './core';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

export interface ShieldDefinition {
  name: string;
  description: string;
  aliases: string[];
  smartRules: SmartRule[];
  dangerousWords: string[];
}

// ---------------------------------------------------------------------------
// Shield loader — reads builtin JSON files + user-installed shields
// ---------------------------------------------------------------------------

const BUILTIN_DIR = path.join(__dirname, 'shields', 'builtin');
const USER_SHIELDS_DIR = path.join(os.homedir(), '.node9', 'shields');

function validateShieldDefinition(raw: unknown, filePath: string): ShieldDefinition | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    process.stderr.write(`[node9] Shield file is not an object: ${filePath}\n`);
    return null;
  }
  const r = raw as Record<string, unknown>;
  if (typeof r.name !== 'string' || !r.name) {
    process.stderr.write(`[node9] Shield file missing 'name': ${filePath}\n`);
    return null;
  }
  if (typeof r.description !== 'string') {
    process.stderr.write(`[node9] Shield file missing 'description': ${filePath}\n`);
    return null;
  }
  if (!Array.isArray(r.aliases)) {
    process.stderr.write(`[node9] Shield file missing 'aliases' array: ${filePath}\n`);
    return null;
  }
  if (!Array.isArray(r.smartRules)) {
    process.stderr.write(`[node9] Shield file missing 'smartRules' array: ${filePath}\n`);
    return null;
  }
  if (!Array.isArray(r.dangerousWords)) {
    process.stderr.write(`[node9] Shield file missing 'dangerousWords' array: ${filePath}\n`);
    return null;
  }
  return r as unknown as ShieldDefinition;
}

function loadShieldsFromDir(dir: string, label: string): Record<string, ShieldDefinition> {
  const result: Record<string, ShieldDefinition> = {};
  let entries: string[];
  try {
    entries = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      process.stderr.write(`[node9] Could not read ${label} shields dir ${dir}: ${String(err)}\n`);
    }
    return result;
  }
  for (const file of entries) {
    const filePath = path.join(dir, file);
    try {
      const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as unknown;
      const shield = validateShieldDefinition(raw, filePath);
      if (shield) result[shield.name] = shield;
    } catch (err) {
      process.stderr.write(`[node9] Failed to load ${label} shield ${file}: ${String(err)}\n`);
    }
  }
  return result;
}

function buildSHIELDS(): Record<string, ShieldDefinition> {
  const builtins = loadShieldsFromDir(BUILTIN_DIR, 'builtin');
  const userShields = loadShieldsFromDir(USER_SHIELDS_DIR, 'user');
  // User shields override builtins on name collision (power-user customisation)
  return { ...builtins, ...userShields };
}

export const SHIELDS: Record<string, ShieldDefinition> = buildSHIELDS();

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

// Resolve alias → canonical name
export function resolveShieldName(input: string): string | null {
  const lower = input.toLowerCase();
  if (SHIELDS[lower]) return lower;
  for (const [name, def] of Object.entries(SHIELDS)) {
    if (def.aliases.includes(lower)) return name;
  }
  return null;
}

export function getShield(name: string): ShieldDefinition | null {
  const resolved = resolveShieldName(name);
  return resolved ? SHIELDS[resolved] : null;
}

export function listShields(): ShieldDefinition[] {
  return Object.values(SHIELDS);
}

// ---------------------------------------------------------------------------
// Shield state (active shields + per-rule verdict overrides)
// ---------------------------------------------------------------------------

const SHIELDS_STATE_FILE = path.join(os.homedir(), '.node9', 'shields.json');

export type ShieldVerdict = 'allow' | 'review' | 'block';
// overrides: { shieldName: { fullRuleName: verdict } }
export type ShieldOverrides = Record<string, Record<string, ShieldVerdict>>;

export function isShieldVerdict(v: unknown): v is ShieldVerdict {
  return v === 'allow' || v === 'review' || v === 'block';
}

/**
 * Validates and filters an overrides object read from disk.
 * Entries with invalid (non-ShieldVerdict) values are silently dropped
 * to prevent tampered disk content from propagating arbitrary strings
 * into the policy engine.
 */
function validateOverrides(raw: unknown): ShieldOverrides {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const result: ShieldOverrides = {};
  for (const [shieldName, rules] of Object.entries(raw as Record<string, unknown>)) {
    if (!rules || typeof rules !== 'object' || Array.isArray(rules)) continue;
    const validRules: Record<string, ShieldVerdict> = {};
    for (const [ruleName, verdict] of Object.entries(rules as Record<string, unknown>)) {
      if (isShieldVerdict(verdict)) {
        validRules[ruleName] = verdict;
      } else {
        process.stderr.write(
          `[node9] Warning: shields.json contains invalid verdict "${String(verdict)}" ` +
            `for ${shieldName}/${ruleName} — entry ignored. ` +
            `File may be corrupted or tampered with.\n`
        );
      }
    }
    if (Object.keys(validRules).length > 0) result[shieldName] = validRules;
  }
  return result;
}

interface ShieldsFile {
  active: string[];
  overrides?: ShieldOverrides;
}

function readShieldsFile(): ShieldsFile {
  try {
    const raw = fs.readFileSync(SHIELDS_STATE_FILE, 'utf-8');
    if (!raw.trim()) return { active: [] };
    const parsed = JSON.parse(raw) as Partial<ShieldsFile>;
    const active = Array.isArray(parsed.active)
      ? parsed.active.filter(
          (e): e is string => typeof e === 'string' && e.length > 0 && e in SHIELDS
        )
      : [];
    return { active, overrides: validateOverrides(parsed.overrides) };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      process.stderr.write(`[node9] Warning: could not read shields state: ${String(err)}\n`);
    }
    return { active: [] };
  }
}

function writeShieldsFile(data: ShieldsFile): void {
  fs.mkdirSync(path.dirname(SHIELDS_STATE_FILE), { recursive: true });
  const tmp = `${SHIELDS_STATE_FILE}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  // Omit overrides key if empty — keeps the file clean for users who never use overrides
  const toWrite: ShieldsFile = { active: data.active };
  if (data.overrides && Object.keys(data.overrides).length > 0) toWrite.overrides = data.overrides;
  fs.writeFileSync(tmp, JSON.stringify(toWrite, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, SHIELDS_STATE_FILE);
}

export function readActiveShields(): string[] {
  return readShieldsFile().active;
}

export function writeActiveShields(active: string[]): void {
  const current = readShieldsFile();
  writeShieldsFile({ ...current, active });
}

export function readShieldOverrides(): ShieldOverrides {
  return readShieldsFile().overrides ?? {};
}

/**
 * Writes a per-rule verdict override to shields.json.
 *
 * TRUST BOUNDARY: This function is a raw storage primitive with no policy
 * guards of its own. The allow-requires-force guard lives in the CLI.
 * Any non-CLI caller (daemon, programmatic use) must validate the verdict
 * and rule name via resolveShieldRule() before calling this function.
 * The daemon currently does NOT expose this function through any endpoint.
 */
export function writeShieldOverride(
  shieldName: string,
  ruleName: string,
  verdict: ShieldVerdict
): void {
  const current = readShieldsFile();
  const overrides = { ...(current.overrides ?? {}) };
  overrides[shieldName] = { ...(overrides[shieldName] ?? {}), [ruleName]: verdict };
  writeShieldsFile({ ...current, overrides });
}

export function clearShieldOverride(shieldName: string, ruleName: string): void {
  const current = readShieldsFile();
  // True no-op: don't touch disk if the override doesn't exist
  if (!current.overrides?.[shieldName]?.[ruleName]) return;
  const overrides = { ...current.overrides };
  const updated = { ...overrides[shieldName] };
  delete updated[ruleName];
  if (Object.keys(updated).length === 0) {
    delete overrides[shieldName];
  } else {
    overrides[shieldName] = updated;
  }
  writeShieldsFile({ ...current, overrides });
}

/**
 * Resolves a short rule identifier to the full rule name within a shield.
 * Accepts three forms (case-insensitive):
 *   - Full name:            "shield:postgres:block-drop-table"
 *   - Without shield prefix: "block-drop-table"
 *   - Operation only:       "drop-table"
 */
export function resolveShieldRule(shieldName: string, identifier: string): string | null {
  const shield = SHIELDS[shieldName];
  if (!shield) return null;
  const id = identifier.toLowerCase();
  for (const rule of shield.smartRules) {
    if (!rule.name) continue;
    if (rule.name === id) return rule.name;
    const withoutShieldPrefix = rule.name.replace(`shield:${shieldName}:`, '');
    if (withoutShieldPrefix === id) return rule.name;
    // NOTE: operation-suffix matching returns the first rule whose suffix matches.
    // If two rules in the same shield ever share a suffix (e.g. block-drop and review-drop),
    // the first entry wins silently. Keep rule names unambiguous within each shield.
    const operation = withoutShieldPrefix.replace(/^(block|review|allow)-/, '');
    if (operation === id) return rule.name;
  }
  return null;
}

// ---------------------------------------------------------------------------
// User shield install helper (used by CLI `node9 shield install`)
// ---------------------------------------------------------------------------

export const USER_SHIELDS_DIR_PATH = USER_SHIELDS_DIR;

/** Validates and writes a shield definition to ~/.node9/shields/<name>.json */
export function installShield(name: string, shieldJson: unknown): void {
  // Reject names that could escape USER_SHIELDS_DIR via path traversal
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `Invalid shield name '${name}': only alphanumeric characters, hyphens, and underscores are allowed`
    );
  }
  const shield = validateShieldDefinition(shieldJson, `<downloaded:${name}>`);
  if (!shield) throw new Error(`Downloaded shield '${name}' failed validation`);
  if (shield.name !== name) {
    throw new Error(`Shield name mismatch: file declares '${shield.name}' but expected '${name}'`);
  }
  fs.mkdirSync(USER_SHIELDS_DIR, { recursive: true });
  const filePath = path.join(USER_SHIELDS_DIR, `${name}.json`);
  const tmp = `${filePath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(shieldJson, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

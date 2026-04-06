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

export const SHIELDS: Record<string, ShieldDefinition> = {
  postgres: {
    name: 'postgres',
    description: 'Protects PostgreSQL databases from destructive AI operations',
    aliases: ['pg', 'postgresql'],
    smartRules: [
      {
        name: 'shield:postgres:block-drop-table',
        tool: '*',
        conditions: [{ field: 'sql', op: 'matches', value: 'DROP\\s+TABLE', flags: 'i' }],
        verdict: 'block',
        reason: 'DROP TABLE is irreversible — blocked by Postgres shield',
      },
      {
        name: 'shield:postgres:block-truncate',
        tool: '*',
        conditions: [{ field: 'sql', op: 'matches', value: 'TRUNCATE\\s+TABLE', flags: 'i' }],
        verdict: 'block',
        reason: 'TRUNCATE is irreversible — blocked by Postgres shield',
      },
      {
        name: 'shield:postgres:block-drop-column',
        tool: '*',
        conditions: [
          { field: 'sql', op: 'matches', value: 'ALTER\\s+TABLE.*DROP\\s+COLUMN', flags: 'i' },
        ],
        verdict: 'block',
        reason: 'DROP COLUMN is irreversible — blocked by Postgres shield',
      },
      {
        name: 'shield:postgres:review-grant-revoke',
        tool: '*',
        conditions: [{ field: 'sql', op: 'matches', value: '\\b(GRANT|REVOKE)\\b', flags: 'i' }],
        verdict: 'review',
        reason: 'Permission changes require human approval (Postgres shield)',
      },
    ],
    dangerousWords: ['dropdb', 'pg_dropcluster'],
  },

  github: {
    name: 'github',
    description: 'Protects GitHub repositories from destructive AI operations',
    aliases: ['git'],
    smartRules: [
      {
        // Note: git branch -d/-D is already caught by the built-in review-git-destructive rule.
        // This rule adds coverage for `git push --delete` which the built-in does not match.
        name: 'shield:github:review-delete-branch-remote',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'git\\s+push\\s+.*--delete',
            flags: 'i',
          },
        ],
        verdict: 'review',
        reason: 'Remote branch deletion requires human approval (GitHub shield)',
      },
      {
        name: 'shield:github:block-delete-repo',
        tool: '*',
        conditions: [
          { field: 'command', op: 'matches', value: 'gh\\s+repo\\s+delete', flags: 'i' },
        ],
        verdict: 'block',
        reason: 'Repository deletion is irreversible — blocked by GitHub shield',
      },
    ],
    dangerousWords: [],
  },

  aws: {
    name: 'aws',
    description: 'Protects AWS infrastructure from destructive AI operations',
    aliases: ['amazon'],
    smartRules: [
      {
        name: 'shield:aws:block-delete-s3-bucket',
        tool: '*',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'aws\\s+s3.*rb\\s|aws\\s+s3api\\s+delete-bucket',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason: 'S3 bucket deletion is irreversible — blocked by AWS shield',
      },
      {
        name: 'shield:aws:review-iam-changes',
        tool: '*',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'aws\\s+iam\\s+(create|delete|attach|detach|put|remove)',
            flags: 'i',
          },
        ],
        verdict: 'review',
        reason: 'IAM changes require human approval (AWS shield)',
      },
      {
        name: 'shield:aws:block-ec2-terminate',
        tool: '*',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'aws\\s+ec2\\s+terminate-instances',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason: 'EC2 instance termination is irreversible — blocked by AWS shield',
      },
      {
        name: 'shield:aws:review-rds-delete',
        tool: '*',
        conditions: [
          { field: 'command', op: 'matches', value: 'aws\\s+rds\\s+delete-', flags: 'i' },
        ],
        verdict: 'review',
        reason: 'RDS deletion requires human approval (AWS shield)',
      },
    ],
    dangerousWords: [],
  },

  'bash-safe': {
    name: 'bash-safe',
    description: 'Blocks high-risk bash patterns: pipe-to-shell, rm -rf /, disk overwrites, eval',
    aliases: ['bash', 'shell'],
    smartRules: [
      {
        name: 'shield:bash-safe:block-pipe-to-shell',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '(curl|wget)\\s+[^|]*\\|\\s*(bash|sh|zsh|fish|python3?|ruby|perl|node)',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason:
          'Pipe-to-shell is a common supply-chain attack vector — blocked by bash-safe shield',
      },
      {
        name: 'shield:bash-safe:block-obfuscated-exec',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'base64\\s+(-d|--decode).*\\|\\s*(bash|sh|zsh)',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason: 'Obfuscated execution via base64 decode — blocked by bash-safe shield',
      },
      {
        name: 'shield:bash-safe:block-rm-root',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value:
              'rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\\s+(\\/|~|\\$HOME|\\$\\{HOME\\})\\s*$',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason: 'rm -rf of root or home directory is catastrophic — blocked by bash-safe shield',
      },
      {
        name: 'shield:bash-safe:block-disk-overwrite',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'dd\\s+.*of=\\/dev\\/(sd|nvme|hd|vd|xvd)',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason: 'Writing directly to a block device is irreversible — blocked by bash-safe shield',
      },
      {
        name: 'shield:bash-safe:review-eval',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '\\beval\\s+[\\$`("]',
            flags: 'i',
          },
        ],
        verdict: 'review',
        reason: 'eval of dynamic content requires human approval (bash-safe shield)',
      },
    ],
    dangerousWords: [],
  },

  filesystem: {
    name: 'filesystem',
    description: 'Protects the local filesystem from dangerous AI operations',
    aliases: ['fs'],
    smartRules: [
      {
        name: 'shield:filesystem:review-chmod-777',
        tool: 'bash',
        conditions: [
          { field: 'command', op: 'matches', value: 'chmod\\s+(777|a\\+rwx)', flags: 'i' },
        ],
        verdict: 'review',
        reason: 'chmod 777 requires human approval (filesystem shield)',
      },
      {
        name: 'shield:filesystem:review-write-etc',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            // Narrow to write-indicative operations to avoid approval fatigue on reads.
            // Matches: tee /etc/*, cp .../etc/*, mv .../etc/*, > /etc/*, install .../etc/*
            op: 'matches',
            value: '(tee|\\bcp\\b|\\bmv\\b|install|>+)\\s+.*\\/etc\\/',
          },
        ],
        verdict: 'review',
        reason: 'Writing to /etc requires human approval (filesystem shield)',
      },
    ],
    // dd removed: too common as a legitimate tool (disk imaging, file ops).
    // mkfs removed: already in the built-in DANGEROUS_WORDS baseline.
    // wipefs retained: rarely legitimate in an agent context and not in built-ins.
    dangerousWords: ['wipefs'],
  },
};

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

// --- Shield state (active shields + per-rule verdict overrides) ---

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

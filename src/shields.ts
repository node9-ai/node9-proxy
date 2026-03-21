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

// --- Shield state (which shields are active) ---

const SHIELDS_STATE_FILE = path.join(os.homedir(), '.node9', 'shields.json');

export function readActiveShields(): string[] {
  try {
    const raw = fs.readFileSync(SHIELDS_STATE_FILE, 'utf-8');
    if (!raw.trim()) return []; // empty file — treat same as missing
    const parsed = JSON.parse(raw) as { active?: unknown };
    if (Array.isArray(parsed.active)) {
      // Validate each element is a non-empty string that refers to a known shield
      return parsed.active.filter(
        (e): e is string => typeof e === 'string' && e.length > 0 && e in SHIELDS
      );
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      // Unexpected error (permissions, parse failure) — log but don't crash
      process.stderr.write(`[node9] Warning: could not read shields state: ${String(err)}\n`);
    }
  }
  return [];
}

export function writeActiveShields(active: string[]): void {
  // mkdirSync is idempotent with recursive:true — avoids existsSync TOCTOU window
  fs.mkdirSync(path.dirname(SHIELDS_STATE_FILE), { recursive: true });
  // Use random suffix to avoid pid collision on concurrent invocations
  const tmp = `${SHIELDS_STATE_FILE}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ active }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, SHIELDS_STATE_FILE);
}

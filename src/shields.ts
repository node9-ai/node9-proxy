import type { SmartRule } from './core';
import fs from 'fs';
import path from 'path';
import os from 'os';

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
        name: 'shield:github:block-force-push',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'git\\s+push.*(--force|-f\\b|--force-with-lease)',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason: 'Force push is irreversible — blocked by GitHub shield',
      },
      {
        name: 'shield:github:review-delete-branch',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'git\\s+push\\s+.*--delete|git\\s+branch\\s+-[dD]',
            flags: 'i',
          },
        ],
        verdict: 'review',
        reason: 'Branch deletion requires human approval (GitHub shield)',
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
        name: 'shield:filesystem:block-rm-rf-home',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            // Covers: rm -rf, rm --recursive --force, rm -fr, and home paths including
            // ~, $HOME, /home/*, /root. Does not rely on whitespace before path.
            op: 'matches',
            value:
              'rm\\b.*(--recursive|--force|-[a-z]*r[a-z]*|-[a-z]*f[a-z]*).*(-[a-z]*f[a-z]*|-[a-z]*r[a-z]*|--force|--recursive).*(~|\\$HOME|\\/home\\/|\\/root\\/|\\/root$)',
            flags: 'i',
          },
        ],
        verdict: 'block',
        reason: 'Recursive force-delete of home directory — blocked by filesystem shield',
      },
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
            // Match /etc/ anywhere in the command, not just after whitespace
            op: 'matches',
            value: '\\/etc\\/',
          },
        ],
        verdict: 'review',
        reason: 'Writing to /etc requires human approval (filesystem shield)',
      },
    ],
    dangerousWords: ['dd', 'wipefs', 'mkfs'],
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
    if (fs.existsSync(SHIELDS_STATE_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(SHIELDS_STATE_FILE, 'utf-8')) as {
        active?: unknown;
      };
      if (Array.isArray(parsed.active)) {
        // Validate each element is a non-empty string
        return parsed.active.filter((e): e is string => typeof e === 'string' && e.length > 0);
      }
    }
  } catch {}
  return [];
}

export function writeActiveShields(active: string[]): void {
  const dir = path.dirname(SHIELDS_STATE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = `${SHIELDS_STATE_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ active }, null, 2));
  fs.renameSync(tmp, SHIELDS_STATE_FILE);
}

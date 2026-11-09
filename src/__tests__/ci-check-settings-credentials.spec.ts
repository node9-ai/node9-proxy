// node9Firewall#465: a secret saved inside an approved command. Claude Code's "don't ask
// again" writes the command word for word into `.claude/settings.local.json`; the committed
// file is then graded for permission shape only. WRITTEN BEFORE THE IMPLEMENTATION.
//
// Every secret-shaped fixture is built at run time: node9's own gate blocks a credential
// literal in a tool argument, test files included, and this repository is public.

import { describe, it, expect } from 'vitest';
import { analyzeAgentConfig } from '../ci-check/agent-config';
import { scanTree } from '../ci-check';
import { isAlert, isReviewItem, tierOf } from '../ci-check/tier';
import { crc32, base62Checksum } from '../../packages/policy-engine/src/scan/checksums';
import { DLP_SCAN_LIMITS } from '@node9/policy-engine';
import { createHash } from 'node:crypto';

const CRED = 'CI-1.allow-rule-credential';
const LOCAL = 'CI-1.local-settings-committed';

// A password that is not a word, a run or a placeholder.
const PASSWORD = ['Zq8v', 'L2pX', '9mQ4', 'rT7w', 'B1n'].join('');
const DB_URL = `postgres://app:${PASSWORD}@db.internal:5432/app`;
const RANDOM30 = ['k3Jd8', 'Qw2Lp', '9ZxVb', '7NmRt', '4HgYc', '1FsEa'].join('');
const CHECKSUM = base62Checksum(crc32(RANDOM30));
const GH_TOKEN = 'ghp_' + RANDOM30 + CHECKSUM;
// The same 30 characters with the first checksum character changed.
const GH_LOOKALIKE = 'ghp_' + RANDOM30 + (CHECKSUM[0] === 'A' ? 'B' : 'A') + CHECKSUM.slice(1);
const AWS_SECRET = ['wJalrXUtn', 'FEMIK7MD', 'ENGbPxRf', 'iCYQvZtSnKEY'].join('');
const locatorOf = (list: string, entry: string) =>
  `permissions.${list}:${createHash('sha256').update(entry).digest('hex').slice(0, 12)}`;

const settings = (permissions: Record<string, unknown>, path = '.claude/settings.json') =>
  analyzeAgentConfig(path, JSON.stringify({ permissions }, null, 2));

const cred = (permissions: Record<string, unknown>, path?: string) =>
  settings(permissions, path).filter((f) => f.rule === CRED);

describe('CI-1.allow-rule-credential', () => {
  it('a connection string in an approved psql command: high, located by list and digest, the password nowhere', () => {
    const entry = `Bash(psql ${DB_URL} -c 'select 1')`;
    const [f, ...rest] = cred({ allow: [entry] });
    expect(rest).toHaveLength(0);
    expect(f).toMatchObject({
      check: 'CI-1',
      rule: CRED,
      dimension: 'data',
      severity: 'high',
      locator: locatorOf('allow', entry),
      file: '.claude/settings.json',
    });
    expect(f.signals[0]).toMatch(/^permissions\.allow\[0\] matches /);
    expect(f.signals[0]).toMatch(/Database Connection String/);
    expect(f.line).toBe(4);
    expect(JSON.stringify(f)).not.toContain(PASSWORD);
    expect(tierOf(f)).toBe('alert');
  });

  it('a GitHub token with a valid checksum is a finding; the same shape with a wrong checksum is not', () => {
    expect(
      cred({
        allow: [`Bash(curl -H "Authorization: token ${GH_TOKEN}" https://api.github.com/user)`],
      })
    ).toHaveLength(1);
    expect(
      cred({
        allow: [`Bash(curl -H "Authorization: token ${GH_LOOKALIKE}" https://api.github.com/user)`],
      })
    ).toHaveLength(0);
  });

  it('an inline AWS secret assignment is read like the gate reads a command: medium, as the engine only trusts the name', () => {
    const [f] = cred({ allow: [`Bash(AWS_SECRET_ACCESS_KEY=${AWS_SECRET} aws s3 ls)`] });
    expect(f?.severity).toBe('medium');
    expect(f.signals[0]).toMatch(/Assigned Secret|Inline Secret Assignment/);
    expect(JSON.stringify(f)).not.toContain(AWS_SECRET);
  });

  it.each([
    'Bash(psql $DATABASE_URL)',
    "Bash(psql ${DATABASE_URL} -c 'select 1')",
    'Bash(psql postgres://user:<your-password>@host/db)',
    'Bash(curl -H "Authorization: Bearer your_token_here" https://x.test)',
    'Bash(export GITHUB_TOKEN=$(gh auth token) && gh api user)',
    'Bash(git push:*)',
    'mcp__github__get_issue',
  ])('%s is not a credential', (entry) => {
    expect(cred({ allow: [entry] })).toHaveLength(0);
  });

  it('allowedTools, deny and ask are read like allow, each entry its own finding with its own line', () => {
    const permissions = {
      allowedTools: ['Read', `Bash(psql ${DB_URL})`],
      deny: [`Bash(curl -H "Authorization: token ${GH_TOKEN}")`],
      ask: [`Bash(AWS_SECRET_ACCESS_KEY=${AWS_SECRET} aws s3 ls)`],
    };
    const findings = cred(permissions);
    expect(findings.map((f) => f.locator)).toEqual([
      locatorOf('allowedTools', permissions.allowedTools[1]),
      locatorOf('deny', permissions.deny[0]),
      locatorOf('ask', permissions.ask[0]),
    ]);
    expect(findings.map((f) => f.title)).toEqual([
      expect.stringMatching(/^An approved command/),
      expect.stringMatching(/^A permission rule/),
      expect.stringMatching(/^A permission rule/),
    ]);
    const content = JSON.stringify({ permissions }, null, 2).split('\n');
    for (const f of findings) {
      expect(f.line).toBeDefined();
      expect(content[f.line! - 1]).toMatch(/Bash\(/);
    }
    expect(new Set(findings.map((f) => f.line)).size).toBe(3);
  });

  it('keeps its identity when entries above it move, so a CI-5 diff sees one unchanged finding', () => {
    const entry = `Bash(psql ${DB_URL})`;
    const [before] = cred({ allow: [entry, 'Read'] });
    const [after] = cred({ allow: ['Read', 'Bash(git status:*)', entry] });
    expect(after.locator).toBe(before.locator);
    expect(after.line).not.toBe(before.line);
  });

  it('the same entry in two lists anchors each finding at its own line', () => {
    const entry = `Bash(psql ${DB_URL})`;
    const findings = cred({ allow: [entry], deny: [entry] });
    expect(findings).toHaveLength(2);
    expect(findings[0].line).toBeLessThan(findings[1].line!);
  });

  it('reads an entry only up to the engine cap, like every other scanner input', () => {
    const giant = 'Bash(' + 'a'.repeat(DLP_SCAN_LIMITS.maxStringBytes) + ` psql ${DB_URL})`;
    const started = Date.now();
    expect(cred({ allow: [giant] })).toHaveLength(0);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it('the fix names the rotation and, for the local file, the untracking', () => {
    const [shared] = cred({ allow: [`Bash(psql ${DB_URL})`] });
    expect(shared.fix).toMatch(/rotate/i);
    const [local] = cred({ allow: [`Bash(psql ${DB_URL})`] }, '.claude/settings.local.json');
    expect(local.fix).toMatch(/git rm --cached \.claude\/settings\.local\.json/);
  });
});

describe('CI-1.local-settings-committed', () => {
  it('a committed settings.local.json is a review item on its own, once, whatever it holds', () => {
    const clean = settings(
      { allow: ['Read', 'Bash(git status:*)'] },
      '.claude/settings.local.json'
    );
    expect(clean.map((f) => f.rule)).toEqual([LOCAL]);
    expect(clean[0]).toMatchObject({
      severity: 'advisory',
      dimension: 'toolRules',
      file: '.claude/settings.local.json',
    });
    expect(tierOf(clean[0])).toBe('review');
    expect(clean[0].fix).toMatch(/\.gitignore/);
  });

  it('is reported for a nested copy and for a file that does not parse', () => {
    expect(settings({}, 'packages/app/.claude/settings.local.json').map((f) => f.rule)).toEqual([
      LOCAL,
    ]);
    expect(
      analyzeAgentConfig('.claude/settings.local.json', '{ not json').map((f) => f.rule)
    ).toEqual([LOCAL]);
  });

  it('never fires for the shared settings.json', () => {
    expect(settings({ allow: ['Read'] }).some((f) => f.rule === LOCAL)).toBe(false);
  });
});

describe('through scanTree (the hosted scan reads the same JSON)', () => {
  it('a local file with a connection string: worst high, the credential counted, the committed file listed, the password absent', () => {
    const res = scanTree({
      source: 'o/r',
      notes: [],
      files: [
        {
          path: '.claude/settings.local.json',
          content: JSON.stringify(
            { permissions: { allow: [`Bash(psql ${DB_URL} -c 'select 1')`] } },
            null,
            2
          ),
        },
      ],
    });
    expect(res.worst).toBe('high');
    const credential = res.findings.find((f) => f.rule === CRED)!;
    const committed = res.findings.find((f) => f.rule === LOCAL)!;
    expect(isAlert(credential)).toBe(true);
    expect(isReviewItem(committed)).toBe(true);
    expect(JSON.stringify(res)).not.toContain(PASSWORD);
  });
});

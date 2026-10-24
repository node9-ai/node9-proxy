// Finding apps from names only (node9Firewall#390, phase 2): MCP server
// labels and programs in the audit log, dependency names in a project's
// manifests, env var NAMES in its .env files. A value never comes back.
import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  programsOf,
  observeAudit,
  projectPackages,
  projectEnvNames,
  matchApps,
} from '../apps/detect';
import { appsReportLines } from '../apps/report';

const dirs: string[] = [];
function tmp(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-apps-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

const SECRET = 'sk_live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2';

describe('programsOf: the program each command segment runs', () => {
  it.each([
    ['psql -h db -c "select 1"', ['psql']],
    ['STRIPE_API_KEY=x stripe refunds create', ['stripe']],
    ['sudo -E redis-cli FLUSHALL', ['redis-cli']],
    ['cd x && /usr/local/bin/kubectl get pods | grep api', ['cd', 'kubectl', 'grep']],
    ['npx stripe listen', ['stripe']],
    ['', []],
  ])('%s', (cmd, want) => {
    expect(programsOf(cmd)).toEqual(want);
  });
});

describe('observeAudit', () => {
  it('reads MCP servers, Bash programs and working directories, newest first', () => {
    const d = tmp();
    const audit = path.join(d, 'audit.log');
    const rows = [
      { tool: 'Bash', argsPreview: 'psql -c "select 1"', workingDir: '/srv/old' },
      { tool: 'mcp__stripe__list_customers', argsPreview: '{}', workingDir: '/srv/shop' },
      { tool: 'create_refund', mcpServer: 'PayPal-Live', workingDir: '/srv/shop' },
      'not json',
    ];
    fs.writeFileSync(
      audit,
      rows.map((r) => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n')
    );
    const obs = observeAudit(audit);
    expect([...obs.servers].sort()).toEqual(['paypal-live', 'stripe']);
    expect(obs.commands.has('psql')).toBe(true);
    expect(obs.projects).toEqual(['/srv/shop', '/srv/old']);
  });

  it('a missing log observes nothing', () => {
    const obs = observeAudit(path.join(tmp(), 'nope.log'));
    expect(obs.servers.size + obs.commands.size + obs.projects.length).toBe(0);
  });
});

describe('a project: dependency names and env NAMES, never values', () => {
  it('reads package.json, requirements.txt and pyproject.toml', () => {
    const d = tmp();
    fs.writeFileSync(
      path.join(d, 'package.json'),
      JSON.stringify({
        dependencies: { stripe: '^14', express: '^4' },
        devDependencies: { '@aws-sdk/client-s3': '^3' },
      })
    );
    fs.writeFileSync(
      path.join(d, 'requirements.txt'),
      '# deps\nboto3==1.34\n-r other.txt\npsycopg2-binary\n'
    );
    fs.writeFileSync(
      path.join(d, 'pyproject.toml'),
      '[project]\ndependencies = ["pymongo>=4", "httpx"]\n[tool.poetry.dependencies]\npython = "^3.11"\nredis = "^5"\n'
    );
    const pk = projectPackages(d);
    for (const n of [
      'stripe',
      'express',
      '@aws-sdk/client-s3',
      'boto3',
      'psycopg2-binary',
      'pymongo',
      'redis',
    ])
      expect(pk.has(n), n).toBe(true);
    expect(pk.has('python')).toBe(false);
  });

  it('keeps the name of every .env line and drops its value', () => {
    const d = tmp();
    fs.writeFileSync(
      path.join(d, '.env'),
      `STRIPE_SECRET_KEY=${SECRET}\nexport DATABASE_URL="postgres://u:p@h/db"\n# comment\n`
    );
    const names = projectEnvNames(d);
    expect([...names].sort()).toEqual(['DATABASE_URL', 'STRIPE_SECRET_KEY']);
  });
});

describe('matchApps', () => {
  it('names each app with how it was found, and no value', () => {
    const d = tmp();
    fs.writeFileSync(
      path.join(d, 'package.json'),
      JSON.stringify({ dependencies: { stripe: '^14' } })
    );
    fs.writeFileSync(path.join(d, '.env'), `STRIPE_SECRET_KEY=${SECRET}\nPAYPAL_CLIENT_ID=abc\n`);
    const found = matchApps(
      { servers: new Set(['redis-prod']), commands: new Set(['psql', 'git']), projects: [d] },
      [{ dir: d, packages: projectPackages(d), envNames: projectEnvNames(d) }]
    );
    const bySlug = Object.fromEntries(found.map((f) => [f.slug, f.signals]));
    expect(Object.keys(bySlug).sort()).toEqual(['paypal', 'postgres', 'redis', 'stripe']);
    expect(bySlug.stripe.map((s) => `${s.kind}:${s.value}`)).toEqual([
      'package:stripe',
      'env-name:STRIPE_SECRET_KEY',
    ]);
    expect(JSON.stringify(found)).not.toContain(SECRET);
    // git is everywhere and names no app.
    expect(bySlug.github).toBeUndefined();
  });
});

describe('appsReportLines', () => {
  const file = {
    version: 1 as const,
    apps: {
      stripe: { state: 'on' as const, by: 'detected' as const, at: '', signals: [] },
      redis: { state: 'off' as const, by: 'user' as const, at: '', signals: [] },
    },
    links: {},
  };
  it('names what is protected and what a person turned off', () => {
    const lines = appsReportLines(file, ['stripe'], { loggedIn: true, asked: 3 });
    expect(lines[0]).toContain('Stripe');
    expect(lines[1]).toContain('Redis');
  });
  it('suggests the dashboard only when not logged in and asked often', () => {
    expect(
      appsReportLines(file, ['stripe'], { loggedIn: false, asked: 9 }).join('\n')
    ).not.toContain('node9 login');
    expect(appsReportLines(file, ['stripe'], { loggedIn: false, asked: 10 }).join('\n')).toContain(
      'node9 login'
    );
    expect(
      appsReportLines(file, ['stripe'], { loggedIn: true, asked: 50 }).join('\n')
    ).not.toContain('node9 login');
  });
});

describe('applyDetection on a machine the workspace manages', () => {
  it('records what it found and turns no shield on', async () => {
    const home = tmp();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    const prevHome = process.env.HOME;
    process.env.HOME = home;
    try {
      vi.resetModules();
      const state = await import('../apps/state.js');
      const shields = await import('../shields.js');
      const res = state.applyDetection(
        [{ slug: 'stripe', signals: [{ kind: 'package', value: 'stripe' }] }],
        { managed: true, home }
      );
      expect(res).toEqual({ turnedOn: [], recordedOnly: ['stripe'] });
      expect(state.readAppsFile(home).apps.stripe.state).toBe('on');
      expect(shields.readActiveShields()).not.toContain('stripe');
    } finally {
      process.env.HOME = prevHome;
      vi.resetModules();
    }
  });
});

describe('resolveLinkedServer: local and workspace links', () => {
  it('maps a label by this machine, by server key, by the gateway name and by a cfg: key', async () => {
    const home = tmp();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'mcp-tools.json'),
      JSON.stringify({ k1: { tools: [], disabled: [], status: 'approved', name: 'billing-gw' } })
    );
    const prevHome = process.env.HOME;
    process.env.HOME = home;
    try {
      vi.resetModules();
      const state = await import('../apps/state.js');
      state.setLink('acme_billing', 'stripe', home);
      expect(state.resolveLinkedServer('acme_billing')).toBe('stripe');
      const managedLinks = { k1: 'paypal', 'cfg:claude:pay-svc': 'stripe' };
      expect(state.resolveLinkedServer('x', { serverKey: 'k1', managedLinks })).toBe('paypal');
      expect(state.resolveLinkedServer('billing-gw', { managedLinks })).toBe('paypal');
      expect(state.resolveLinkedServer('pay-svc', { managedLinks })).toBe('stripe');
      expect(state.resolveLinkedServer('other', { managedLinks })).toBe('other');
    } finally {
      process.env.HOME = prevHome;
      vi.resetModules();
    }
  });
});

describe('snapshotApps: what the dashboard gets', () => {
  it('names and states, no project paths, capped signals', async () => {
    const { snapshotApps } = await import('../policy-snapshot/build.js');
    const out = snapshotApps({
      version: 1,
      apps: {
        stripe: {
          state: 'on',
          by: 'detected',
          at: '',
          signals: Array.from({ length: 9 }, (_, i) => ({
            kind: 'package' as const,
            value: `p${i}`,
            project: '/home/dana/secret-project',
          })),
        },
      },
      links: {},
    });
    expect(out).toHaveLength(1);
    expect(out[0].signals).toHaveLength(6);
    expect(JSON.stringify(out)).not.toContain('secret-project');
  });
});

describe('tune from the event: approvals in the audit become one suggestion', () => {
  it('reads inline approvals and card decisions, and names the command that stops the question', async () => {
    const { approvalsFromAudit, suggestionLines } = await import('../apps/report.js');
    const d = tmp();
    const audit = path.join(d, 'audit.log');
    const now = Date.now();
    const row = (o: Record<string, unknown>) =>
      JSON.stringify({ ts: new Date(now - 1000).toISOString(), ...o });
    fs.writeFileSync(
      audit,
      [
        row({
          tool: 'mcp__stripe__create_refund',
          checkedBy: 'inline-review',
          decision: 'allow',
          ruleName: 'Smart Rule: shield:stripe:review-refund',
          sessionId: 's1',
        }),
        row({
          tool: 'mcp__stripe__create_refund',
          checkedBy: 'inline-review',
          decision: 'allow',
          ruleName: 'Smart Rule: shield:stripe:review-refund',
          sessionId: 's2',
        }),
        row({
          tool: 'mcp__stripe__create_refund',
          decidedBy: 'person',
          decision: 'allow',
          ruleName: 'shield:stripe:review-refund',
          sessionId: 's2',
        }),
        // An auto-allow is not a person's approval.
        row({
          tool: 'mcp__stripe__create_refund',
          checkedBy: 'smart-rule',
          decision: 'allow',
          ruleName: 'shield:stripe:review-refund',
          sessionId: 's3',
        }),
        // Too old for the period.
        JSON.stringify({
          ts: new Date(now - 40 * 86400000).toISOString(),
          tool: 'x',
          checkedBy: 'inline-review',
          decision: 'allow',
          ruleName: 'shield:stripe:review-payout',
          sessionId: 's9',
        }),
      ].join('\n')
    );
    const rows = approvalsFromAudit(audit, now - 7 * 86400000);
    expect(rows).toHaveLength(3);
    const lines = suggestionLines(rows);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('Stripe: you approved refunds 3 times in 2 sessions');
    expect(lines[0]).toContain('node9 apps stripe refunds allow --force');
  });

  it('a card a person denied cancels it', async () => {
    const { approvalsFromAudit, suggestionLines } = await import('../apps/report.js');
    const d = tmp();
    const audit = path.join(d, 'audit.log');
    const ts = new Date().toISOString();
    const lines = ['s1', 's2', 's3'].map((s) =>
      JSON.stringify({
        ts,
        tool: 't',
        checkedBy: 'inline-review',
        decision: 'allow',
        ruleName: 'shield:redis:review-config-set',
        sessionId: s,
      })
    );
    lines.push(
      JSON.stringify({
        ts,
        tool: 't',
        decidedBy: 'person',
        decision: 'deny',
        ruleName: 'shield:redis:review-config-set',
        sessionId: 's4',
      })
    );
    fs.writeFileSync(audit, lines.join('\n'));
    expect(suggestionLines(approvalsFromAudit(audit, 0))).toEqual([]);
  });
});

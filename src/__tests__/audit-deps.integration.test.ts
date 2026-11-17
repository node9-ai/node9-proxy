import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';

// scripts/audit-deps.sh turns `npm audit` into three outcomes. The stub seams
// let each branch run without npm or the network, and the "unavailable" branch
// is also exercised for real below by pointing npm at a dead registry.
const script = path.resolve(process.cwd(), 'scripts/audit-deps.sh');
const run = (env: Record<string, string>, args: string[] = []) =>
  spawnSync('bash', [script, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });

const report = (vulns: Record<string, number>, list: Record<string, unknown> = {}) =>
  JSON.stringify({ metadata: { vulnerabilities: vulns }, vulnerabilities: list });

// Git Bash exists on windows-latest, but this test pins CI behaviour on the
// runners that hit the outage; skip where `bash` may be a different shell.
describe.skipIf(process.platform === 'win32')('scripts/audit-deps.sh', () => {
  it('clean report → exit 0', () => {
    const r = run({ AUDIT_STUB_RC: '0', AUDIT_STUB_STDOUT: report({ moderate: 0, high: 0 }) });
    expect(r.error).toBeUndefined();
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toMatch(/no vulnerabilities/);
  });

  it('vulnerabilities found → exit 1 (the gate is unchanged)', () => {
    const r = run({
      AUDIT_STUB_RC: '1',
      AUDIT_STUB_STDOUT: report(
        { moderate: 1, high: 2 },
        { lodash: { severity: 'high', fixAvailable: true } }
      ),
    });
    expect(r.status, r.stdout + r.stderr).toBe(1);
    expect(r.stdout).toMatch(/2 high/);
    expect(r.stdout).toMatch(/lodash: high/);
  });

  it('endpoint error → exit 0 with a DID NOT RUN warning, never a pass', () => {
    const r = run({
      AUDIT_STUB_RC: '1',
      AUDIT_STUB_STDOUT: '',
      AUDIT_STUB_STDERR:
        'npm warn audit 503 Service Unavailable\nnpm error audit endpoint returned an error',
    });
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toMatch(/DID NOT RUN/);
    expect(r.stdout).toMatch(/::warning/);
    expect(r.stdout).not.toMatch(/no vulnerabilities/);
  });

  it('hang (timeout exit 124) → exit 0 with a DID NOT RUN warning', () => {
    const r = run({ AUDIT_STUB_RC: '124', AUDIT_STUB_STDOUT: '', AUDIT_STUB_STDERR: '' });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/DID NOT RUN/);
  });

  // ── Exemptions: an advisory with no patched version (picomatch, 2026-11-17)
  describe('exemptions', () => {
    const GHSA = 'GHSA-fc5q-39xc-vjpf';
    const exemptFile = (expires: string) => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-audit-ex-'));
      const file = path.join(dir, 'audit-exemptions.json');
      fs.writeFileSync(
        file,
        JSON.stringify({
          exemptions: [{ advisory: GHSA, package: 'picomatch', expires, reason: 'test' }],
        })
      );
      return file;
    };
    const via = (id: string) => ({ url: `https://github.com/advisories/${id}`, severity: 'high' });
    const picomatchOnly = report(
      { high: 1 },
      { picomatch: { severity: 'high', via: [via(GHSA)], fixAvailable: false } }
    );
    const args = ['--omit=dev', '--audit-level=moderate'];

    it('only an exempted, unexpired advisory → exit 0 with a warning that names it', () => {
      const r = run(
        {
          AUDIT_STUB_RC: '1',
          AUDIT_STUB_STDOUT: picomatchOnly,
          AUDIT_EXEMPTIONS: exemptFile('2026-12-17'),
          AUDIT_TODAY: '2026-11-17',
        },
        args
      );
      expect(r.status, r.stdout + r.stderr).toBe(0);
      expect(r.stdout).toMatch(/EXEMPTED/);
      expect(r.stdout).toMatch(/::warning/);
      expect(r.stdout).toContain(`exempted: ${GHSA} (picomatch) until 2026-12-17`);
      expect(r.stdout).not.toMatch(/no vulnerabilities/);
    });

    it('an expired exemption no longer applies → exit 1', () => {
      const r = run(
        {
          AUDIT_STUB_RC: '1',
          AUDIT_STUB_STDOUT: picomatchOnly,
          AUDIT_EXEMPTIONS: exemptFile('2026-12-17'),
          AUDIT_TODAY: '2026-12-18',
        },
        args
      );
      expect(r.status, r.stdout + r.stderr).toBe(1);
      expect(r.stdout).toMatch(/expired on 2026-12-17/);
      expect(r.stdout).toMatch(/picomatch: high/);
    });

    it('an exemption never covers a second, different advisory → exit 1', () => {
      const r = run(
        {
          AUDIT_STUB_RC: '1',
          AUDIT_STUB_STDOUT: report(
            { high: 2 },
            {
              picomatch: { severity: 'high', via: [via(GHSA)] },
              lodash: { severity: 'high', via: [via('GHSA-aaaa-bbbb-cccc')] },
            }
          ),
          AUDIT_EXEMPTIONS: exemptFile('2026-12-17'),
          AUDIT_TODAY: '2026-11-17',
        },
        args
      );
      expect(r.status, r.stdout + r.stderr).toBe(1);
      expect(r.stdout).toMatch(/lodash: high/);
      expect(r.stdout).not.toMatch(/picomatch: high/);
    });

    it('a package vulnerable only through an exempted one is exempt too', () => {
      const r = run(
        {
          AUDIT_STUB_RC: '1',
          AUDIT_STUB_STDOUT: report(
            { high: 2 },
            {
              picomatch: { severity: 'high', via: [via(GHSA)] },
              micromatch: { severity: 'high', via: ['picomatch'] },
            }
          ),
          AUDIT_EXEMPTIONS: exemptFile('2026-12-17'),
          AUDIT_TODAY: '2026-11-17',
        },
        args
      );
      expect(r.status, r.stdout + r.stderr).toBe(0);
    });

    it('a missing exemptions file changes nothing → exit 1', () => {
      const r = run(
        {
          AUDIT_STUB_RC: '1',
          AUDIT_STUB_STDOUT: picomatchOnly,
          AUDIT_EXEMPTIONS: path.join(os.tmpdir(), 'n9-no-such-exemptions.json'),
        },
        args
      );
      expect(r.status, r.stdout + r.stderr).toBe(1);
    });

    it('the checked-in exemptions file is well formed and every entry expires', () => {
      const file = path.resolve(process.cwd(), 'scripts/audit-exemptions.json');
      const { exemptions } = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const e of exemptions) {
        expect(e.advisory).toMatch(/^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/);
        expect(e.expires).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(e.reason.length).toBeGreaterThan(20);
      }
    });
  });

  it('unknown shape → fails closed', () => {
    const r = run({ AUDIT_STUB_RC: '2', AUDIT_STUB_STDOUT: 'garbage', AUDIT_STUB_STDERR: '' });
    expect(r.status).not.toBe(0);
    expect(r.stdout).toMatch(/failing closed/);
  });

  it('exit 0 without a real report is NOT treated as clean', () => {
    const r = run({ AUDIT_STUB_RC: '0', AUDIT_STUB_STDOUT: '', AUDIT_STUB_STDERR: '' });
    expect(r.status).not.toBe(0);
  });

  it('REAL npm against a dead registry → DID NOT RUN, not a failure (no stubs)', () => {
    const r = run({ npm_config_registry: 'http://127.0.0.1:9/', AUDIT_TIMEOUT: '60' }, [
      '--omit=dev',
    ]);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toMatch(/DID NOT RUN/);
  });
});

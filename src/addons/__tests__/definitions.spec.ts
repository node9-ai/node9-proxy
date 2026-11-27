// node9Firewall#342 (add-ons plan phase 4, check C): what the gateway's scan
// of tool definitions stored, and how it reaches the add-ons report.
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { collectAddons } from '../collect';
import { definitionsDir, readDefinitionScans, writeDefinitionScan } from '../definitions-file';
import { writeStanding } from '../standing-file';

const homes: string[] = [];
function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-definitions-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  homes.push(h);
  return h;
}
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

const KEY_A = 'a'.repeat(16);
const KEY_B = 'b'.repeat(16);
const AT = '2026-11-27T10:00:00.000Z';
const INJECTION = { rule: 'mcp.definition-injection', severity: 'high' as const };

describe('the stored definition scans', () => {
  // CodeQL js/file-system-race (release PR): one descriptor checks and reads,
  // and a link planted where the gateway writes its own file is not followed.
  it.skipIf(process.platform === 'win32')('does not follow a link in place of a record', () => {
    const h = home();
    writeDefinitionScan(KEY_A, { identity: 'npm:x', findings: [INJECTION], scannedAt: AT }, h);
    const file = path.join(definitionsDir(h), `${KEY_A}.json`);
    const elsewhere = path.join(h, 'elsewhere.json');
    fs.renameSync(file, elsewhere);
    fs.symlinkSync(elsewhere, file);
    expect(readDefinitionScans(h).size).toBe(0);
  });

  it('keeps one record per server and gives them back by identity', () => {
    const h = home();
    writeDefinitionScan(
      KEY_A,
      { identity: 'npm:@acme/db-mcp', findings: [INJECTION], scannedAt: AT },
      h
    );
    writeDefinitionScan(
      KEY_B,
      { identity: 'pypi:mcp-server-fetch', findings: [], scannedAt: AT },
      h
    );
    const scans = readDefinitionScans(h);
    expect(scans.get('npm:@acme/db-mcp')).toEqual({
      identity: 'npm:@acme/db-mcp',
      findings: [INJECTION],
      scannedAt: AT,
    });
    expect(scans.get('pypi:mcp-server-fetch')?.findings).toEqual([]);
  });

  it('joins two servers that run the same package, and keeps the newer time', () => {
    const h = home();
    const later = '2026-11-27T12:00:00.000Z';
    writeDefinitionScan(KEY_A, { identity: 'npm:x', findings: [INJECTION], scannedAt: AT }, h);
    writeDefinitionScan(
      KEY_B,
      {
        identity: 'npm:x',
        findings: [{ rule: 'mcp.definition-suspicious', severity: 'medium' }],
        scannedAt: later,
      },
      h
    );
    const rec = readDefinitionScans(h).get('npm:x')!;
    expect(rec.findings.map((f) => f.rule).sort()).toEqual([
      'mcp.definition-injection',
      'mcp.definition-suspicious',
    ]);
    expect(rec.scannedAt).toBe(later);
  });

  it('does not rewrite an unchanged verdict within the hour, and does after a change', () => {
    const h = home();
    const file = path.join(definitionsDir(h), `${KEY_A}.json`);
    writeDefinitionScan(KEY_A, { identity: 'npm:x', findings: [], scannedAt: AT }, h);
    const first = fs.readFileSync(file, 'utf8');
    writeDefinitionScan(
      KEY_A,
      { identity: 'npm:x', findings: [], scannedAt: '2026-11-27T10:20:00.000Z' },
      h
    );
    expect(fs.readFileSync(file, 'utf8')).toBe(first);
    writeDefinitionScan(
      KEY_A,
      { identity: 'npm:x', findings: [INJECTION], scannedAt: '2026-11-27T10:21:00.000Z' },
      h
    );
    expect(readDefinitionScans(h).get('npm:x')?.findings).toEqual([INJECTION]);
  });

  it('writes nothing for a key that is not a server key, and reads nothing from a bad file', () => {
    const h = home();
    writeDefinitionScan('../../evil', { identity: 'npm:x', findings: [], scannedAt: AT }, h);
    expect(fs.existsSync(definitionsDir(h))).toBe(false);
    fs.mkdirSync(definitionsDir(h), { recursive: true });
    fs.writeFileSync(path.join(definitionsDir(h), `${KEY_A}.json`), '{not json');
    fs.writeFileSync(
      path.join(definitionsDir(h), `${KEY_B}.json`),
      JSON.stringify({
        identity: 'npm:y',
        scannedAt: AT,
        findings: [
          INJECTION,
          { rule: 'has spaces', severity: 'high' },
          { rule: 'x', severity: 'low' },
        ],
      })
    );
    fs.writeFileSync(path.join(definitionsDir(h), 'notes.txt'), 'ignored');
    const scans = readDefinitionScans(h);
    expect([...scans.keys()]).toEqual(['npm:y']);
    expect(scans.get('npm:y')?.findings).toEqual([INJECTION]);
  });
});

describe('the add-ons report: which checks ran for a server', () => {
  function configured(h: string): void {
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({
        mcpServers: {
          // Through the gateway: its definitions are scanned.
          wrapped: {
            command: 'node9',
            args: ['mcp-gateway', '--config-name', 'wrapped', '--upstream', 'npx -y @acme/db-mcp'],
          },
          // The same package started directly by the agent: node9 never sees its catalog.
          direct: { command: 'npx', args: ['-y', '@acme/db-mcp'] },
          other: { command: 'npx', args: ['-y', '@acme/ok-mcp'] },
        },
      })
    );
  }

  it('lists `definitions` only for a server that runs through the gateway', () => {
    const h = home();
    configured(h);
    writeDefinitionScan(
      KEY_A,
      { identity: 'npm:@acme/db-mcp', findings: [INJECTION], scannedAt: AT },
      h
    );
    const byName = Object.fromEntries(collectAddons(h, {}).mcp.map((m) => [m.name, m]));
    expect(byName.wrapped.checks).toEqual(['definitions']);
    expect(byName.wrapped.findings).toEqual([INJECTION]);
    expect(byName.direct.checks).toBeUndefined();
    expect(byName.direct.findings).toBeUndefined();
    expect(byName.other.checks).toBeUndefined();
  });

  it('carries both checks and both sets of findings when both ran', () => {
    const h = home();
    configured(h);
    writeDefinitionScan(KEY_A, { identity: 'npm:@acme/db-mcp', findings: [], scannedAt: AT }, h);
    writeStanding(
      {
        v: 1,
        entries: {
          'npm:@acme/db-mcp': {
            findings: [{ rule: 'mcp.package-lookalike', severity: 'high' }],
            registry: true,
            checkedAt: AT,
          },
        },
      },
      h
    );
    const byName = Object.fromEntries(collectAddons(h, {}).mcp.map((m) => [m.name, m]));
    expect(byName.wrapped.checks).toEqual(['package', 'definitions']);
    expect(byName.wrapped.findings).toEqual([{ rule: 'mcp.package-lookalike', severity: 'high' }]);
    expect(byName.direct.checks).toEqual(['package']);
  });
});

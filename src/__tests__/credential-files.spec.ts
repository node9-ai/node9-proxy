// fw#408: blast and posture read ONE list of credential files, the gate covers
// every credential entry of it, and posture's advice matches the shield state
// and the mode.
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { homeCredentialFiles } from '../credential-files';
import { scanFilePath } from '../dlp';
import { checkSecrets } from '../posture/secrets';
import { annotateCoverage } from '../posture/enforcement';
import { _resetConfigCache } from '../config';
import type { CheckContext } from '../posture/types';

const home = () => os.homedir();

function plant(rel: string[]): string {
  const p = path.join(home(), ...rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, 'placeholder');
  return p;
}

function writeConfig(v2: Record<string, unknown>): void {
  fs.mkdirSync(path.join(home(), '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home(), '.node9', 'config.json'),
    JSON.stringify({ version: '2', ...v2 })
  );
  _resetConfigCache();
}

beforeEach(() => {
  for (const d of ['.ssh', '.aws', '.config', '.docker', '.node9'])
    fs.rmSync(path.join(home(), d), { recursive: true, force: true });
  for (const f of ['.netrc', '.npmrc']) fs.rmSync(path.join(home(), f), { force: true });
});

describe('one list of credential files', () => {
  it('holds both gcloud files and the token files blast already named', () => {
    const labels = homeCredentialFiles('/h').map((c) => c.label);
    expect(labels).toEqual(
      expect.arrayContaining([
        '~/.config/gcloud/credentials.db',
        '~/.config/gcloud/application_default_credentials.json',
        '~/.npmrc',
        '~/.netrc',
        '~/.docker/config.json',
        '~/.ssh/id_dsa',
      ])
    );
    for (const c of homeCredentialFiles('/h')) expect(c.full.startsWith('/h/')).toBe(true);
  });

  it('the DLP gate recognises a read of every credential entry but ~/.netrc', () => {
    // ~/.netrc is covered by the project-jail shield, not by the DLP path list
    // (whose four synced copies jail-both-doors.test.ts holds together). Widening
    // the live gate is its own change; this pins the gap so it cannot grow.
    const uncovered = homeCredentialFiles(home())
      .filter((c) => c.kind === 'credential')
      .filter((c) => scanFilePath(c.full) === null)
      .map((c) => c.label);
    expect(uncovered).toEqual(['~/.netrc']);
  });

  it('posture reports the files blast reports (both gcloud files, .npmrc)', () => {
    plant(['.config', 'gcloud', 'credentials.db']);
    plant(['.config', 'gcloud', 'application_default_credentials.json']);
    plant(['.npmrc']);
    plant(['.aws', 'config']);
    const ctx = { home: home(), cwd: home() } as CheckContext;
    const row = checkSecrets(ctx).find((f) => f.title.includes('credential file'));
    expect(row?.detail).toEqual(
      expect.arrayContaining([
        path.join('~', '.config', 'gcloud', 'credentials.db'),
        path.join('~', '.config', 'gcloud', 'application_default_credentials.json'),
        path.join('~', '.npmrc'),
      ])
    );
    // Account configuration is not key material.
    expect(row?.detail).not.toContain(path.join('~', '.aws', 'config'));
  });
});

describe('posture advice follows the state', () => {
  const ctx = () => ({ home: home(), cwd: home() }) as CheckContext;

  it('standard mode with no agent wired: the advice is not about the mode', async () => {
    plant(['.ssh', 'id_rsa']);
    writeConfig({ mode: 'standard' });
    const findings = checkSecrets(ctx());
    await annotateCoverage(findings, ctx());
    const row = findings.find((f) => f.title.includes('credential file'));
    expect(row?.fix).not.toContain('set mode to');
  });

  it('audit mode: the files are recognised, the advice is the mode, not the shield', async () => {
    plant(['.ssh', 'id_rsa']);
    writeConfig({ mode: 'audit' });
    const findings = checkSecrets(ctx());
    await annotateCoverage(findings, ctx());
    const row = findings.find((f) => f.title.includes('credential file'));
    expect(row?.coverage?.state).toBe('open');
    expect(row?.fix).not.toContain('shield enable project-jail');
    expect(row?.fix).toContain('audit mode');
    expect(row?.fix).toContain('standard');
    // The fix string ships to the dashboard: never a path in it.
    expect(row?.fix).not.toContain('.ssh');
  });
});

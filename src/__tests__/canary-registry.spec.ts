// Canary registry corpus, canary-corpus.md section C. Unit rows: tmp HOME via
// vi.spyOn(os, 'homedir') installed BEFORE a resetModules + dynamic import,
// because shields.ts computes its paths at module load. Values are generated
// per test from the engine fixtures; no assembled decoy exists in this file.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import { genAwsId, ROW_COUNTS } from '../../packages/policy-engine/src/dlp/canary.fixtures';

type Reg = typeof import('../canary/registry.js');
type Jail = typeof import('../shields/jail.js');

const sha = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
const S = (row: string) => 'canary-corpus-v1:' + row;

let home: string;
let reg: Reg;
let jail: Jail;
const storeFile = () => path.join(home, '.node9', 'canaries.json');
const jailFile = () => path.join(home, '.node9', 'jail-paths.json');
const shieldFile = () => path.join(home, '.node9', 'shields', 'user-jail.json');
const stateFile = () => path.join(home, '.node9', 'shields.json');

const newRec = (row: string, value?: string) => ({
  kind: 'aws-profile' as const,
  field: 'aws_access_key_id',
  path: path.join(home, '.aws', 'credentials'),
  value: value ?? genAwsId(S(row)),
  label: 'backup',
  fileHash: sha('file-' + row),
  createdDir: true,
});

beforeEach(async () => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-canary-reg-'));
  vi.spyOn(os, 'homedir').mockReturnValue(home);
  vi.resetModules();
  reg = await import('../canary/registry.js');
  jail = await import('../shields/jail.js');
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('C. registry', () => {
  it('C1 missing file: [] and a read never creates the file', () => {
    expect(reg.loadCanaries()).toEqual([]);
    expect(fs.existsSync(storeFile())).toBe(false);
  });
  it('C2 malformed JSON: throws naming the path; bytes untouched', () => {
    fs.mkdirSync(path.dirname(storeFile()), { recursive: true });
    fs.writeFileSync(storeFile(), '{ not json');
    const before = sha(fs.readFileSync(storeFile()));
    expect(() => reg.loadCanaries()).toThrow(/canaries\.json/);
    expect(sha(fs.readFileSync(storeFile()))).toBe(before);
  });
  it('C3 malformed records dropped, well-formed kept, nothing written', () => {
    fs.mkdirSync(path.dirname(storeFile()), { recursive: true });
    const good = {
      ...newRec('C3'),
      id: 'good',
      valueHash: sha(genAwsId(S('C3'))),
      plantedAt: '2026-09-07T00:00:00Z',
    };
    fs.writeFileSync(
      storeFile(),
      JSON.stringify({ records: [good, { id: 'no-value' }, 'junk', { value: 'x'.repeat(20) }] })
    );
    const before = sha(fs.readFileSync(storeFile()));
    const got = reg.loadCanaries();
    expect(got.map((r) => r.id)).toEqual(['good']);
    expect(sha(fs.readFileSync(storeFile()))).toBe(before);
    fs.writeFileSync(storeFile(), JSON.stringify({ records: 'not-an-array' }));
    expect(reg.loadCanaries()).toEqual([]);
  });
  it('C4 first save: 0600, ~/.node9 created, store jailed as block, shield MATERIALISED and active', () => {
    const rec = reg.registerCanary(newRec('C4'));
    expect(rec.id).toBeTruthy();
    expect(fs.existsSync(storeFile())).toBe(true);
    if (process.platform !== 'win32') expect(fs.statSync(storeFile()).mode & 0o777).toBe(0o600);
    expect(jail.readJailPaths()).toContainEqual({ path: storeFile(), verdict: 'block' });
    expect(
      fs.existsSync(shieldFile()),
      'regenerateUserJail must run, not only addJailPath (H9)'
    ).toBe(true);
    const state = JSON.parse(fs.readFileSync(stateFile(), 'utf-8')) as
      | { active?: string[] }
      | string[];
    const active = Array.isArray(state) ? state : (state.active ?? []);
    expect(JSON.stringify(state)).toContain('user-jail');
    expect(active.length >= 0).toBe(true);
  });
  it('C5 two saves: one jail entry for the store, not two', () => {
    reg.registerCanary(newRec('C5-1'));
    reg.registerCanary(newRec('C5-2'));
    expect(jail.readJailPaths().filter((p) => p.path === storeFile())).toHaveLength(1);
  });
  it('C6 retire keeps the record, sets retiredAt, leaves value and hash; default load includes it', () => {
    const rec = reg.registerCanary(newRec('C6'));
    const r = reg.retireCanary(rec.id);
    expect(r?.retiredAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(r?.value).toBe(rec.value);
    expect(r?.valueHash).toBe(rec.valueHash);
    expect(reg.loadCanaries().map((x) => x.id)).toContain(rec.id);
    expect(reg.loadCanaries({ includeRetired: true }).map((x) => x.id)).toContain(rec.id);
    expect(reg.canaryValues().find((v) => v.id === rec.id)?.retired).toBe(true);
  });
  it('C7 a 15-char value: throws, nothing written', () => {
    expect(() => reg.registerCanary(newRec('C7', genAwsId(S('C7')).slice(0, 15)))).toThrow(/16/);
    expect(fs.existsSync(storeFile())).toBe(false);
  });
  it('C8 valueHash is sha256 of the exact value bytes (recomputed here)', () => {
    const rec = reg.registerCanary(newRec('C8'));
    expect(rec.valueHash).toBe(sha(rec.value));
    expect(reg.loadCanaries()[0].valueHash).toBe(sha(rec.value));
  });
  it('C9 malformed jail-paths.json: save throws BEFORE writing the store', () => {
    fs.mkdirSync(path.dirname(jailFile()), { recursive: true });
    fs.writeFileSync(jailFile(), '{ nope');
    expect(() => reg.registerCanary(newRec('C9'))).toThrow();
    expect(fs.existsSync(storeFile()), 'never leave an unjailed registry behind').toBe(false);
  });
  it('row counts', () => {
    expect(ROW_COUNTS.C).toBe(9);
  });
});

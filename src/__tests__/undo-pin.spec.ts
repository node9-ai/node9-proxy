// The undo feature is removed: no input path may re-enable it.
//
// ⭐ R1 is the row that matters. An earlier version of this design put the pin
// inside `applyLayer` — the closure config/index.ts runs ONCE PER LAYER. That
// closure early-returns on a null layer, and a machine with no config file has
// no layers at all, so the pin never executed there. The merged value then came
// solely from DEFAULT_CONFIG, an unnamed second point that any later cleanup
// could delete without connecting it to this. R1 is the no-config case.
//
// HONESTY: R1 is GREEN today, because DEFAULT_CONFIG already supplies `false`.
// It is a regression guard, not a bug reproduction, and its proof is the
// mutation in doc/undo-removal-commit1-spec.md §3: remove DEFAULT_CONFIG's
// `enableUndo: false` and R1 must STAY GREEN. If it goes red, the pin is back
// inside the closure and this row is the only thing that will say so.
//
// Driven through the REAL merge (getConfig) with a temp HOME — no mocks. The
// four rows are the four ways a value can reach the flag: no file, global file,
// project file, and the byte shape the daemon's writeGlobalSetting produces.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { getConfig, _resetConfigCache } from '../config';
import { shouldSnapshot } from '../policy';
import { validateConfig, sanitizeConfig } from '../config-schema';

describe('undo removed — the flag cannot be turned on', () => {
  let tmpHome: string;
  let tmpProject: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-undo-pin-'));
    tmpProject = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-undo-proj-'));
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    _resetConfigCache();
  });

  afterEach(() => {
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    if (origUserprofile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = origUserprofile;
    _resetConfigCache();
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(tmpProject, { recursive: true, force: true });
  });

  // ── R1 ⭐ the row the first design did not have ───────────────────────────
  it('R1: a machine with NO config file at all merges to false', () => {
    expect(fs.existsSync(path.join(tmpHome, '.node9', 'config.json'))).toBe(false);
    expect(getConfig(tmpProject).settings.enableUndo).toBe(false);
  });

  // ── R2 — a stored `true` from before the removal ──────────────────────────
  it('R2: a global config with enableUndo:true still merges to false', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } }, null, 2)
    );
    _resetConfigCache();
    expect(getConfig(tmpProject).settings.enableUndo).toBe(false);
  });

  // ── R3 — the project layer ────────────────────────────────────────────────
  it('R3: a project node9.config.json with enableUndo:true merges to false', () => {
    fs.writeFileSync(
      path.join(tmpProject, 'node9.config.json'),
      JSON.stringify({ settings: { enableUndo: true } }, null, 2)
    );
    _resetConfigCache();
    expect(getConfig(tmpProject).settings.enableUndo).toBe(false);
  });

  // ── R4 — the daemon route, byte-for-byte ──────────────────────────────────
  // Not a paraphrase: this is exactly what writeGlobalSetting (daemon/state.ts:278)
  // produces — same serialisation, same 0600 mode. A test using a shape the real
  // writer never emits would prove nothing about the real writer.
  it('R4: the exact bytes writeGlobalSetting produces still merge to false', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } }, null, 2),
      { mode: 0o600 }
    );
    _resetConfigCache();
    expect(getConfig(tmpProject).settings.enableUndo).toBe(false);
  });

  // ── R5 — the gate that guards the PreToolUse write path ───────────────────
  it('R5: shouldSnapshot returns false even with enableUndo:true on disk', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } }, null, 2)
    );
    _resetConfigCache();
    const config = getConfig(tmpProject);
    expect(shouldSnapshot('Write', { file_path: '/tmp/x.ts' }, config)).toBe(false);
    expect(shouldSnapshot('Edit', { file_path: '/tmp/x.ts' }, config)).toBe(false);
    expect(shouldSnapshot('Bash', { command: 'echo hi' }, config)).toBe(false);
  });

  // ── R20 — the schema drops the field with NO error ────────────────────────
  // The first design kept `enableUndo` in the schema on the stated grounds that
  // removing it would turn an existing `"enableUndo": true` into a validation
  // error. That premise was false: the schema is a plain zod object with neither
  // .strict() nor .passthrough(), so it strips undeclared keys silently. This row
  // pins the real behaviour so the false premise cannot come back.
  it('R20: a stale enableUndo:true is stripped, not rejected', () => {
    const raw = { settings: { mode: 'strict', enableUndo: true } };
    expect(validateConfig(raw, '/tmp/config.json')).toBeNull();
    const { sanitized, error } = sanitizeConfig(raw);
    expect(error).toBeNull();
    const settings = (sanitized.settings ?? {}) as Record<string, unknown>;
    expect('enableUndo' in settings).toBe(false);
    // Control: the sanitizer is doing real work, not returning an empty object.
    expect(settings.mode).toBe('strict');
  });

  // ── Control ───────────────────────────────────────────────────────────────
  // Proves the harness actually drives the merge: a DIFFERENT setting written
  // the same way DOES come through. Without this row, every assertion above
  // would also pass against a getConfig that silently returned defaults.
  it('CONTROL: a neighbouring setting written the same way IS honoured', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { mode: 'audit', enableUndo: true } }, null, 2)
    );
    _resetConfigCache();
    const config = getConfig(tmpProject);
    expect(config.settings.mode).toBe('audit');
    expect(config.settings.enableUndo).toBe(false);
  });
});

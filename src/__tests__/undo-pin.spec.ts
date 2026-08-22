// The undo feature is removed: the flag is gone from the type, so there is
// nothing left to turn on.
//
// ⭐ What changed, and why this file shrank. The previous version proved AT
// RUNTIME that `settings.enableUndo` merged to `false` no matter which of four
// input paths supplied a `true` — that took a pin in getConfig plus a spec to
// guard the pin. The field has now been removed from the Settings type, and
// `tsc` will not compile a read or a write of a field that does not exist. The
// strongest rows in the old file became a compile-time guarantee and were
// deleted rather than kept as theatre.
//
// What is still worth asserting at runtime is the part the compiler cannot see:
// what happens to a `true` that is ALREADY SITTING in a user's config.json,
// written before the removal. That value crosses a JSON boundary, so no type
// stops it. These rows say it is dropped quietly rather than rejected loudly.
//
// Driven through the REAL merge (getConfig) with a temp HOME — no mocks.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { getConfig, _resetConfigCache } from '../config';
import { validateConfig, sanitizeConfig } from '../config-schema';

/** The merged settings, as a bag — the typed view no longer has the key at all. */
function mergedSettings(cwd: string): Record<string, unknown> {
  return getConfig(cwd).settings as unknown as Record<string, unknown>;
}

describe('undo removed — a stale flag on disk is dropped, not honoured', () => {
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

  // ── R1 — the field is absent, not false ───────────────────────────────────
  // `false` and "not there" are different claims. A `false` would mean the knob
  // still exists and is off, which is what every removed surface says it is not.
  it('R1: the merged config has no enableUndo key at all', () => {
    expect(fs.existsSync(path.join(tmpHome, '.node9', 'config.json'))).toBe(false);
    expect('enableUndo' in mergedSettings(tmpProject)).toBe(false);
  });

  // ── R2 — a stored `true` from before the removal, global layer ────────────
  it('R2: a global config with enableUndo:true does not put the key back', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } }, null, 2)
    );
    _resetConfigCache();
    expect('enableUndo' in mergedSettings(tmpProject)).toBe(false);
  });

  // ── R3 — the project layer ────────────────────────────────────────────────
  it('R3: a project node9.config.json with enableUndo:true does not either', () => {
    fs.writeFileSync(
      path.join(tmpProject, 'node9.config.json'),
      JSON.stringify({ settings: { enableUndo: true } }, null, 2)
    );
    _resetConfigCache();
    expect('enableUndo' in mergedSettings(tmpProject)).toBe(false);
  });

  // ── R4 — the daemon route, byte-for-byte ──────────────────────────────────
  // Not a paraphrase: this is exactly what writeGlobalSetting (daemon/state.ts)
  // produced before the key was dropped from POST /settings — same
  // serialisation, same 0600 mode. Machines carry that file today.
  it('R4: the exact bytes writeGlobalSetting produced are still dropped', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } }, null, 2),
      { mode: 0o600 }
    );
    _resetConfigCache();
    expect('enableUndo' in mergedSettings(tmpProject)).toBe(false);
  });

  // ── R5 — policy.snapshot went with it ─────────────────────────────────────
  it('R5: a stale policy.snapshot block does not survive the merge', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify(
        { policy: { snapshot: { tools: ['my_tool'], ignorePaths: ['x/**'] } } },
        null,
        2
      )
    );
    _resetConfigCache();
    const policy = getConfig(tmpProject).policy as unknown as Record<string, unknown>;
    expect('snapshot' in policy).toBe(false);
  });

  // ── R20 — the schema drops both fields with NO error ──────────────────────
  // An earlier design kept `enableUndo` in the schema on the stated grounds
  // that removing it would turn an existing `"enableUndo": true` into a
  // validation error. That premise was measured and found false: the schema is
  // a plain zod object with neither .strict() nor .passthrough(), so it strips
  // undeclared keys silently. This row pins the real behaviour so the false
  // premise cannot come back and re-add the field "for compatibility".
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
  // would also pass against a getConfig that silently returned defaults — and
  // an absence assertion is exactly the kind that passes for the wrong reason.
  it('CONTROL: a neighbouring setting written the same way IS honoured', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { mode: 'audit', enableUndo: true } }, null, 2)
    );
    _resetConfigCache();
    const s = mergedSettings(tmpProject);
    expect(s.mode).toBe('audit');
    expect('enableUndo' in s).toBe(false);
  });
});

// Regression test for scripts/check-extractor-version.mjs.
//
// The script gates CI: if detector source (canonical.ts / pii.ts /
// destructive-regex.ts) drifts from CANONICAL_EXTRACTOR_HASH without the
// dev bumping it, the watermark migration on the live daemon won't fire
// on user upgrade and findings stay frozen with the old detector — silent
// corruption. So the script's exit-code contract is itself load-bearing
// and worth pinning.
//
// Strategy: run the real script as a subprocess. Two cases:
//   1. Current state — hash matches source, expect exit 0 + ✓ message.
//   2. Drift simulation — copy the script + source files to a tmpdir,
//      mutate one source file, run from the tmpdir, expect exit 1 +
//      "mismatch" diagnostic.
//
// We don't shell out via execSync('npm run …') because that adds shell
// quoting complexity and obscures the failure mode. spawnSync directly.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const ROOT = path.resolve(__dirname, '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'check-extractor-version.mjs');
const SOURCE_FILES = [
  'packages/policy-engine/src/scan/canonical.ts',
  'packages/policy-engine/src/scan/pii.ts',
  'packages/policy-engine/src/scan/destructive-regex.ts',
];

describe('check-extractor-version.mjs', () => {
  it('exits 0 when CANONICAL_EXTRACTOR_HASH matches the source', () => {
    const r = spawnSync('node', [SCRIPT], { cwd: ROOT, encoding: 'utf-8' });
    expect(r.status).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/CANONICAL_EXTRACTOR_HASH matches/);
  });

  it('exits 1 when detector source drifts without a hash bump', () => {
    // Build a fixture mirror of the repo layout under a tmpdir, then
    // mutate one source file. The script's ROOT is computed relative to
    // its own __dirname, so we copy it into the fixture tree at the same
    // relative path it lives at in the real repo.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-hash-drift-'));
    try {
      // Recreate directory structure.
      const tmpScriptDir = path.join(tmp, 'scripts');
      fs.mkdirSync(tmpScriptDir, { recursive: true });
      fs.copyFileSync(SCRIPT, path.join(tmpScriptDir, 'check-extractor-version.mjs'));
      for (const rel of SOURCE_FILES) {
        const dest = path.join(tmp, rel);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.copyFileSync(path.join(ROOT, rel), dest);
      }
      // Establish baseline: in the fixture, run the script once (`--bump`)
      // so its embedded hash matches the copied sources. Without this the
      // script would just complain about the placeholder it inherited.
      const init = spawnSync(
        'node',
        [path.join(tmpScriptDir, 'check-extractor-version.mjs'), '--bump'],
        { cwd: tmp, encoding: 'utf-8' }
      );
      expect(init.status).toBe(0);

      // Now mutate one source file: append a comment line that survives
      // the script's strip filter (it doesn't strip arbitrary comments).
      const target = path.join(tmp, SOURCE_FILES[0]);
      fs.appendFileSync(target, '\n// drift sentinel for hash-check spec\n');

      // Re-run check (no --bump) — should fail.
      const r = spawnSync('node', [path.join(tmpScriptDir, 'check-extractor-version.mjs')], {
        cwd: tmp,
        encoding: 'utf-8',
      });
      expect(r.status).toBe(1);
      expect(r.stdout + r.stderr).toMatch(/mismatch/i);
      expect(r.stdout + r.stderr).toMatch(/bump-extractor-version/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('--bump updates the hash in canonical.ts (using a fixture so the real file is untouched)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-hash-bump-'));
    try {
      const tmpScriptDir = path.join(tmp, 'scripts');
      fs.mkdirSync(tmpScriptDir, { recursive: true });
      fs.copyFileSync(SCRIPT, path.join(tmpScriptDir, 'check-extractor-version.mjs'));
      for (const rel of SOURCE_FILES) {
        const dest = path.join(tmp, rel);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.copyFileSync(path.join(ROOT, rel), dest);
      }
      // Force the embedded hash to a known-wrong value, then run --bump.
      const canonical = path.join(tmp, SOURCE_FILES[0]);
      const before = fs.readFileSync(canonical, 'utf-8');
      const wrong = before.replace(
        /export const CANONICAL_EXTRACTOR_HASH = '[^']*';/,
        "export const CANONICAL_EXTRACTOR_HASH = 'wrong-on-purpose';"
      );
      fs.writeFileSync(canonical, wrong);

      const r = spawnSync(
        'node',
        [path.join(tmpScriptDir, 'check-extractor-version.mjs'), '--bump'],
        { cwd: tmp, encoding: 'utf-8' }
      );
      expect(r.status).toBe(0);
      const after = fs.readFileSync(canonical, 'utf-8');
      expect(after).toMatch(/CANONICAL_EXTRACTOR_HASH = '[a-f0-9]{16}'/);
      expect(after).not.toMatch(/wrong-on-purpose/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

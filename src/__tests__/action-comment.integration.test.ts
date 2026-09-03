import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import path from 'path';

// The GitHub Action's comment + fail-on gate logic lives in comment.js at the
// repo root: a plain-Node CommonJS script that action.yml runs with `node`,
// outside the TS build. Its pure-logic selftest (`node comment.js --selftest`)
// is the regression suite for the PR comment rendering and the severity gate.
// Run it as a subprocess so `npm test` fails when it fails.
describe('GitHub Action comment.js selftest', () => {
  it('exits 0', () => {
    const script = path.resolve(process.cwd(), 'comment.js');
    const r = spawnSync(process.execPath, [script, '--selftest'], { encoding: 'utf8' });
    expect(r.error).toBeUndefined();
    expect(r.status, `${r.stdout}\n${r.stderr}`).toBe(0);
  });
});

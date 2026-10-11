// Every test file runs with its own empty home directory. Before this, specs that call
// authorizeHeadless read the developer's real ~/.node9 (config, credentials, shields) and
// 124 of them failed on a developer machine while passing in CI, which has no ~/.node9.
// Modules that resolve ~/.node9 at import time must see the temporary home too.

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

describe('test home isolation', () => {
  it('os.homedir() is a fresh directory under the system temp dir', () => {
    expect(fs.realpathSync(os.homedir()).startsWith(fs.realpathSync(os.tmpdir()))).toBe(true);
  });

  it('the developer ~/.node9 is not visible', () => {
    expect(fs.existsSync(path.join(os.homedir(), '.node9', 'config.json'))).toBe(false);
    expect(fs.existsSync(path.join(os.homedir(), '.node9', 'credentials.json'))).toBe(false);
  });

  it('a fixture repository never resolves to the caller repository (GIT_DIR from a hook)', () => {
    for (const k of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR'])
      expect(process.env[k]).toBeUndefined();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-git-iso-'));
    execFileSync('git', ['-C', root, 'init', '-q'], { stdio: 'ignore' });
    const gitDir = execFileSync('git', ['-C', root, 'rev-parse', '--absolute-git-dir'], {
      encoding: 'utf8',
    }).trim();
    // `.native` on both sides: on Windows the temp dir can come back in its 8.3 short form
    // (RUNNER~1) from one call and the long form from another, and only the native resolver
    // expands it (CI on windows-latest failed on exactly that).
    expect(fs.realpathSync.native(gitDir)).toBe(fs.realpathSync.native(path.join(root, '.git')));
    fs.rmSync(root, { recursive: true, force: true });
  });
});

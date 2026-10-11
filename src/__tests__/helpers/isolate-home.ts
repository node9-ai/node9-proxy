// Vitest setup file: every test file runs with its own empty home directory and without the
// caller's git repository variables.
//
// Code under test reads ~/.node9 (config, credentials, shields, baselines) and ~/.claude, and
// several modules resolve those paths at import time. With the developer's real home, their
// config changed policy results (124 authorizeHeadless specs failed locally and passed in CI,
// which has no ~/.node9), and a spec that writes state could touch the real files. Setup files
// run before the test file is imported, so import-time paths see the temporary home as well.
// A test that needs a specific home still sets its own HOME for the subprocess it spawns.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterAll } from 'vitest';

// Git exports its repository variables to hooks. A suite run from the pre-commit hook inherited
// GIT_DIR, so a fixture's `git -C <tmp> init` / `git config user.name t` wrote into the REAL
// repository (on 2026-10-11 it set core.bare = true and user.name = t in .git/config). No test
// may see the caller's repository.
for (const k of Object.keys(process.env)) {
  if (
    /^GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|PREFIX|NAMESPACE|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|QUARANTINE_PATH|CONFIG|CONFIG_GLOBAL|CONFIG_SYSTEM|CONFIG_COUNT|CONFIG_PARAMETERS)$|^GIT_CONFIG_(KEY|VALUE)_\d+$/.test(
      k
    )
  )
    delete process.env[k];
}

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-test-home-'));
process.env.HOME = home;
process.env.USERPROFILE = home;
delete process.env.XDG_CONFIG_HOME;

afterAll(() => {
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch (err) {
    // A leftover temp dir is harmless; say so instead of failing the file.
    console.error(`isolate-home: could not remove ${home}: ${String(err)}`);
  }
});

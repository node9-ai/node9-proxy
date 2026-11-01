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
import { normalizeCommandForPolicy } from '@node9/policy-engine';

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

// The engine loads the mvdan-sh parser on its first parse (fw#425), through
// Node's module loader, which reads files with the same `fs` object many specs
// replace (`vi.spyOn(fs, 'readFileSync')`). Loaded inside such a spec, the
// parser would read the mock instead of its own source and every parse would
// fail. One parse here, before any spec installs a mock, loads it the way the
// eager import used to.
normalizeCommandForPolicy('true');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-test-home-'));
// Spawned node9 processes inherit this: Node compiles into a cache outside every
// test HOME, and the launcher (fw#425) leaves its own cache alone when the
// environment chose one. Specs that snapshot a whole HOME (canary plant D4,
// the keyed write guard) then see only what the command itself wrote.
// hook-startup.integration removes it on purpose to test the launcher's cache.
const compileCache = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-test-compile-cache-'));
process.env.NODE_COMPILE_CACHE = compileCache;
process.env.HOME = home;
process.env.USERPROFILE = home;
delete process.env.XDG_CONFIG_HOME;

afterAll(() => {
  try {
    fs.rmSync(compileCache, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  } catch (err) {
    // A leftover temp dir is harmless; say so instead of failing the file.
    console.error(`isolate-home: could not remove ${home}: ${String(err)}`);
  }
});

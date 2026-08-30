// Keyedness hygiene for subprocess-spawning tests (PR-2 matrix §0.12).
//
// A spawner that inherits `...process.env` verbatim inherits the DEVELOPER
// MACHINE'S real NODE9_API_KEY / NODE9_PROFILE / NODE9_API_URL — and once
// replace-mode lands, a keyed subprocess builds its policy from the cloud,
// silently flipping entire suites to a different config source depending on
// whose machine runs them. Four suites already deleted the key by hand;
// the rest leaked. ONE helper, no hand-rolled deletes.
//
// Keyed fixtures never come from the environment: a test that WANTS a keyed
// subprocess writes a `credentials.json` into its temp HOME (file-keyed —
// subprocess-safe and Windows-safe), via `writeKeyedHome` below.

import * as fs from 'fs';
import * as path from 'path';

/** process.env minus every keyedness channel. Overrides apply on top. */
export function keySafeEnv(
  overrides: Record<string, string | undefined> = {}
): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  delete env.NODE9_PROFILE;
  return { ...env, ...overrides };
}

/** Make a temp HOME keyed by FILE (the machine-wide channel): a test that
 *  wants a keyed subprocess opts in explicitly — never by inheritance. */
export function writeKeyedHome(
  home: string,
  opts: { apiKey?: string; apiUrl?: string; localOnly?: boolean } = {}
): void {
  const dir = path.join(home, '.node9');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'credentials.json'),
    JSON.stringify(
      {
        apiKey: opts.apiKey ?? 'n9_live_' + 'f'.repeat(40),
        apiUrl: opts.apiUrl ?? 'http://127.0.0.1:1', // unroutable — no network
        ...(opts.localOnly ? { localOnly: true } : {}),
      },
      null,
      2
    )
  );
}

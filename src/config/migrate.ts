// src/config/migrate.ts
// Move ~/.node9/config.json from the legacy shape to v2, once, with a backup.
//
// Runs automatically the first time a CLI command or the daemon starts after
// an upgrade, never from the hooks (they run on every tool call, in parallel;
// two migrations at once would race on the file). Writes only what departs
// from the shipped defaults, keeps the old file as a dated backup, prints one
// line, and `--undo` puts the backup back. A failure leaves the old file in
// place and is recorded in hook-debug.log; node9 keeps reading the legacy
// shape, so nothing is lost.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { atomicWriteSync } from '../utils/atomic-write';
import { isV2File, legacyToV2, type LegacyFile } from './v2';
import { globalConfigPath, rewriteAsV2 } from './write';
import { getCredentials } from './index';

export type MigrateOutcome =
  | { status: 'migrated'; backup: string; written: Record<string, unknown> }
  | { status: 'already-v2' }
  | { status: 'no-file' }
  | { status: 'dry-run'; wouldWrite: Record<string, unknown> }
  | { status: 'failed'; error: string };

export interface MigrateOptions {
  filePath?: string;
  dryRun?: boolean;
}

function backupPath(filePath: string): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${filePath}.bak-${stamp}`;
}

/** Migrate one file. Idempotent: a v2 file is left alone. */
export function migrateConfigFile(options: MigrateOptions = {}): MigrateOutcome {
  const filePath = options.filePath ?? globalConfigPath();
  if (options.dryRun) {
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'no-file' };
      return { status: 'failed', error: `cannot read ${filePath}: ${(err as Error).message}` };
    }
    if (isV2File(raw)) return { status: 'already-v2' };
    if (!raw || typeof raw !== 'object' || Array.isArray(raw))
      return { status: 'failed', error: `${filePath} is not a JSON object` };
    return {
      status: 'dry-run',
      wouldWrite: legacyToV2(raw as LegacyFile) as unknown as Record<string, unknown>,
    };
  }
  try {
    const r = rewriteAsV2(filePath, backupPath(filePath));
    if (r.status === 'rewritten')
      return { status: 'migrated', backup: r.backup, written: r.written };
    return r;
  } catch (err) {
    return { status: 'failed', error: (err as Error).message };
  }
}

/** Put the newest backup back in place of the current file. */
export function undoMigration(filePath: string = globalConfigPath()): { restored: string } | null {
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  const backups = fs
    .readdirSync(dir)
    .filter((f) => f.startsWith(`${base}.bak-`))
    .sort();
  const newest = backups.at(-1);
  if (!newest) return null;
  const from = path.join(dir, newest);
  atomicWriteSync(filePath, fs.readFileSync(from, 'utf8'), { mode: 0o600 });
  fs.unlinkSync(from);
  return { restored: from };
}

/**
 * The automatic, once-after-upgrade run. Quiet unless it migrated (one line
 * to stderr, so stdout stays clean for commands that print JSON) or failed
 * (a breadcrumb in hook-debug.log). Never throws.
 */
export function autoMigrateLocalConfig(): MigrateOutcome | null {
  if (process.env.NODE9_NO_CONFIG_MIGRATE === '1') return null;
  // Under the test runner a spawned CLI that forgot to point HOME at a temp
  // directory would rewrite the developer's real ~/.node9/config.json (it did,
  // once). Tests that exercise the migration opt in explicitly.
  if (process.env.NODE9_TESTING === '1' && process.env.NODE9_TEST_CONFIG_MIGRATE !== '1')
    return null;
  try {
    // A keyed machine's local file has no say over policy, and a keyed
    // command that refuses a write must leave every local store untouched.
    // It migrates after `node9 logout`, on the next command.
    const creds = getCredentials();
    if (creds?.apiKey && creds.localOnly !== true) return null;
    const outcome = migrateConfigFile();
    if (outcome.status === 'migrated') {
      process.stderr.write(
        `node9: your configuration was moved to the new format (backup: ${outcome.backup}). ` +
          `Run \`node9 checks\` to see it.\n`
      );
    } else if (outcome.status === 'failed') {
      try {
        fs.appendFileSync(
          path.join(os.homedir(), '.node9', 'hook-debug.log'),
          `[${new Date().toISOString()}] config migrate failed: ${outcome.error}\n`
        );
      } catch {
        /* best effort */
      }
    }
    return outcome;
  } catch (err) {
    return { status: 'failed', error: (err as Error).message };
  }
}

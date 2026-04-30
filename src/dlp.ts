// src/dlp.ts
// Thin host wrapper over @node9/policy-engine's DLP module.
//
// Most of the DLP logic (patterns, scanArgs, scanText, redactText,
// matchSensitivePath) is pure and lives in the engine. This file only
// keeps the I/O wrapper for scanFilePath, which resolves symlinks via
// fs.realpathSync.native — that's the only filesystem touch in the
// scanner pipeline and the reason it can't be in the engine.

import fs from 'fs';
import path from 'path';
import { matchSensitivePath, sensitivePathMatch, type DlpMatch } from '@node9/policy-engine';

// Re-exports so existing import paths (`from '../dlp'`) keep working.
export type { DlpMatch } from '@node9/policy-engine';
export { DLP_PATTERNS, scanArgs, scanText, redactText } from '@node9/policy-engine';

/**
 * Checks whether a file path argument targets a sensitive credential file.
 * Resolves symlinks (if the file exists) before checking, to prevent symlink
 * escape attacks where a safe-looking path points to a protected file.
 *
 * Returns a DlpMatch if the path is sensitive, null if clean.
 */
export function scanFilePath(filePath: string, cwd = process.cwd()): DlpMatch | null {
  if (!filePath) return null;

  let resolved: string;
  try {
    const absolute = path.resolve(cwd, filePath);
    // Call native() unconditionally — no existsSync pre-check.
    // Skipping existsSync eliminates the TOCTOU window between the check and
    // the native() call. Missing files throw ENOENT, which is caught below and
    // treated as unresolvable (safe — a non-existent file can't be read).
    resolved = fs.realpathSync.native(absolute);
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      // File doesn't exist yet (e.g. new file being written) — use raw path.
      // A non-existent file can't be a symlink, so no symlink escape is possible.
      resolved = path.resolve(cwd, filePath);
    } else {
      // Any other error (EACCES, unexpected throw, possible TOCTOU remnant) —
      // fail-closed: block rather than risk allowing a sensitive file.
      return sensitivePathMatch(filePath);
    }
  }

  return matchSensitivePath(resolved, filePath);
}

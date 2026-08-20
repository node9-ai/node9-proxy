// src/shields/jail.ts
// User-extensible credential jail. A `~/.node9/jail-paths.json` store of paths
// the user wants protected, materialized into a `user-jail` shield (block/review
// reads) via the shared shield builder. Reuses buildShield + installShield + the
// active-shield list — no @node9/policy-engine change.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { buildShield, pathMatchesFragment, pathToRegexFragment } from './build';
import { validateRegex } from '@node9/policy-engine';
import {
  installShield,
  readActiveShields,
  writeActiveShields,
  USER_SHIELDS_DIR_PATH,
} from '../shields';

export const USER_JAIL_SHIELD = 'user-jail';

export type JailVerdict = 'block' | 'review';
export interface JailPath {
  path: string;
  verdict: JailVerdict;
}

function jailStorePath(): string {
  return path.join(os.homedir(), '.node9', 'jail-paths.json');
}

/** Read the jail-paths store. Missing → []. Malformed → throw (never clobber). */
export function readJailPaths(): JailPath[] {
  let text: string;
  try {
    text = fs.readFileSync(jailStorePath(), 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  let parsed: { paths?: unknown };
  try {
    parsed = JSON.parse(text) as { paths?: unknown };
  } catch {
    throw new Error(`${jailStorePath()} is not valid JSON — fix it before changing the jail.`);
  }
  if (!Array.isArray(parsed.paths)) return [];
  return parsed.paths.filter(
    (p): p is JailPath =>
      !!p &&
      typeof (p as JailPath).path === 'string' &&
      ((p as JailPath).verdict === 'block' || (p as JailPath).verdict === 'review')
  );
}

export function writeJailPaths(paths: JailPath[]): void {
  const p = jailStorePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify({ paths }, null, 2) + '\n', { mode: 0o600 });
}

/**
 * Add or update a path's verdict (dedup by exact stored string). Returns the new
 * list. Throws on an over-broad path (`~`, `/`, `$HOME`) that yields no usable
 * match fragment — such a path would silently produce a 0-rule, no-op shield.
 */
export function addJailPath(rawPath: string, verdict: JailVerdict): JailPath[] {
  const norm = rawPath.trim();
  const fragment = pathToRegexFragment(norm);
  if (!fragment) {
    throw new Error(
      `"${rawPath}" is too broad to jail — give a specific path (e.g. ~/.gmail-mcp), not a home or root directory.`
    );
  }
  // The engine is the arbiter of what a rule may contain. A fragment it
  // rejects (e.g. over its regex length cap) would install a rule that
  // SILENTLY allows while `jail add` prints "reads now BLOCK" — the Windows
  // fail-open of 2026-08-19. Refuse loudly instead of lying quietly.
  const rejection = validateRegex(fragment);
  if (rejection !== null) {
    throw new Error(
      `"${rawPath}" cannot be jailed: the generated match pattern was rejected by the policy engine (${rejection}). Try a shorter or more specific path.`
    );
  }
  const next = [...readJailPaths().filter((p) => p.path !== norm), { path: norm, verdict }];
  writeJailPaths(next);
  return next;
}

/**
 * Does a candidate string (a file_path / path / pattern arg from a file tool)
 * hit a jailed path? Uses the SAME regex fragment the shield rules embed, so
 * the orchestrator's fast-path guard and the policy engine can never disagree
 * about what counts as jailed (task #20). Returns the matching entry (its
 * verdict decides block vs review) or null.
 */
export function findJailedPath(candidate: string): JailPath | null {
  return findJailedPathIn(candidate, readJailPaths());
}

/**
 * Same match, against an explicit list — used for the ORG-managed jail
 * (config.policy.managedJailPaths), which has no local store. Task #22: the
 * managed route reintroduced task #20's file-tool bypass because the guard
 * could only see the local store; both now go through this one matcher.
 */
export function findJailedPathIn(candidate: string, paths: JailPath[]): JailPath | null {
  if (!candidate) return null;
  for (const entry of paths) {
    if (pathMatchesFragment(candidate, entry.path)) return entry;
  }
  return null;
}

/** Remove a path (exact match). Returns whether it was present + the new list. */
export function removeJailPath(rawPath: string): { removed: boolean; paths: JailPath[] } {
  const norm = rawPath.trim();
  const before = readJailPaths();
  const after = before.filter((p) => p.path !== norm);
  const removed = after.length !== before.length;
  if (removed) writeJailPaths(after);
  return { removed, paths: after };
}

/**
 * Materialize the user-jail shield from the current store. Non-empty → (re)write
 * the shield and ensure it's enabled. Empty → disable + delete it (the builder
 * rejects a 0-rule shield, so we must not route an empty store through it).
 */
export function regenerateUserJail(paths: JailPath[]): void {
  const file = path.join(USER_SHIELDS_DIR_PATH, `${USER_JAIL_SHIELD}.json`);

  if (paths.length === 0) {
    const active = readActiveShields();
    if (active.includes(USER_JAIL_SHIELD)) {
      writeActiveShields(active.filter((s) => s !== USER_JAIL_SHIELD));
    }
    try {
      fs.rmSync(file, { force: true });
    } catch {
      /* best-effort cleanup */
    }
    return;
  }

  const def = buildShield({
    name: USER_JAIL_SHIELD,
    description: 'User-added credential jail paths (node9 jail add)',
    blockPaths: paths.filter((p) => p.verdict === 'block').map((p) => p.path),
    reviewPaths: paths.filter((p) => p.verdict === 'review').map((p) => p.path),
  });
  installShield(USER_JAIL_SHIELD, def); // atomic write; same name → overwrite
  const active = readActiveShields();
  if (!active.includes(USER_JAIL_SHIELD)) writeActiveShields([...active, USER_JAIL_SHIELD]);
}

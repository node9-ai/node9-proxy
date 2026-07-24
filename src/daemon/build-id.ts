// src/daemon/build-id.ts
// Build identity for the daemon (task #18 — rogue/stale daemon).
//
// A daemon must be able to say WHICH build it is running, so that startup
// takeover, `node9 doctor`, and `node9 daemon restart` can distinguish "the
// code on disk" from "the code actually serving :7391". Identity is
// `version` (package.json) tie-broken by the mtime of the running entry file
// (dist/cli.js) — two dev rebuilds of the same version differ by mtime.
//
// CAPTURE-AT-START INVARIANT (G3 in rogue-daemon-code-design.md): consumers
// use the module-load CURRENT_BUILD constant, never a fresh stat. A lazy stat
// reads the file AS IT IS NOW — a daemon that loaded code at 14:09 would stat
// the 14:26-rebuilt dist and misreport itself as the newest build, so a
// takeover for a same-version rebuild would never fire.
//
// npm-install caveat: published-tarball mtimes are epoch-fixed by `npm pack`,
// so the mtime tie-break carries real signal only for locally-built dists; on
// npm-installed machines the semver compare does all the work.

import fs from 'fs';
import path from 'path';

export interface BuildId {
  version: string;
  mtimeMs: number;
}

/** Read this build's version from package.json. Works both bundled (dist/
 *  cli.js → ../package.json) and unbundled under vitest (src/daemon/ →
 *  ../../package.json). '0.0.0' when neither resolves — never throws. */
function readOwnVersion(): string {
  for (const rel of ['../package.json', '../../package.json']) {
    try {
      const raw = fs.readFileSync(path.join(__dirname, rel), 'utf-8');
      const v = (JSON.parse(raw) as { version?: unknown }).version;
      if (typeof v === 'string' && v.length > 0) return v;
    } catch {
      /* try the next candidate */
    }
  }
  return '0.0.0';
}

/** Compute a build id for an entry file (default: the running entry).
 *  mtimeMs is 0 when the entry can't be stat'd — version still compares. */
export function computeBuildId(entry: string = process.argv[1] ?? ''): BuildId {
  let mtimeMs = 0;
  try {
    if (entry) mtimeMs = fs.statSync(entry).mtimeMs;
  } catch {
    /* unknown entry (REPL, deleted file) — version alone identifies */
  }
  return { version: readOwnVersion(), mtimeMs };
}

/** `1.63.0+1753357612975` — for pidfile / /health / logs. */
export function buildIdString(b: BuildId): string {
  return `${b.version}+${Math.round(b.mtimeMs)}`;
}

/** Inverse of buildIdString. null on anything malformed — callers treat an
 *  unparseable peer as "cannot compare" and yield, never guess. */
export function parseBuildId(s: unknown): BuildId | null {
  if (typeof s !== 'string') return null;
  const at = s.lastIndexOf('+');
  if (at <= 0) return null;
  const version = s.slice(0, at);
  const mtimeMs = Number(s.slice(at + 1));
  if (!/^\d+(\.\d+){2}/.test(version) || !Number.isFinite(mtimeMs) || mtimeMs < 0) return null;
  return { version, mtimeMs };
}

/** Numeric x.y.z compare; prerelease/build suffixes beyond the third numeric
 *  part are ignored (this repo releases plain semver). Unparseable parts
 *  compare as 0 so a malformed peer can never win a takeover. */
function compareVersion(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** >0 ⇒ a is STRICTLY newer than b. Version dominates; mtime only breaks a
 *  version tie. Strict total order — the takeover rule `compareBuild(mine,
 *  holder) > 0` can never make two builds each think they're newer. */
export function compareBuild(a: BuildId, b: BuildId): number {
  const v = compareVersion(a.version, b.version);
  if (v !== 0) return v;
  return a.mtimeMs - b.mtimeMs;
}

/** Doctor/status drift line. `running` is the daemon's /health answer:
 *  - null → daemon not reachable (no drift statement possible) → null
 *  - 'no-health' → a daemon is serving but doesn't implement /health; since
 *    THIS (installed) build does, the runner is provably older → drift.
 *  - health with a buildId → drift iff it differs from the installed build.
 *  Pure — no I/O — so it is unit-testable. */
export function describeBuildDrift(
  running: { version?: unknown; buildId?: unknown } | 'no-health' | null,
  installed: BuildId
): string | null {
  const mine = buildIdString(installed);
  if (running === null) return null;
  if (running === 'no-health') {
    return `running daemon predates the installed build (no /health — older than v${installed.version}) — it is enforcing OLD code`;
  }
  const theirs = typeof running.buildId === 'string' ? running.buildId : null;
  if (!theirs || theirs === mine) return null;
  const theirVersion = typeof running.version === 'string' ? running.version : 'unknown';
  return `running daemon is v${theirVersion} (build ${theirs}) but installed is v${installed.version} (build ${mine}) — it is enforcing a different build`;
}

/** The identity of THIS process's build, captured once at module load (G3).
 *  NODE9_BUILD_ID_OVERRIDE ("1.63.0+2000") lets integration tests fabricate
 *  older/newer builds without touching files. Env is trusted (same trust
 *  class as NODE9_MODE et al. — an attacker who sets our env owns the box). */
export const CURRENT_BUILD: BuildId =
  parseBuildId(process.env.NODE9_BUILD_ID_OVERRIDE) ?? computeBuildId();

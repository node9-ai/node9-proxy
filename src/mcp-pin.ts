// src/mcp-pin.ts
// MCP tool pinning — rug pull defense.
// Records SHA-256 hashes of MCP server tool definitions on first use.
// On subsequent connections, compares hashes and blocks if tools changed.
//
// Storage: ~/.node9/mcp-pins.json (atomic writes, mode 0o600)
// Pattern: follows shields.ts for file I/O conventions.

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PinEntry {
  /** Human-readable label (the upstream command that was pinned) */
  label: string;
  /** SHA-256 hex hash of the canonicalized tool definitions */
  toolsHash: string;
  /** Tool names at the time of pinning (for display purposes) */
  toolNames: string[];
  /** Number of tools at the time of pinning */
  toolCount: number;
  /** ISO 8601 timestamp of when the pin was created */
  pinnedAt: string;
  /** ISO 8601 timestamp of when the reconciler last saw this server in agent configs */
  lastSeen?: string;
}

export interface PinsFile {
  servers: Record<string, PinEntry>;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** Home pin file — always `~/.node9/mcp-pins.json`. The fallback / personal source. */
function getHomePinsFilePath(): string {
  return path.join(os.homedir(), '.node9', 'mcp-pins.json');
}

/** Backward-compat alias for callers that don't care about repo-local lookup. */
function getPinsFilePath(): string {
  return getHomePinsFilePath();
}

/**
 * Find the pin file to read from, given a starting cwd (#179 part 2).
 * Walks up from `cwd` looking for a `.node9/mcp-pins.json` in any ancestor,
 * stopping at the user's home dir (so we never escape into `/` and never
 * treat `~` itself as a repo root). If nothing is found, returns the home
 * pin file path.
 *
 * Returns `{ path, source }` so callers can render hints like `[repo]` /
 * `[home]` in CLI output without re-deriving the source.
 */
export function findPinsFilePath(cwd?: string): { path: string; source: 'repo' | 'home' } {
  const homeDir = os.homedir();
  const homePath = getHomePinsFilePath();
  let current = path.resolve(cwd ?? process.cwd());

  while (true) {
    if (current === homeDir) break; // don't escape past or into ~
    const candidate = path.join(current, '.node9', 'mcp-pins.json');
    if (fs.existsSync(candidate)) {
      return { path: candidate, source: 'repo' };
    }
    const next = path.dirname(current);
    if (next === current) break; // filesystem root
    current = next;
  }
  return { path: homePath, source: 'home' };
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 hash of an array of MCP tool definitions.
 * Tools are sorted by name before hashing so order does not matter.
 */
export function hashToolDefinitions(tools: unknown[]): string {
  const sorted = [...tools].sort((a, b) => {
    const nameA = (a as { name?: string }).name ?? '';
    const nameB = (b as { name?: string }).name ?? '';
    return nameA.localeCompare(nameB);
  });
  const canonical = JSON.stringify(sorted);
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

/**
 * Derive a short server key from the upstream command string.
 * Returns the first 16 hex chars of the SHA-256 hash.
 */
export function getServerKey(upstreamCommand: string): string {
  return crypto.createHash('sha256').update(upstreamCommand).digest('hex').slice(0, 16);
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

export type PinsReadResult =
  | { ok: true; pins: PinsFile }
  | { ok: false; reason: 'missing' }
  | { ok: false; reason: 'corrupt'; detail: string };

/** Read a single pin file at `filePath`. Pure / path-agnostic. */
function readPinsFile(filePath: string): PinsReadResult {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    if (!raw.trim()) {
      return { ok: false, reason: 'corrupt', detail: 'empty file' };
    }
    const parsed = JSON.parse(raw) as Partial<PinsFile>;
    if (!parsed.servers || typeof parsed.servers !== 'object' || Array.isArray(parsed.servers)) {
      return { ok: false, reason: 'corrupt', detail: 'invalid structure: missing servers object' };
    }
    return { ok: true, pins: { servers: parsed.servers } };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { ok: false, reason: 'missing' };
    }
    return { ok: false, reason: 'corrupt', detail: String(err) };
  }
}

/**
 * Read the home pin file with explicit error reporting.
 * - File missing (ENOENT): returns `{ ok: false, reason: 'missing' }`.
 * - File corrupt / unreadable: returns `{ ok: false, reason: 'corrupt' }`.
 * - File valid: returns `{ ok: true, pins }`.
 *
 * Note: this reads ONLY the home file. For repo-aware reads (#179), use
 * `findPinsFilePath` + `readPinsFile`, or `checkPin(... , cwd)`.
 */
export function readMcpPinsSafe(): PinsReadResult {
  return readPinsFile(getHomePinsFilePath());
}

/** Read the home pin registry. Returns empty servers on missing file. Throws on corrupt. */
export function readMcpPins(): PinsFile {
  const result = readMcpPinsSafe();
  if (result.ok) return result.pins;
  if (result.reason === 'missing') return { servers: {} };
  throw new Error(`[node9] MCP pin file is corrupt: ${result.detail}`);
}

/** Atomic write to an arbitrary pin file path. Used by both home writes and `promotePin`. */
function writePinsFile(filePath: string, data: PinsFile): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  // Home file holds personal trust state — chmod 0600. Repo files are
  // committed to git and don't need exclusive permissions; let the user's
  // umask govern.
  const isHome = filePath === getHomePinsFilePath();
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), isHome ? { mode: 0o600 } : {});
  fs.renameSync(tmp, filePath);
}

/** Atomic write of the home pin registry. */
export function writeMcpPins(data: PinsFile): void {
  writePinsFile(getHomePinsFilePath(), data);
}

/**
 * Seed an empty pin registry at ~/.node9/mcp-pins.json if it doesn't exist.
 * Called from agent setup paths (#179) so a fresh install distinguishes
 * "never installed" from "installed but no pins yet" — tooling that asserts
 * pin presence can now treat a missing file as "node9 install was never
 * run", separate from "no MCP server has been pinned yet".
 *
 * Idempotent: no-op when the file already exists.
 */
export function seedMcpPinsIfMissing(): void {
  const filePath = getPinsFilePath();
  if (fs.existsSync(filePath)) return;
  writeMcpPins({ servers: {} });
}

// ---------------------------------------------------------------------------
// Pin operations
// ---------------------------------------------------------------------------

/**
 * Check whether a server's tool definitions match the pinned hash.
 *
 * When `cwd` is provided and the call resolves a repo-local pin file via
 * `findPinsFilePath`, both files are consulted with **per-server merge**
 * semantics (#179):
 *   - if the repo file has an entry for `serverKey`, that wins
 *   - otherwise, the home file's entry is used
 *   - if neither has it, returns 'new'
 *
 * Returns:
 *   'new'      — no pin exists for this server in either file
 *   'match'    — winning entry's hash matches the current hash
 *   'mismatch' — winning entry's hash differs (possible rug pull)
 *   'corrupt'  — the resolved file (or repo file, when present) is unreadable
 */
export function checkPin(
  serverKey: string,
  currentHash: string,
  cwd?: string
): 'match' | 'mismatch' | 'new' | 'corrupt' {
  const found = findPinsFilePath(cwd);

  // Repo entry (if a repo file is in play).
  let repoEntry: PinEntry | undefined;
  if (found.source === 'repo') {
    const repoResult = readPinsFile(found.path);
    if (!repoResult.ok) {
      // Repo file present-then-gone is suspicious — could be a benign
      // concurrent `rm`, could be an attacker racing the existsSync ↔
      // readFileSync window to slip past the pin check. Either way we
      // refuse to evaluate rather than silently fall back to home
      // (which may be more permissive). Fail closed on both 'corrupt'
      // and 'missing'.
      return 'corrupt';
    }
    repoEntry = repoResult.pins.servers[serverKey];
  }
  if (repoEntry) {
    return repoEntry.toolsHash === currentHash ? 'match' : 'mismatch';
  }

  // Fall back to home for servers the repo file doesn't pin.
  const homeResult = readPinsFile(getHomePinsFilePath());
  if (!homeResult.ok) {
    if (homeResult.reason === 'missing') return 'new';
    return 'corrupt';
  }
  const homeEntry = homeResult.pins.servers[serverKey];
  if (!homeEntry) return 'new';
  return homeEntry.toolsHash === currentHash ? 'match' : 'mismatch';
}

/** Save or overwrite a pin for a server. */
export function updatePin(
  serverKey: string,
  label: string,
  toolsHash: string,
  toolNames: string[]
): void {
  const pins = readMcpPins();
  pins.servers[serverKey] = {
    label,
    toolsHash,
    toolNames,
    toolCount: toolNames.length,
    pinnedAt: new Date().toISOString(),
  };
  writeMcpPins(pins);
}

/** Remove a single server's pin. */
export function removePin(serverKey: string): void {
  const pins = readMcpPins();
  delete pins.servers[serverKey];
  writeMcpPins(pins);
}

/** Clear all pins (fresh start). */
export function clearAllPins(): void {
  writeMcpPins({ servers: {} });
}

/**
 * Promote a pin from `~/.node9/mcp-pins.json` into the repo-local pin file
 * at `<cwd-ancestor>/.node9/mcp-pins.json` (#179 part 2).
 *
 * - If a repo pin file exists in any ancestor of `cwd`, write into that one.
 * - If no repo pin file is found, create `<cwd>/.node9/mcp-pins.json` with
 *   just this entry (auto-create on first promote).
 * - Throws if the server isn't pinned in home.
 * - Throws if the resolved repo file is corrupt.
 *
 * Does NOT auto-commit the result to git; the user is expected to review +
 * commit the change as part of their normal workflow.
 */
export function promotePin(
  serverKey: string,
  cwd?: string
): { repoPath: string; created: boolean } {
  const homePins = readMcpPins(); // throws if home is corrupt
  const homeEntry = homePins.servers[serverKey];
  if (!homeEntry) {
    throw new Error(
      `[node9] Server "${serverKey}" is not pinned in ~/.node9/mcp-pins.json. ` +
        `Run \`node9 mcp pin list\` to see what's pinned.`
    );
  }

  const found = findPinsFilePath(cwd);
  let repoPath: string;
  let repoPins: PinsFile;
  let created = false;

  if (found.source === 'repo') {
    repoPath = found.path;
    const result = readPinsFile(repoPath);
    if (!result.ok) {
      const detail = result.reason === 'corrupt' ? result.detail : 'missing';
      throw new Error(`[node9] Repo pin file at ${repoPath} is unreadable: ${detail}`);
    }
    repoPins = result.pins;
  } else {
    // No repo file in any ancestor — auto-create at the supplied cwd.
    repoPath = path.join(cwd ?? process.cwd(), '.node9', 'mcp-pins.json');
    repoPins = { servers: {} };
    created = true;
  }

  repoPins.servers[serverKey] = { ...homeEntry };
  writePinsFile(repoPath, repoPins);
  return { repoPath, created };
}

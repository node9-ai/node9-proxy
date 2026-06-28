// src/auth/egress-config.ts
// Shared egress-config read/merge/write. Used by BOTH the `node9 egress` CLI
// (src/cli/commands/egress.ts) and the node9 MCP egress tools (src/mcp-server)
// so the allowlist is mutated through exactly one path.
//
// We touch only policy.egress in ~/.node9/config.json (an arbitrary JSON bag) and
// REFUSE to write over a config we couldn't parse — silently overwriting would
// destroy the user's other settings.

import fs from 'fs';
import os from 'os';
import path from 'path';

export type EgressMode = 'off' | 'review' | 'block';

export interface EgressBlock {
  enabled: boolean;
  mode: EgressMode;
  allow: string[];
  deny: string[];
  allowPrivate: boolean;
}

export const DEFAULT_EGRESS: EgressBlock = {
  enabled: false,
  mode: 'review',
  allow: [],
  deny: [],
  allowPrivate: true,
};

// The on-disk config is an arbitrary JSON bag; we only ever touch policy.egress.
type RawConfig = { policy?: Record<string, unknown>; [key: string]: unknown };

export function egressConfigPath(): string {
  return path.join(os.homedir(), '.node9', 'config.json');
}

/**
 * Read the raw config. A MISSING file → fresh `{}` (fine). A file that EXISTS
 * but isn't valid JSON → throw — we must never overwrite a config we couldn't
 * parse (that would silently destroy the user's other settings).
 */
export function readEgressRawConfig(): RawConfig {
  let text: string;
  try {
    text = fs.readFileSync(egressConfigPath(), 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw err; // permission/other read error — don't silently clobber
  }
  try {
    return JSON.parse(text) as RawConfig;
  } catch {
    throw new Error(
      `${egressConfigPath()} is not valid JSON — fix it before changing egress (refusing to overwrite).`
    );
  }
}

export function writeEgressRawConfig(config: RawConfig): void {
  const p = egressConfigPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

/**
 * Pure: apply a change to the egress block of a raw config (read-merge-write
 * semantics — never clobbers other config). Exported for tests.
 */
export function applyEgress(config: RawConfig, change: Partial<EgressBlock>): RawConfig {
  const policy = (config.policy = config.policy ?? {});
  const existing = (policy.egress ?? {}) as Partial<EgressBlock>;
  policy.egress = { ...DEFAULT_EGRESS, ...existing, ...change };
  return config;
}

/**
 * Current egress block from the global config file, defaults merged. Reads the
 * raw ~/.node9/config.json directly (the thing mutations target) rather than the
 * fully-merged getConfig() view. Throws on a malformed config file.
 */
export function getEgress(): EgressBlock {
  const raw = readEgressRawConfig();
  const existing = (raw.policy?.egress ?? {}) as Partial<EgressBlock>;
  return { ...DEFAULT_EGRESS, ...existing };
}

/** Read-merge-write a change to policy.egress. Throws on a malformed config. */
export function setEgress(change: Partial<EgressBlock>): void {
  const config = readEgressRawConfig();
  applyEgress(config, change);
  writeEgressRawConfig(config);
}

/** Append a host to the allow or deny list (idempotent). Throws on malformed config. */
export function addEgressHost(list: 'allow' | 'deny', host: string): void {
  const config = readEgressRawConfig();
  const existing = (config.policy?.egress ?? {}) as Partial<EgressBlock>;
  const current: EgressBlock = { ...DEFAULT_EGRESS, ...existing };
  const updated = current[list].includes(host) ? current[list] : [...current[list], host];
  applyEgress(config, { [list]: updated });
  writeEgressRawConfig(config);
}

/** Lowercase + trim a host so the CLI and MCP normalize identically. */
export function normalizeEgressHost(host: string): string {
  return host.trim().toLowerCase();
}

/** Loose hostname validator: FQDN or wildcard glob (*.example.com). */
const EGRESS_HOST_RE = /^(\*\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/;
export function isValidEgressHost(host: string): boolean {
  return EGRESS_HOST_RE.test(host);
}

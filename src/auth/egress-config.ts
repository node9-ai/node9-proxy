// src/auth/egress-config.ts
// Shared egress-config read/merge/write. Used by BOTH the `node9 egress` CLI
// (src/cli/commands/egress.ts) and the node9 MCP egress tools (src/mcp-server)
// so the allowlist is mutated through exactly one path.
//
// We touch only policy.egress in ~/.node9/config.json (an arbitrary JSON bag) and
// REFUSE to write over a config we couldn't parse — silently overwriting would
// destroy the user's other settings.

import { readConfigFileLegacy, writeConfigFile } from '../config/write';
import os from 'os';
import path from 'path';
import { classifySsrf } from '@node9/policy-engine';

export type EgressMode = 'off' | 'review' | 'block';

export interface EgressBlock {
  enabled: boolean;
  mode: EgressMode;
  allow: string[];
  deny: string[];
  allowPrivate: boolean;
  /** SSRF floor, strict tier: also block loopback and the private ranges. */
  ssrfStrict: boolean;
  /** SSRF floor exemptions. Only an OVERRIDABLE tier can be exempted; a
   *  protected address stays blocked whatever this list says. */
  ssrfAllow: string[];
}

export const DEFAULT_EGRESS: EgressBlock = {
  enabled: false,
  mode: 'review',
  allow: [],
  deny: [],
  allowPrivate: true,
  ssrfStrict: false,
  ssrfAllow: [],
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
  // The legacy view of the file whatever its format; throws on a file that
  // exists but cannot be read, so it is never overwritten.
  return readConfigFileLegacy(egressConfigPath()) as RawConfig;
}

/** Read-mutate-write the global file under the one config writer. */
function mutateEgressConfig(mutate: (config: RawConfig) => void): void {
  writeConfigFile(egressConfigPath(), (file) => {
    mutate(file as unknown as RawConfig);
  });
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
  mutateEgressConfig((config) => {
    applyEgress(config, change);
  });
}

/** Append a host to the allow or deny list (idempotent). Throws on malformed config. */
export function addEgressHost(list: 'allow' | 'deny', host: string): void {
  mutateEgressConfig((config) => {
    const existing = (config.policy?.egress ?? {}) as Partial<EgressBlock>;
    const current: EgressBlock = { ...DEFAULT_EGRESS, ...existing };
    const updated = current[list].includes(host) ? current[list] : [...current[list], host];
    applyEgress(config, { [list]: updated });
  });
}

/**
 * Append an address to the SSRF exemption list (idempotent). Refuses a
 * protected address HERE, at the keystroke: the config layer drops such an
 * entry at load time, which left a user who typed one believing the exemption
 * existed. Throws on a malformed config.
 */
export function addSsrfExemption(address: string): void {
  // A range is judged by its BASE address, the same rule sanitizeSsrfAllow
  // applies at load and the CLI applies at the keystroke. The writer keeps its
  // own guard rather than trusting the caller: it is the one place every
  // surface goes through, and today's only caller having checked first is not
  // a property the next caller inherits.
  const slash = address.indexOf('/');
  const m = classifySsrf(slash === -1 ? address : address.slice(0, slash));
  if (m && !m.overridable) {
    throw new Error(
      `${address} ${slash === -1 ? 'is a protected address' : 'covers only protected addresses'} ` +
        `(${m.tier}) and cannot be exempted by anyone. ` +
        `This is the one part of the floor no setting releases.`
    );
  }
  mutateEgressConfig((config) => {
    const existing = (config.policy?.egress ?? {}) as Partial<EgressBlock>;
    // A hand-edited scalar here used to be spread per CHARACTER: "10.0.0.1"
    // became ["1","0",".",…] and the command still reported success. Refuse and
    // say so rather than rewriting a file we cannot read as intended.
    if (existing.ssrfAllow !== undefined && !Array.isArray(existing.ssrfAllow)) {
      throw new Error(
        `${egressConfigPath()} has policy.egress.ssrfAllow set to something that is not a list — ` +
          `fix it before adding an exemption (refusing to overwrite).`
      );
    }
    const current: EgressBlock = { ...DEFAULT_EGRESS, ...existing };
    const updated = current.ssrfAllow.includes(address)
      ? current.ssrfAllow
      : [...current.ssrfAllow, address];
    applyEgress(config, { ssrfAllow: updated });
  });
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

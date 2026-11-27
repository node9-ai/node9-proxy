// src/addons/standing-file.ts
// What the package check found for the MCP servers on this machine
// (node9Firewall#376 item 6, phase 4, check D). The daemon writes it
// (package-standing.ts: registry lookups, never on a hook's path); the
// collector puts its findings on the add-ons report, and the hook and the
// gateway read it to stop a server whose package is on the malicious list.
//
// It holds identities, rule ids, advisory ids and times. No argument, path or
// env value. This module reads and writes the file and nothing else, so the
// hook bundle can carry it.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { atomicWriteSync } from '../utils/atomic-write';

/** The rule for a package the malicious-package list covers at the version in use. */
export const MALICIOUS_RULE = 'mcp.package-malicious';

export interface StandingFinding {
  rule: string;
  severity: 'critical' | 'high' | 'medium';
  /** Advisory ids (`MAL-2025-1234`), for the reason shown on the machine. */
  advisories?: string[];
}

export interface StandingEntry {
  findings: StandingFinding[];
  /** The registry answered, so "no finding" means checked. False: only the
   *  local malicious-package index was read. */
  registry: boolean;
  /** The pinned version the check ran for, when the launch command pins one. */
  version?: string;
  checkedAt: string;
}

export interface StandingFile {
  v: 1;
  /** By MCP identity (`npm:<pkg>`, `pypi:<pkg>`). */
  entries: Record<string, StandingEntry>;
}

const MAX_ENTRIES = 200;
const MAX_BYTES = 512 * 1024;

export function standingPath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'addons-standing.json');
}

const RULE_SHAPE = /^[A-Za-z0-9._-]{1,80}$/;
const ADVISORY_SHAPE = /^[A-Za-z0-9._-]{1,64}$/;

function entryOf(raw: unknown): StandingEntry | null {
  const e = raw as Partial<StandingEntry> | null;
  if (!e || typeof e !== 'object' || !Array.isArray(e.findings)) return null;
  if (typeof e.checkedAt !== 'string' || typeof e.registry !== 'boolean') return null;
  const findings: StandingFinding[] = [];
  for (const f of e.findings.slice(0, 10)) {
    const r = f as Partial<StandingFinding> | null;
    if (!r || typeof r.rule !== 'string' || !RULE_SHAPE.test(r.rule)) continue;
    if (r.severity !== 'critical' && r.severity !== 'high' && r.severity !== 'medium') continue;
    const advisories = Array.isArray(r.advisories)
      ? r.advisories
          .filter((a): a is string => typeof a === 'string' && ADVISORY_SHAPE.test(a))
          .slice(0, 5)
      : [];
    findings.push({
      rule: r.rule,
      severity: r.severity,
      ...(advisories.length ? { advisories } : {}),
    });
  }
  return {
    findings,
    registry: e.registry,
    ...(typeof e.version === 'string' ? { version: e.version.slice(0, 64) } : {}),
    checkedAt: e.checkedAt,
  };
}

/** The file, or an empty one when it was never written or cannot be read. */
export function readStanding(home: string = os.homedir()): StandingFile {
  const out: StandingFile = { v: 1, entries: {} };
  try {
    const file = standingPath(home);
    if (fs.statSync(file).size > MAX_BYTES) return out;
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as { entries?: unknown };
    if (!raw.entries || typeof raw.entries !== 'object' || Array.isArray(raw.entries)) return out;
    for (const [identity, v] of Object.entries(raw.entries).slice(0, MAX_ENTRIES)) {
      const e = entryOf(v);
      if (e) out.entries[identity] = e;
    }
  } catch {
    /* none yet */
  }
  return out;
}

/** Best effort: a failure leaves the previous file. */
export function writeStanding(data: StandingFile, home: string = os.homedir()): void {
  try {
    const text = JSON.stringify(data);
    try {
      if (fs.readFileSync(standingPath(home), 'utf8') === text) return;
    } catch {
      /* none yet */
    }
    atomicWriteSync(standingPath(home), text, { mode: 0o600 });
  } catch {
    /* the next refresh writes it */
  }
}

/** Whether any stored result is a malicious package. One small file read:
 *  the hook asks this before it reads any agent config. */
export function anyMalicious(home: string = os.homedir()): boolean {
  return Object.values(readStanding(home).entries).some((e) =>
    e.findings.some((f) => f.rule === MALICIOUS_RULE)
  );
}

/**
 * The advisory ids when the server's package is on the malicious-package list
 * at the version in use, else null. An empty list means "on the list, id not
 * recorded".
 */
export function maliciousAdvisories(
  identity: string,
  home: string = os.homedir()
): string[] | null {
  const e = readStanding(home).entries[identity];
  const hit = e?.findings.find((f) => f.rule === MALICIOUS_RULE);
  return hit ? (hit.advisories ?? []) : null;
}

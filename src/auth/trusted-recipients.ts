// src/auth/trusted-recipients.ts
// Destinations the user trusts for sends after exposure (fw#318, design 4.4):
// exact values only ('email:x@y.z', 'host:api.example', 'iban:GB..'), never a
// domain (a domain goes in policy.untrustedContent.orgDomains). Written by
// `node9 trust recipient add|remove` and, later, by the approval button.
// Same file shape and write discipline as trusted-hosts.ts.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { normalizeRecipient } from '@node9/policy-engine';

export interface TrustedRecipientEntry {
  value: string;
  addedAt: number;
  addedBy: 'user' | 'approval';
}

interface TrustedRecipientsFile {
  entries: TrustedRecipientEntry[];
}

export function getTrustedRecipientsPath(): string {
  return path.join(os.homedir(), '.node9', 'trusted-recipients.json');
}

export function readTrustedRecipients(): TrustedRecipientEntry[] {
  try {
    const raw = fs.readFileSync(getTrustedRecipientsPath(), 'utf8');
    const parsed = JSON.parse(raw) as TrustedRecipientsFile;
    return Array.isArray(parsed.entries)
      ? parsed.entries.filter((e) => e && typeof e.value === 'string')
      : [];
  } catch {
    return [];
  }
}

function writeTrustedRecipients(entries: TrustedRecipientEntry[]): void {
  const filePath = getTrustedRecipientsPath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + '.node9-tmp';
  fs.writeFileSync(tmp, JSON.stringify({ entries }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

// The stored form of a typed value (an address `email:`, an IBAN `iban:`, a
// URL or hostname `host:`, `account:<number>`) is the engine's, shared with
// the dashboard's mirror.
export { normalizeRecipient };

/** Add a value. Returns the stored form, or null when it is not a destination. */
export function addTrustedRecipient(
  raw: string,
  addedBy: 'user' | 'approval' = 'user'
): string | null {
  const value = normalizeRecipient(raw);
  if (!value) return null;
  const entries = readTrustedRecipients();
  if (!entries.some((e) => e.value === value)) {
    entries.push({ value, addedAt: Date.now(), addedBy });
    writeTrustedRecipients(entries);
  }
  return value;
}

export function removeTrustedRecipient(raw: string): boolean {
  const value = normalizeRecipient(raw) ?? raw.trim();
  const entries = readTrustedRecipients();
  const next = entries.filter((e) => e.value !== value);
  if (next.length === entries.length) return false;
  writeTrustedRecipients(next);
  return true;
}

let cache: { mtime: number; values: Set<string> } | null = null;

function mtimeOf(): number {
  try {
    return fs.statSync(getTrustedRecipientsPath()).mtimeMs;
  } catch {
    return 0;
  }
}

/** Is `value` on the list? Re-reads the file only when it changed. */

export function isTrustedRecipient(value: string): boolean {
  const mtime = mtimeOf();
  if (!cache || cache.mtime !== mtime) {
    cache = { mtime, values: new Set(readTrustedRecipients().map((e) => e.value)) };
  }
  return cache.values.has(value);
}

export function _resetTrustedRecipientsCache(): void {
  cache = null;
}

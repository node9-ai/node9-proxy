// src/auth/trusted-recipients.ts
// Destinations the user trusts for sends after exposure (fw#318, design 4.4):
// exact values only ('email:x@y.z', 'host:api.example', 'iban:GB..'), never a
// domain (a domain goes in policy.untrustedContent.orgDomains). Written by
// `node9 trust recipient add|remove` and, later, by the approval button.
// Same file shape and write discipline as trusted-hosts.ts.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { extractArgDestinations } from '@node9/policy-engine';

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

/**
 * Normalise a user-typed value to the stored form. An address becomes
 * `email:`, an IBAN `iban:`, a URL or hostname `host:`. Returns null when the
 * value is not one of those three (a bare word, a domain without a host part
 * is still a host, which is fine: it is exact, not a wildcard).
 */
export function normalizeRecipient(raw: string): string | null {
  const v = raw.trim();
  if (!v) return null;
  if (/^(email|host|iban):/i.test(v)) {
    const i = v.indexOf(':');
    const kind = v.slice(0, i).toLowerCase();
    const inner = normalizeRecipient(v.slice(i + 1));
    return inner && inner.startsWith(`${kind}:`) ? inner : null;
  }
  const found = extractArgDestinations({ to: v });
  return found.length === 1 ? found[0] : null;
}

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

export function isTrustedRecipient(value: string): boolean {
  return readTrustedRecipients().some((e) => e.value === value);
}

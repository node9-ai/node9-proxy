// src/addons/definitions-file.ts
// What the MCP gateway's scan of tool definitions last found for each server
// it fronts (node9Firewall#342; add-ons plan phase 4, check C). The gateway
// writes one small file per server when it scans a `tools/list` answer; the
// add-ons collector reads them and puts the findings on the server's row.
//
// One file per server key, so two gateways never write the same file. A file
// holds the server's identity, rule ids with severities, and a time. No tool
// name, description or schema text.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { atomicWriteSync } from '../utils/atomic-write';
import { readSmallFile } from '../utils/read-small-file';

export interface DefinitionScanRecord {
  identity: string;
  findings: Array<{ rule: string; severity: 'high' | 'medium' }>;
  scannedAt: string;
}

const MAX_FILES = 200;
const MAX_BYTES = 16 * 1024;
const KEY_SHAPE = /^[0-9a-f]{16}$/;
const RULE_SHAPE = /^[A-Za-z0-9._-]{1,80}$/;

export function definitionsDir(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'mcp-definitions');
}

/** Best effort: a failure to write never reaches the JSON-RPC path. */
export function writeDefinitionScan(
  serverKey: string,
  record: DefinitionScanRecord,
  home: string = os.homedir()
): void {
  try {
    if (!KEY_SHAPE.test(serverKey)) return;
    const file = path.join(definitionsDir(home), `${serverKey}.json`);
    const data = JSON.stringify({ v: 1, ...record });
    try {
      // The time changes on every scan; rewrite only when the verdict did or
      // the stored one is more than an hour old.
      const prev = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<DefinitionScanRecord>;
      const same =
        prev.identity === record.identity &&
        JSON.stringify(prev.findings) === JSON.stringify(record.findings);
      const age = Date.parse(record.scannedAt) - Date.parse(String(prev.scannedAt));
      if (same && age >= 0 && age < 60 * 60 * 1000) return;
    } catch {
      /* none yet */
    }
    atomicWriteSync(file, data, { mode: 0o600 });
  } catch {
    /* the next scan writes it */
  }
}

function recordOf(raw: unknown): DefinitionScanRecord | null {
  const r = raw as Partial<DefinitionScanRecord> | null;
  if (!r || typeof r.identity !== 'string' || typeof r.scannedAt !== 'string') return null;
  if (!Array.isArray(r.findings)) return null;
  const findings: DefinitionScanRecord['findings'] = [];
  for (const f of r.findings.slice(0, 10)) {
    const x = f as { rule?: unknown; severity?: unknown } | null;
    if (typeof x?.rule !== 'string' || !RULE_SHAPE.test(x.rule)) continue;
    if (x.severity !== 'high' && x.severity !== 'medium') continue;
    findings.push({ rule: x.rule, severity: x.severity });
  }
  return { identity: r.identity.slice(0, 200), findings, scannedAt: r.scannedAt };
}

/**
 * The stored scans by server identity. Two configured servers that run the
 * same package share an identity: their findings are joined, and the newer
 * scan time is kept. Never throws.
 */
export function readDefinitionScans(
  home: string = os.homedir()
): Map<string, DefinitionScanRecord> {
  const out = new Map<string, DefinitionScanRecord>();
  let names: string[];
  try {
    names = fs.readdirSync(definitionsDir(home)).filter((n) => /^[0-9a-f]{16}\.json$/.test(n));
  } catch {
    return out;
  }
  for (const name of names.slice(0, MAX_FILES)) {
    try {
      // One descriptor checks and reads (CodeQL js/file-system-race); the
      // gateway writes these files itself, so a link in their place is refused.
      const text = readSmallFile(path.join(definitionsDir(home), name), MAX_BYTES, {
        noFollow: true,
      });
      if (text === null) continue;
      const rec = recordOf(JSON.parse(text));
      if (!rec) continue;
      const cur = out.get(rec.identity);
      if (!cur) {
        out.set(rec.identity, rec);
        continue;
      }
      for (const f of rec.findings)
        if (!cur.findings.some((c) => c.rule === f.rule)) cur.findings.push(f);
      if (rec.scannedAt > cur.scannedAt) cur.scannedAt = rec.scannedAt;
    } catch {
      /* an unreadable file is a server not scanned */
    }
  }
  return out;
}

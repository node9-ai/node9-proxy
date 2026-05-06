#!/usr/bin/env node
// Diagnostic: re-extracts canonical findings over the same window
// `node9 scan --upload-history` uses (default 3m / 90d), buckets by
// ScanFinding.type, and prints counts. Use to verify the SaaS dashboard
// reflects what was actually uploaded.
//
// Run from the proxy repo root:
//   node scripts/count-upload-by-type.mjs [days]
//
// Default window is 90 days (matches --upload-history default 3m).

import fs from 'fs';
import path from 'path';
import os from 'os';
import {
  extractCanonicalFindings,
  extractSessionLevelFindings,
  toScanFinding,
  LONG_OUTPUT_THRESHOLD_BYTES,
} from '../packages/policy-engine/dist/index.mjs';

const days = parseInt(process.argv[2] ?? '90', 10);
const cutoffMs = Date.now() - days * 24 * 3600 * 1000;
const projectsDir = path.join(os.homedir(), '.claude', 'projects');

const counts = {};
let totalScanFindings = 0;
let filesScanned = 0;
let linesParsed = 0;
const seenSessions = new Set();

if (!fs.existsSync(projectsDir)) {
  console.log('No ~/.claude/projects/ — nothing to scan.');
  process.exit(0);
}

const ctxBase = {
  project: '',
  agent: 'claude',
  rules: [],
  toolInspection: { bash: 'command', execute_bash: 'command' },
  dlpEnabled: false,
};

for (const proj of fs.readdirSync(projectsDir)) {
  const projPath = path.join(projectsDir, proj);
  if (!fs.statSync(projPath).isDirectory()) continue;
  for (const file of fs.readdirSync(projPath).filter((f) => f.endsWith('.jsonl'))) {
    const filePath = path.join(projPath, file);
    const stat = fs.statSync(filePath);
    if (stat.mtimeMs < cutoffMs) continue;
    filesScanned++;
    const sessionId = file.replace(/\.jsonl$/, '');
    let lineIndex = 0;
    let raw;
    try {
      raw = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    const sessionCalls = [];
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      lineIndex++;
      let obj;
      try {
        obj = JSON.parse(line);
      } catch {
        continue;
      }
      if (obj.timestamp && new Date(obj.timestamp).getTime() < cutoffMs) continue;
      seenSessions.add(sessionId);
      linesParsed++;

      const ctx = { ...ctxBase, sessionId, lineIndex };

      const message = obj.message;
      if (!message || typeof message !== 'object') continue;
      const content = message.content;
      if (!Array.isArray(content)) continue;
      for (const block of content) {
        if (!block || typeof block !== 'object') continue;
        if (block.type === 'tool_result') {
          const c = block.content;
          const len =
            typeof c === 'string' ? c.length : Array.isArray(c) ? JSON.stringify(c).length : 0;
          if (len > LONG_OUTPUT_THRESHOLD_BYTES) {
            counts['long-output-redacted'] = (counts['long-output-redacted'] || 0) + 1;
            totalScanFindings++;
          }
          continue;
        }
        if (block.type !== 'tool_use') continue;
        const call = {
          toolName: typeof block.name === 'string' ? block.name : '',
          args: block.input || {},
          timestamp: typeof obj.timestamp === 'string' ? obj.timestamp : '',
        };
        // Per-line canonical findings
        const canonical = extractCanonicalFindings(call, ctx);
        for (const cf of canonical) {
          const sf = toScanFinding(cf);
          if (sf) {
            counts[sf.type] = (counts[sf.type] || 0) + 1;
            totalScanFindings++;
          }
        }
        // Buffer for session-level loop pass below
        sessionCalls.push({ ...call, lineIndex });
      }
    }

    // Session-level loop detection — same backfill semantics --upload-history
    // uses (threshold=3, no window).
    if (sessionCalls.length > 0) {
      const loops = extractSessionLevelFindings(sessionCalls, {
        sessionId,
        project: '',
        agent: 'claude',
        loopDetection: { enabled: true, threshold: 3, windowSeconds: 0 },
      });
      for (const cf of loops) {
        const sf = toScanFinding(cf);
        if (sf) {
          counts[sf.type] = (counts[sf.type] || 0) + 1;
          totalScanFindings++;
        }
      }
    }
  }
}

console.log(`\nWindow: last ${days} days (since ${new Date(cutoffMs).toISOString()})`);
console.log(`Files scanned: ${filesScanned}, sessions touched: ${seenSessions.size}`);
console.log(`Lines parsed: ${linesParsed.toLocaleString()}`);
console.log(`Total ScanFindings: ${totalScanFindings}\n`);
console.log('By type (these are what get POSTed to the SaaS rollup):');
for (const [t, c] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${t.padEnd(28)} ${c}`);
}

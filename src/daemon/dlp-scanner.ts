// src/daemon/dlp-scanner.ts
// Background DLP scanner for Claude response text.
// Runs on daemon startup and every hour — reads ~/.claude/projects/**/*.jsonl,
// processes only new content (delta via ~/.node9/dlp-index.json), and fires a
// desktop notification + audit log entry when a secret is found in response text.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanText } from '../dlp';
import { sendDesktopNotification } from '../ui/native';
import { AUDIT_LOG_FILE } from './state';

const INDEX_FILE = path.join(os.homedir(), '.node9', 'dlp-index.json');
const PROJECTS_DIR = path.join(os.homedir(), '.claude', 'projects');

// filePath → last scanned byte offset, plus a rolling seen-set of already-notified
// findings so a single legitimate session doesn't fire N popups for the same secret.
interface DlpIndex {
  offsets: Record<string, number>;
  seen: string[]; // `${patternName}|${redactedSample}` keys already notified
}
const SEEN_CAP = 500; // bound the persisted set (drop-oldest)

function loadIndex(): DlpIndex {
  try {
    const raw = JSON.parse(fs.readFileSync(INDEX_FILE, 'utf-8')) as unknown;
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
      const r = raw as Record<string, unknown>;
      // New shape: { offsets, seen }.
      if (r.offsets && typeof r.offsets === 'object') {
        return {
          offsets: r.offsets as Record<string, number>,
          seen: Array.isArray(r.seen) ? (r.seen as string[]) : [],
        };
      }
      // Legacy flat map (filePath → offset) — treat as offsets, seen starts empty.
      return { offsets: r as Record<string, number>, seen: [] };
    }
  } catch {
    /* fall through to empty */
  }
  return { offsets: {}, seen: [] };
}

function saveIndex(index: DlpIndex): void {
  try {
    fs.writeFileSync(
      INDEX_FILE,
      JSON.stringify({ offsets: index.offsets, seen: index.seen.slice(-SEEN_CAP) }),
      { encoding: 'utf-8', mode: 0o600 }
    );
  } catch {}
}

function appendAuditEntry(entry: Record<string, unknown>): void {
  try {
    fs.appendFileSync(AUDIT_LOG_FILE, JSON.stringify(entry) + '\n');
  } catch {}
}

export function runDlpScan(): void {
  if (!fs.existsSync(PROJECTS_DIR)) return;

  const index = loadIndex();
  const seen = new Set(index.seen);
  // Collected across the whole pass so we emit ONE notification, not one per match.
  const newFindings: { patternName: string; redactedSample: string; project: string }[] = [];
  let updated = false;

  let projDirs: string[];
  try {
    projDirs = fs.readdirSync(PROJECTS_DIR);
  } catch {
    return;
  }

  for (const proj of projDirs) {
    const projPath = path.join(PROJECTS_DIR, proj);
    try {
      // lstatSync does not follow symlinks — prevents a crafted symlink in
      // ~/.claude/projects/ from redirecting the scanner to arbitrary paths.
      if (!fs.lstatSync(projPath).isDirectory()) continue;
      // Canonicalize and verify the resolved path stays under PROJECTS_DIR.
      const real = fs.realpathSync(projPath);
      if (!real.startsWith(PROJECTS_DIR + path.sep) && real !== PROJECTS_DIR) continue;
    } catch {
      continue;
    }

    let files: string[];
    try {
      files = fs
        .readdirSync(projPath)
        .filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-'));
    } catch {
      continue;
    }

    for (const file of files) {
      const filePath = path.join(projPath, file);
      const lastOffset = index.offsets[filePath] ?? 0;

      let size: number;
      try {
        size = fs.statSync(filePath).size;
      } catch {
        continue;
      }

      if (size <= lastOffset) continue;

      let fd: number;
      try {
        fd = fs.openSync(filePath, 'r');
      } catch {
        continue;
      }

      try {
        const chunkSize = size - lastOffset;
        const buf = Buffer.alloc(chunkSize);
        fs.readSync(fd, buf, 0, chunkSize, lastOffset);
        const chunk = buf.toString('utf-8');

        for (const line of chunk.split('\n')) {
          if (!line.trim()) continue;
          let entry: {
            type?: string;
            timestamp?: string;
            message?: { content?: unknown; model?: string };
          };
          try {
            entry = JSON.parse(line);
          } catch {
            continue;
          }

          if (entry.type !== 'assistant') continue;
          const content = entry.message?.content;
          if (!Array.isArray(content)) continue;

          for (const block of content) {
            if (
              typeof block !== 'object' ||
              block === null ||
              (block as Record<string, unknown>).type !== 'text'
            )
              continue;
            const text = (block as Record<string, unknown>).text;
            if (typeof text !== 'string') continue;

            const match = scanText(text);
            if (!match) continue;

            const projLabel = decodeURIComponent(proj).replace(os.homedir(), '~').slice(0, 40);
            const ts = entry.timestamp ?? new Date().toISOString();

            // Audit ALWAYS — telemetry stays complete (every match recorded).
            appendAuditEntry({
              ts,
              tool: 'response-text',
              decision: 'dlp',
              checkedBy: 'response-dlp',
              source: 'response-dlp',
              dlpPattern: match.patternName,
              dlpSample: match.redactedSample,
              project: projLabel,
            });

            // Notify only for a finding not seen before — dedup the popup storm.
            const seenKey = `${match.patternName}|${match.redactedSample}`;
            if (!seen.has(seenKey)) {
              seen.add(seenKey);
              newFindings.push({
                patternName: match.patternName,
                redactedSample: match.redactedSample,
                project: projLabel,
              });
            }
          }
        }

        index.offsets[filePath] = size;
        updated = true;
      } finally {
        try {
          fs.closeSync(fd);
        } catch {}
      }
    }
  }

  // ONE notification for the whole pass. Zero new findings (all duplicates) = silence.
  if (newFindings.length === 1) {
    const f = newFindings[0];
    sendDesktopNotification(
      '⚠️ node9 DLP Alert',
      `${f.patternName} found in Claude response\nSample: ${f.redactedSample}\nProject: ${f.project}\nRun: node9 report --period 30d`
    );
  } else if (newFindings.length > 1) {
    sendDesktopNotification(
      '⚠️ node9 DLP Alert',
      `${newFindings.length} new secrets found in Claude responses (top: ${newFindings[0].patternName}) — run: node9 report --period 30d`
    );
  }

  if (updated) {
    index.seen = [...seen];
    saveIndex(index);
  }
}

export function startDlpScanner(): void {
  // Run once at startup (async so daemon startup isn't delayed)
  setImmediate(() => {
    try {
      runDlpScan();
    } catch {}
  });

  // Then every hour
  const timer = setInterval(
    () => {
      try {
        runDlpScan();
      } catch {}
    },
    60 * 60 * 1000
  );
  timer.unref();
}

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

type DlpIndex = Record<string, number>; // filePath → last scanned byte offset

function loadIndex(): DlpIndex {
  try {
    return JSON.parse(fs.readFileSync(INDEX_FILE, 'utf-8')) as DlpIndex;
  } catch {
    return {};
  }
}

function saveIndex(index: DlpIndex): void {
  try {
    fs.writeFileSync(INDEX_FILE, JSON.stringify(index), 'utf-8');
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
      const lastOffset = index[filePath] ?? 0;

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

            sendDesktopNotification(
              '⚠️ node9 DLP Alert',
              `${match.patternName} found in Claude response\nSample: ${match.redactedSample}\nProject: ${projLabel}\nRun: node9 report --period 30d`
            );
          }
        }

        index[filePath] = size;
        updated = true;
      } finally {
        try {
          fs.closeSync(fd);
        } catch {}
      }
    }
  }

  if (updated) saveIndex(index);
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

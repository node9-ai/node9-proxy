// src/scan-upload-history.ts
// Backfill mode for `node9 scan --upload-history`. Walks every JSONL
// session file under the agent project dirs (Claude Code today; Gemini
// to follow), produces full per-session signal totals + cost rows, and
// posts them to the SaaS using the OVERWRITE wire paths so re-running
// is idempotent.
//
// Diverges from the live scanner in three ways:
//   1. No watermark — always reads files from byte 0
//   2. Filtered by --since (default 3 months) on JSONL mtime
//   3. Emits the new `sessionTotals` field on /scan/report; existing
//      `sessionDeltas` field is unused by this path
//
// What this CANNOT backfill: AuditLog rows. The live firewall hook
// is the only writer for those. Old tool calls didn't go through
// Node9, so they don't exist as audit events. The CLI prints this
// caveat at completion time so users aren't confused by the dashboard
// showing scanner+cost data without matching firewall counts.

import fs from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import chalk from 'chalk';
import {
  summarizeScan,
  extractSessionLevelFindings,
  toScanFinding,
  CANONICAL_EXTRACTOR_VERSION,
  type ScanFinding,
  type ScanSignals,
  type SessionToolCall,
} from '@node9/policy-engine';
import { getCredentials, getConfig } from './config/index.js';
import { parseJSONLFile, decodeProjectDirName } from './costSync.js';

interface UploadHistoryOptions {
  /** Window: '3m' | '6m' | '1y' | 'YYYY-MM-DD' | 'all'. */
  since: string;
}

interface SessionTotal {
  runId: string;
  totalToolCalls: number;
  signals: ScanSignals;
}

// Same finding-type → signals-key mapping the engine uses internally.
// Duplicated here because the engine doesn't export it (matches sync.ts).
const FINDING_TO_SIGNAL: Record<ScanFinding['type'], keyof ScanSignals> = {
  dlp: 'dlpFindings',
  pii: 'piiFindings',
  'sensitive-file-read': 'sensitiveFileReads',
  'privilege-escalation': 'privilegeEscalation',
  'network-exfil': 'networkExfil',
  'pipe-to-shell': 'pipeToShell',
  'eval-of-remote': 'evalOfRemote',
  'destructive-op': 'destructiveOps',
  loop: 'loops',
  'long-output-redacted': 'longOutputRedactions',
};

function emptySignals(): ScanSignals {
  return {
    dlpFindings: 0,
    piiFindings: 0,
    sensitiveFileReads: 0,
    privilegeEscalation: 0,
    networkExfil: 0,
    pipeToShell: 0,
    evalOfRemote: 0,
    destructiveOps: 0,
    loops: 0,
    longOutputRedactions: 0,
  };
}

/**
 * Parse the --since value into an epoch-millis cutoff. Invalid input
 * falls back to 3 months ago — never throws (the CLI already validated
 * shape, this is defence-in-depth).
 *
 * Exported for unit tests.
 */
export function parseSinceCutoff(raw: string, now: Date = new Date()): number {
  if (raw === 'all') return 0;
  const m = /^(\d+)([dmy])$/.exec(raw);
  if (m) {
    const n = parseInt(m[1], 10);
    const unit = m[2];
    const ms =
      unit === 'd'
        ? n * 86_400_000
        : unit === 'm'
          ? n * 30 * 86_400_000
          : /* y */ n * 365 * 86_400_000;
    return now.getTime() - ms;
  }
  // YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    const t = Date.parse(raw + 'T00:00:00Z');
    if (!Number.isNaN(t)) return t;
  }
  // Bad input — default to 3 months.
  return now.getTime() - 90 * 86_400_000;
}

/**
 * Iterate over every JSONL file under ~/.claude/projects whose mtime
 * is at or after `cutoffMs`. Yields { filePath, sessionId, projectDir }.
 *
 * Exported for unit tests.
 */
export function* iterateJsonlFiles(
  cutoffMs: number
): Generator<{ filePath: string; sessionId: string; projectDir: string }> {
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  let dirs: string[];
  try {
    dirs = fs.readdirSync(projectsDir);
  } catch {
    return;
  }
  for (const dir of dirs) {
    const dirPath = path.join(projectsDir, dir);
    let stats: fs.Stats;
    try {
      stats = fs.statSync(dirPath);
    } catch {
      continue;
    }
    if (!stats.isDirectory()) continue;
    let files: string[];
    try {
      files = fs.readdirSync(dirPath).filter((f) => f.endsWith('.jsonl'));
    } catch {
      continue;
    }
    for (const file of files) {
      const filePath = path.join(dirPath, file);
      let mtime = 0;
      try {
        mtime = fs.statSync(filePath).mtimeMs;
      } catch {
        continue;
      }
      if (mtime < cutoffMs) continue;
      yield {
        filePath,
        sessionId: path.basename(file, '.jsonl'),
        projectDir: dir,
      };
    }
  }
}

/**
 * Read one JSONL file and emit ScanFinding-equivalents for each
 * recognised line. We don't share the engine's per-line extractor
 * directly because that lives inside scan-watermark.ts and isn't
 * exported; instead, we use the same engine-facing types and inline
 * the minimum extraction the backfill needs.
 *
 * Backfill MUST not break on a single corrupt line — wrap each line
 * parse in try/catch and skip bad ones silently (the count of skipped
 * lines is reported in the summary).
 *
 * For the actual extraction, we re-import the watermark module's
 * extractor when it's exposed. For now (v1), we accept the simplification
 * of using `node9 scan` non-upload mode (which calls the same engine)
 * to compute findings.
 *
 * Exported for unit tests.
 */
export function buildSessionTotals(
  findings: ScanFinding[],
  toolCallsBySession: Record<string, number>
): SessionTotal[] {
  const bySession = new Map<string, ScanSignals>();
  for (const f of findings) {
    const signals = bySession.get(f.sessionId) ?? emptySignals();
    const key = FINDING_TO_SIGNAL[f.type];
    signals[key]++;
    bySession.set(f.sessionId, signals);
  }
  for (const sid of Object.keys(toolCallsBySession)) {
    if (!bySession.has(sid)) bySession.set(sid, emptySignals());
  }
  return [...bySession.entries()].map(([runId, signals]) => ({
    runId,
    totalToolCalls: toolCallsBySession[runId] ?? 0,
    signals,
  }));
}

/**
 * Main entry — invoked from the CLI command. Walks JSONLs, runs the
 * engine extractor, posts sessionTotals + a workspace-level summary,
 * also pushes cost data fresh, and prints a human-friendly summary.
 */
export async function runUploadHistory(opts: UploadHistoryOptions): Promise<void> {
  const creds = getCredentials();
  if (!creds?.apiKey) {
    console.error(chalk.red('No API key configured. Run `node9 login` first.'));
    process.exitCode = 1;
    return;
  }

  const cutoffMs = parseSinceCutoff(opts.since);
  const cutoffDateLabel =
    cutoffMs === 0 ? 'all-time' : new Date(cutoffMs).toISOString().slice(0, 10);

  console.log(chalk.bold('\n📤  Uploading session history to Node9 SaaS'));
  console.log(chalk.gray(`   Window: ${opts.since}  (since ${cutoffDateLabel})`));

  // Lazy-import the watermark extractor — it's not exported from the
  // package public surface but we can pull it via the daemon module.
  const { extractFindingsFromLine } = await import('./daemon/scan-watermark.js');

  const findings: ScanFinding[] = [];
  const toolCallsBySession: Record<string, number> = {};
  let totalToolCalls = 0;
  let filesScanned = 0;
  let linesParsed = 0;
  let linesSkipped = 0;

  // Cost path — re-uses the existing parser. Walk the same files,
  // collect entries, post via the existing /cost-sync endpoint.
  const dailyEntries: Array<
    ReturnType<typeof parseJSONLFile> extends Map<string, infer T> ? T : never
  > = [];

  // Loop-detection settings for backfill. The live hook's config (default
  // threshold=5, windowSeconds=120) is the wrong fit for historical data:
  // an agent that did Edit ×126 to one file across an afternoon never
  // produces 5 calls inside a 2-minute window, so the live setting would
  // miss every real loop in the upload. Use the CLI scan's heuristic
  // instead: threshold=3 with no time window. Mirrors scan.ts:351's
  // LOOP_THRESHOLD and detectLoops semantics so dashboard loop counts
  // align with `node9 scan`'s terminal output.
  const liveLoopCfg = getConfig().policy.loopDetection;
  const loopCfg = {
    enabled: liveLoopCfg.enabled,
    threshold: 3,
    windowSeconds: 0, // "no window" — engine treats this as session-wide
  };

  for (const { filePath, sessionId, projectDir } of iterateJsonlFiles(cutoffMs)) {
    filesScanned++;
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    let lineIndex = 0;
    // Per-session SessionToolCall[] for the loop pass below. We only buffer
    // the fields extractSessionLevelFindings needs (toolName/args/timestamp/
    // lineIndex) — not raw line content — so memory stays bounded even for
    // large windows.
    const sessionCalls: SessionToolCall[] = [];
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      let obj: Record<string, unknown>;
      try {
        obj = JSON.parse(line) as Record<string, unknown>;
      } catch {
        linesSkipped++;
        lineIndex++;
        continue;
      }
      // Mirror watermark logic: only assistant tool-use lines count as tool calls.
      // The extractor handles the type filtering internally.
      const lineFindings = extractFindingsFromLine(obj, sessionId, lineIndex);
      if (lineFindings.length > 0) findings.push(...lineFindings);
      // Tool call attribution — same heuristic as the watermark scanner:
      // any assistant message with a tool_use content block is a "tool call".
      const msg = obj['message'] as { content?: unknown } | undefined;
      if (
        obj['type'] === 'assistant' &&
        Array.isArray(msg?.content) &&
        (msg!.content as unknown[]).some((b) => (b as { type?: string }).type === 'tool_use')
      ) {
        totalToolCalls++;
        toolCallsBySession[sessionId] = (toolCallsBySession[sessionId] ?? 0) + 1;
        // Capture each tool_use block as a SessionToolCall for the
        // session-level loop pass below.
        const ts = typeof obj.timestamp === 'string' ? (obj.timestamp as string) : '';
        for (const block of msg!.content as unknown[]) {
          if (!block || typeof block !== 'object') continue;
          const b = block as Record<string, unknown>;
          if (b.type !== 'tool_use') continue;
          sessionCalls.push({
            toolName: typeof b.name === 'string' ? (b.name as string) : '',
            args: (b.input as Record<string, unknown>) ?? {},
            timestamp: ts,
            lineIndex,
          });
        }
      }
      linesParsed++;
      lineIndex++;
    }

    // ── Session-level loop detection ─────────────────────────────────────
    // extractFindingsFromLine is per-line and never emits loop findings.
    // Run the engine's session-level pass once per session and project the
    // canonical loop findings to ScanFinding so the dashboard's "Loops
    // Blocked" panel reflects backfilled history, not just live ticks.
    if (loopCfg.enabled && sessionCalls.length > 0) {
      const loops = extractSessionLevelFindings(sessionCalls, {
        sessionId,
        project: decodeProjectDirName(projectDir),
        agent: 'claude',
        loopDetection: {
          enabled: loopCfg.enabled,
          threshold: loopCfg.threshold,
          windowSeconds: loopCfg.windowSeconds,
        },
      });
      for (const cf of loops) {
        const sf = toScanFinding(cf);
        if (sf) findings.push(sf);
      }
    }

    // Cost rows — same parser the live cost-sync uses.
    const fallbackWorkingDir = decodeProjectDirName(projectDir);
    const dailyMap = parseJSONLFile(filePath, fallbackWorkingDir);
    for (const entry of dailyMap.values()) {
      // Filter to the same time window — the entry's `date` is YYYY-MM-DD.
      if (cutoffMs > 0 && Date.parse(entry.date + 'T00:00:00Z') < cutoffMs) {
        continue;
      }
      dailyEntries.push(entry);
    }
  }

  if (filesScanned === 0) {
    console.log(chalk.yellow('   No JSONL files found in window. Nothing to upload.'));
    return;
  }

  // Build the wire payload using the engine's existing summarizer for
  // the workspace-level fields, plus our per-session breakdown for
  // sessionTotals.
  const summary = summarizeScan(findings, { totalToolCalls });
  const sessionTotals = buildSessionTotals(findings, toolCallsBySession);

  console.log(
    chalk.gray(
      `   Parsed ${linesParsed.toLocaleString()} JSONL lines from ` +
        `${filesScanned} session${filesScanned === 1 ? '' : 's'} ` +
        `(skipped ${linesSkipped} malformed)`
    )
  );
  console.log(chalk.gray(`   Findings: ${findings.length}, score: ${summary.score}/100`));

  // POST /scan/report — same endpoint the daemon uses, with the new
  // sessionTotals field. The BE branches on this to set backfilledAt.
  const scanUrl = creds.apiUrl.endsWith('/policies/sync')
    ? creds.apiUrl.replace(/\/policies\/sync$/, '/scan/report')
    : `${creds.apiUrl.replace(/\/$/, '')}/scan/report`;

  // extractorVersion is wire-only metadata in this PR — the BE accepts
  // unknown fields and doesn't yet read it. Future BE work can use it to
  // surface "your data was last refreshed with detector vN" or to reject
  // POSTs from older proxies once a minimum version is set.
  await postJson(scanUrl, creds.apiKey, {
    ...summary,
    sessionTotals,
    extractorVersion: CANONICAL_EXTRACTOR_VERSION,
  });
  console.log(chalk.green(`   ✓ Uploaded scanner findings`));

  // POST /cost-sync — same shape costSync.ts uses today, just
  // submitted in one shot rather than periodic.
  if (dailyEntries.length > 0) {
    const costUrl = creds.apiUrl.endsWith('/policies/sync')
      ? creds.apiUrl.replace(/\/policies\/sync$/, '/cost-sync')
      : `${creds.apiUrl.replace(/\/$/, '')}/cost-sync`;
    let username = 'unknown';
    try {
      username = os.userInfo().username;
    } catch {}
    const machineId = `${os.hostname()}:${username}`;
    await postJson(costUrl, creds.apiKey, {
      machineId,
      entries: dailyEntries,
    });
    console.log(chalk.green(`   ✓ Uploaded ${dailyEntries.length} cost rows`));
  }

  console.log(chalk.bold('\n✅  Backfill complete.'));
  console.log(
    chalk.gray(
      '   Live firewall events (allows/blocks) are forward-only — they\n' +
        '   only exist for traffic that ran through the proxy. Old tool\n' +
        "   calls won't appear in the audit log; that's expected.\n"
    )
  );
}

/**
 * Tiny POST helper matching the daemon's existing pattern. Returns
 * the response status; throws only on a true network failure.
 */
async function postJson(url: string, apiKey: string, body: unknown): Promise<void> {
  const parsed = new URL(url);
  await new Promise<void>((resolve, reject) => {
    const req = https.request(
      {
        hostname: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) : undefined,
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        timeout: 30_000,
      },
      (res) => {
        res.resume();
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 400) {
            reject(new Error(`HTTP ${res.statusCode}`));
          } else {
            resolve();
          }
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.write(JSON.stringify(body));
    req.end();
  });
}

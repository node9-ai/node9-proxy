// src/daemon/mcp-reconciler.ts
// P3 Phase 2.6 — periodic reconcile: detect NEW ungoverned MCP servers (across
// all agent configs) and either NUDGE (default) or AUTO-WRAP (settings.mcpAutoWrap)
// them through the gateway. Reuses the DLP-style desktop notification + the
// mcp-discovered cloud-event channel (no new notification system). Baseline in
// ~/.node9/mcp-baseline.json dedups "new" across ticks.
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { inventoryMcp, toGateway, writeMcpEntry, type McpEntry } from '../mcp-wrap';
import { sendDesktopNotification } from '../ui/native';
import { getConfig, getCredentials } from '../config';
import { auditLocalAllow } from '../auth/cloud';

const BASELINE_FILE = path.join(os.homedir(), '.node9', 'mcp-baseline.json');
const BASELINE_CAP = 500;
const DEFAULT_INTERVAL_MIN = 60;

function idKey(e: McpEntry): string {
  const cmdHash = crypto
    .createHash('sha256')
    .update(`${e.command} ${e.args.join(' ')}`)
    .digest('hex')
    .slice(0, 16);
  return `${e.agent}:${e.name}:${cmdHash}`;
}

function loadBaseline(): Set<string> {
  try {
    const raw = JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf-8')) as unknown;
    return new Set(Array.isArray(raw) ? (raw as string[]) : []);
  } catch {
    return new Set();
  }
}

function saveBaseline(keys: Set<string>): void {
  try {
    fs.writeFileSync(BASELINE_FILE, JSON.stringify([...keys].slice(-BASELINE_CAP)), {
      mode: 0o600,
    });
  } catch {
    /* never crash the daemon on a baseline write */
  }
}

// Dashboard event — same channel reportInventoryToCloud uses for mcp-discovered.
// creds read ONCE per pass by the caller (fix #10) and passed in.
function reportToCloud(
  e: McpEntry,
  autoWrapped: boolean,
  creds: { apiKey: string; apiUrl: string } | null
): void {
  if (!creds) return;
  try {
    void auditLocalAllow(
      `mcp-server:${e.name}`,
      { agent: e.agent, name: e.name, command: e.command },
      autoWrapped ? 'mcp-auto-wrapped' : 'mcp-ungoverned',
      creds,
      { agent: e.agent, mcpServer: e.name },
      undefined,
      false
    );
  } catch {
    /* cloud reporting must never affect the reconcile */
  }
}

/** One reconcile pass. Exported for tests. */
export function runMcpReconcile(): void {
  // Auto-wrap does NOT touch TOML (Codex): smol-toml.stringify would reformat the
  // whole file (drop comments, risk value-shape drift on other tables). Codex is
  // nudge-only unattended; the user can wrap it explicitly via the CLI (which
  // backs the file up). (fix #8)
  const autoWrap = getConfig().settings.mcpAutoWrap === true;
  const baseline = loadBaseline();
  const creds = getCredentials(); // once per pass (fix #10)
  const fresh = inventoryMcp().filter((e) => e.state === 'ungoverned' && !baseline.has(idKey(e)));
  if (fresh.length === 0) return;

  const wrappedAgents = new Set<string>();
  let wrappedCount = 0;
  let nudgedCount = 0;
  let failedCount = 0;
  for (const e of fresh) {
    const doWrap = autoWrap && e.format !== 'toml';
    let wrapped = false;
    if (doWrap) {
      try {
        writeMcpEntry(e.mcpFile, e.format, e.name, toGateway(e.raw, e.name));
        wrappedAgents.add(e.agentLabel);
        wrappedCount++;
        wrapped = true;
      } catch {
        failedCount++; // not counted as wrapped; alerted as ungoverned below
      }
    } else {
      nudgedCount++;
    }
    // Baseline EVERY fresh entry — including a failed wrap (re-review): NOT
    // baselining it re-detects it as "new" every tick and re-fires the popup
    // forever (a notification storm on a durable failure e.g. a read-only config).
    // Nudge-once instead; the alert tells the user to run `node9 mcp gateway --all`.
    baseline.add(idKey(e));
    reportToCloud(e, wrapped, creds);
  }

  // ONE aggregated desktop notification per outcome. The `nudgedCount + failedCount`
  // fallback ensures we NEVER go silent about new ungoverned servers even when
  // every auto-wrap failed (fix #3 re-review) — the user is always told.
  if (wrappedCount > 0) {
    sendDesktopNotification(
      'node9: MCP servers governed',
      `Wrapped ${wrappedCount} new MCP server(s) — restart ${[...wrappedAgents].join(', ')} to activate.`
    );
  }
  const stillUngoverned = nudgedCount + failedCount;
  if (stillUngoverned > 0) {
    sendDesktopNotification(
      '⚠️ node9: ungoverned MCP server',
      `${stillUngoverned} new ungoverned MCP server(s) — run: node9 mcp gateway --all`
    );
  }
  saveBaseline(baseline);
}

/** Start the reconcile loop: once at daemon start, then on the configured
 *  interval (re-read each tick so a config/managed change applies live). */
export function startMcpReconciler(): void {
  setImmediate(() => {
    try {
      runMcpReconcile();
    } catch {
      /* never crash daemon startup */
    }
  });
  const schedule = (): void => {
    const mins = getConfig().settings.mcpReconcileIntervalMinutes ?? DEFAULT_INTERVAL_MIN;
    const clamped = Math.min(Math.max(Math.round(mins), 5), 1440);
    const t = setTimeout(() => {
      try {
        runMcpReconcile();
      } catch {
        /* swallow */
      }
      schedule();
    }, clamped * 60_000);
    t.unref();
  };
  schedule();
}

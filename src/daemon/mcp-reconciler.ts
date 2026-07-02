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
function reportToCloud(e: McpEntry, autoWrapped: boolean): void {
  try {
    const creds = getCredentials();
    if (!creds) return;
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
  const autoWrap = getConfig().settings.mcpAutoWrap === true;
  const baseline = loadBaseline();
  const fresh = inventoryMcp().filter((e) => e.state === 'ungoverned' && !baseline.has(idKey(e)));
  if (fresh.length === 0) return;

  const wrappedAgents = new Set<string>();
  for (const e of fresh) {
    if (autoWrap) {
      try {
        writeMcpEntry(e.mcpFile, e.format, e.name, toGateway(e.raw));
        wrappedAgents.add(e.agentLabel);
      } catch {
        /* a bad config never stops the pass */
      }
    }
    baseline.add(idKey(e)); // notify-once, whether wrapped or nudged
    reportToCloud(e, autoWrap);
  }

  // ONE aggregated desktop notification (the DLP-style warning).
  if (autoWrap) {
    sendDesktopNotification(
      'node9: MCP servers governed',
      `Wrapped ${fresh.length} new MCP server(s) — restart ${[...wrappedAgents].join(', ')} to activate.`
    );
  } else {
    sendDesktopNotification(
      '⚠️ node9: ungoverned MCP server',
      `${fresh.length} new ungoverned MCP server(s) — run: node9 mcp gateway --all`
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

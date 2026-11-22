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
import {
  inventoryMcp,
  inventoryServerKeys,
  toGateway,
  regateway,
  writeMcpEntry,
  migrateMcpLaunchers,
  type McpEntry,
} from '../mcp-wrap';
import { sendDesktopNotification } from '../ui/native';
import { getConfig, getCredentials } from '../config';
import { auditLocalAllow } from '../auth/cloud';
import { appendToLog, HOOK_DEBUG_LOG } from '../audit/index.js';
import { readMcpPins, writeMcpPins, type PinsFile } from '../mcp-pin';
import { readyLauncherArgv, createLauncherFromHookShim, pinsNode } from '../node9-shim';
import { mcpLaunchHealth, readMcpNodeFailures } from '../mcp-launch-health';

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

// ── Launcher pass ─────────────────────────────────────────────────────────────
// node9's own MCP entries that start as the bare `node9` run on the Node the
// agent's PATH holds. Under an old Node node9 refuses to run, and the agent
// reports only "failed to connect" for node9's server and for every server
// node9 wrapped. Attended setup moves those entries to the launcher
// (~/.node9/bin/node9), but an npm upgrade runs no setup, and a user who runs
// none keeps the dead entries. This pass is what reaches them.
//
//   1. No launcher: make it from the hook shim (the Node attended setup chose).
//   2. Move the entries to it. JSON only; an entry a person pinned and that
//      works is left. Silent, like the --config-name refresh: one log line each.
//   3. Entries still depend on PATH and node9 has refused to start this week:
//      tell the user once, with the command that fixes it.

const NODE_NUDGE_FILE = (): string => path.join(os.homedir(), '.node9', 'mcp-node-nudged.json');

function runLauncherPass(): void {
  if (process.platform === 'win32') return; // the launcher is a POSIX script
  const home = os.homedir();

  try {
    const made = createLauncherFromHookShim(home);
    if (made) {
      appendToLog(HOOK_DEBUG_LOG, {
        event: 'mcp-launcher-created',
        node: made.node,
        cli: made.cli,
      });
    }
  } catch (err) {
    appendToLog(HOOK_DEBUG_LOG, {
      event: 'mcp-launcher-create-failed',
      error: (err as Error)?.message,
    });
  }

  const moved = migrateMcpLaunchers({
    home,
    unattended: true,
    onError: (entry, err) =>
      appendToLog(HOOK_DEBUG_LOG, {
        event: 'mcp-launcher-migrate-failed',
        agent: entry.agent,
        name: entry.name,
        error: (err as Error)?.message,
      }),
  });
  for (const m of moved) {
    appendToLog(HOOK_DEBUG_LOG, {
      event: 'mcp-launcher-migrated',
      agent: m.agent,
      name: m.name,
      from: m.from,
    });
  }

  nudgeAboutNodeFailures(home);
}

/**
 * One desktop notification when node9's MCP entries are known to fail and this
 * pass could not fix them: there was no hook shim to make the launcher from,
 * the entry is in a TOML file the daemon does not rewrite, or the config is
 * not writable. Only where hook-debug.log holds a refusal from the last 7
 * days: a user whose bare `node9` works is never told about it. Once per
 * episode; the flag clears when no entry depends on PATH, so a later
 * regression is told again.
 */
function nudgeAboutNodeFailures(home: string): void {
  const flag = NODE_NUDGE_FILE();
  const dependent = mcpLaunchHealth(home).pathDependent;
  if (dependent.length === 0) {
    fs.rmSync(flag, { force: true });
    return;
  }
  if (fs.existsSync(flag)) return;
  // A node9 that is not JavaScript run by node (pnpm's wrapper, bun) has no
  // launcher to move to: `node9 heal` would change nothing for it.
  if (!pinsNode(process.execPath, process.argv[1] ?? '')) return;
  const failures = readMcpNodeFailures(home);
  if (!failures) return;
  const count = dependent.reduce((sum, g) => sum + g.names.length, 0);
  sendDesktopNotification(
    '⚠️ node9: MCP servers fail to start',
    `Node.js ${failures.version} is too old for node9, and ${count} MCP entr${count === 1 ? 'y' : 'ies'} (${dependent
      .map((g) => g.agentLabel)
      .join(', ')}) start on it. Run: node9 heal`
  );
  appendToLog(HOOK_DEBUG_LOG, {
    event: 'mcp-node-nudged',
    entries: count,
    node: failures.version,
  });
  try {
    fs.writeFileSync(flag, JSON.stringify({ notifiedAt: Date.now() }), { mode: 0o600 });
  } catch {
    /* not recorded: the next pass tells again, which is the safer side */
  }
}

/** One reconcile pass. Exported for tests. */
export function runMcpReconcile(): void {
  // Before the inventory: the refresh and wrap passes below then read the
  // entries as this pass left them. It must never stop the reconcile.
  try {
    runLauncherPass();
  } catch (err) {
    appendToLog(HOOK_DEBUG_LOG, {
      event: 'mcp-launcher-pass-failed',
      error: (err as Error)?.message,
    });
  }

  // Auto-wrap does NOT touch TOML (Codex): smol-toml.stringify would reformat the
  // whole file (drop comments, risk value-shape drift on other tables). Codex is
  // nudge-only unattended; the user can wrap it explicitly via the CLI (which
  // backs the file up). (fix #8)
  const autoWrap = getConfig().settings.mcpAutoWrap === true;
  const inv = inventoryMcp(); // once per pass — refresh + wrap read the same snapshot

  // ── R1 Layer 1: refresh the `--config-name` stamp on governed servers ──────────
  // A governed server wrapped before `--config-name` existed has no stable identity,
  // so the config-vs-connected join guesses env and phantoms (redis-prod). Re-wrap it
  // WITH the stamp — `regateway(raw, configKey)` — the same primitive `--rewrap`
  // uses. It keeps the entry's launcher, so a wrap that pins its Node stays pinned.
  // serverKey is unchanged (pins/app-perm rules survive),
  // writeMcpEntry backs up, and it's reversible via `ungateway`. Constraints:
  //   • SILENT — no desktop popup (R2 notification fatigue); a hook-debug line instead.
  //   • JSON only — never auto-rewrite TOML/Codex (smol-toml reformats the file, fix #8).
  //   • MISSING-only — never touch a user's deliberate custom `--config-name` (don't
  //     fight the user); already-stamped entries don't match, so it's idempotent.
  for (const e of inv) {
    if (e.state !== 'gatewayed' || e.format === 'toml') continue;
    if (e.args.includes('--config-name')) continue;
    const stamped = regateway(e.raw, e.name);
    if (!stamped) continue; // corrupt wrapper (no parseable --upstream) — leave it
    try {
      writeMcpEntry(e.mcpFile, e.format, e.name, stamped);
      appendToLog(HOOK_DEBUG_LOG, {
        event: 'mcp-config-name-refreshed',
        agent: e.agent,
        name: e.name,
      });
    } catch (err) {
      // Leave it; next tick retries. Never popup / crash the loop over a refresh —
      // but log so a PERMANENT failure (e.g. read-only config) is diagnosable
      // instead of retrying invisibly forever (CLAUDE.md: log guarded catches).
      appendToLog(HOOK_DEBUG_LOG, {
        event: 'mcp-config-name-refresh-failed',
        name: e.name,
        error: (err as Error)?.message,
      });
    }
  }

  const baseline = loadBaseline();
  const creds = getCredentials(); // once per pass (fix #10)

  // ── Orphan detection + stale removal (runs every tick, before early-return) ──
  reconcileStale(inv, creds);

  const fresh = inv.filter((e) => e.state === 'ungoverned' && !baseline.has(idKey(e)));
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
        // The launcher setup left, when there is one: a wrap written as the bare
        // `node9` starts on the agent's PATH Node, and where that is an old Node
        // the wrap takes the user's server down. The daemon never writes the
        // launcher itself (readyLauncherArgv).
        writeMcpEntry(e.mcpFile, e.format, e.name, toGateway(e.raw, e.name, readyLauncherArgv()));
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

const DEFAULT_STALE_DAYS = 7;

/** Stamp lastSeen on active pins, auto-remove pins stale beyond threshold. */
export function reconcileStale(
  inv: McpEntry[],
  creds: { apiKey: string; apiUrl: string } | null
): void {
  let pins: PinsFile;
  try {
    pins = readMcpPins();
  } catch {
    return; // corrupt pin file — don't crash the daemon
  }
  const serverKeys = Object.keys(pins.servers);
  if (serverKeys.length === 0) return;

  const liveKeys = inventoryServerKeys(inv);
  const now = new Date().toISOString();
  let dirty = false;

  for (const sk of serverKeys) {
    const pin = pins.servers[sk];
    if (liveKeys.has(sk)) {
      if (pin.lastSeen !== now) {
        pin.lastSeen = now;
        dirty = true;
      }
    } else if (!pin.lastSeen) {
      pin.lastSeen = pin.pinnedAt;
      dirty = true;
    }
  }

  const staleDays = getConfig().settings.mcpStaleAfterDays ?? DEFAULT_STALE_DAYS;
  // A1: only auto-remove when we POSITIVELY saw live servers this tick. An empty
  // liveKeys can't distinguish "no servers configured" from "every agent config
  // was unreadable" — and a wrongly-removed pin re-pins to whatever tools the
  // server presents next, silently resetting the rug-pull baseline. Fail closed:
  // keep the pins (lastSeen was still stamped/backfilled above; they age out
  // once inventory reads cleanly again).
  if (staleDays > 0 && liveKeys.size > 0) {
    const staleMs = staleDays * 86_400_000;
    for (const sk of serverKeys) {
      const pin = pins.servers[sk];
      if (liveKeys.has(sk)) continue;
      const age = Date.now() - Date.parse(pin.lastSeen ?? pin.pinnedAt);
      if (age >= staleMs) {
        appendToLog(HOOK_DEBUG_LOG, {
          event: 'mcp-pin-auto-removed',
          serverKey: sk,
          label: pin.label,
          lastSeen: pin.lastSeen,
          pinnedAt: pin.pinnedAt,
        });
        if (creds) {
          try {
            void auditLocalAllow(
              `mcp-server:${sk}`,
              {
                serverKey: sk,
                label: pin.label,
                lastSeen: pin.lastSeen,
                reason: 'stale',
                staleDays,
              },
              'mcp-server-removed',
              creds,
              { mcpServer: pin.label },
              undefined,
              false
            );
          } catch {
            /* cloud reporting must never affect the reconcile */
          }
        }
        delete pins.servers[sk];
        dirty = true;
      }
    }
  }

  if (dirty) {
    try {
      writeMcpPins(pins);
    } catch {
      /* never crash daemon on a pin write */
    }
  }
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

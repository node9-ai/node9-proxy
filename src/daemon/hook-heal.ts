// src/daemon/hook-heal.ts
// Agent-hook self-heal, P1 — detect + NUDGE (no config mutation).
//
// node9 governs an agent by installing hooks into that agent's own config. An
// agent's own update can silently rewrite that config and drop node9's hooks,
// leaving it ungoverned with no signal. `setupClaude()` already re-adds a missing
// hook on `node9 init` — this is the CONTINUOUS, passive version: on the daemon
// loop, watch for a node9-governed agent whose hooks went missing/stale and fire a
// ONE-shot nudge ("run node9 init"). No writes to agent configs in P1 — the
// mutating `node9 heal` / opt-in auto-heal are later phases.
//
// Mirrors mcp-reconciler.ts (same loop shape + notification channel). Persistence
// lives in hook-baseline.ts (pure fs) to avoid an import cycle with setup.
import { getAgentWiring } from '../agent-wiring';
import { sendDesktopNotification } from '../ui/native';
import { getConfig } from '../config';
import { checkPause } from '../auth/state';
import {
  loadHookBaseline,
  loadNotified,
  saveNotified,
  seedHookBaselineIfEmpty,
} from './hook-baseline';

const DEFAULT_INTERVAL_MIN = 60;

/** One detection pass. Exported for tests. NEVER mutates an agent config (P1). */
export function runHookHeal(home?: string): void {
  if (checkPause().paused) return; // respect `node9 pause`

  const wiring = getAgentWiring(home);

  // First run: seed intent from what's governed now (existing installs get coverage
  // without a re-init). A seeding pass never nudges — nothing to diff against yet.
  const wiredNow = wiring.filter((a) => a.wireState === 'wired').map((a) => a.id);
  if (seedHookBaselineIfEmpty(wiredNow, Date.now())) return;

  const baseline = loadHookBaseline();
  const notified = loadNotified();

  const newlyWiped: string[] = [];
  let changed = false;

  for (const a of wiring) {
    const governed = !!baseline[a.id]; // node9 intends to govern it
    const wired = a.wireState === 'wired';

    if (governed && a.installed && !wired) {
      // Should be governed, the agent is present, but its node9 hooks are gone/
      // stale/invalid. Nudge ONCE per unwired episode.
      if (!notified.has(a.id)) {
        notified.add(a.id);
        newlyWiped.push(a.label);
        changed = true;
      }
    } else if (wired && notified.has(a.id)) {
      // Re-wired (user ran init) → clear so a future wipe nudges again.
      notified.delete(a.id);
      changed = true;
    }
  }

  if (newlyWiped.length > 0) {
    sendDesktopNotification(
      '⚠️ node9: protection removed',
      `${newlyWiped.join(', ')} lost node9's hooks (likely an agent update). ` +
        `Run: node9 init  to restore protection.`
    );
  }
  if (changed) saveNotified(notified);
}

/** Start the heal loop: once at daemon start, then on the reconcile interval. */
export function startHookHeal(): void {
  setImmediate(() => {
    try {
      runHookHeal();
    } catch {
      /* never crash daemon startup */
    }
  });
  const schedule = (): void => {
    // Reuse the MCP reconcile cadence — hooks change rarely, no separate knob.
    const mins = getConfig().settings.mcpReconcileIntervalMinutes ?? DEFAULT_INTERVAL_MIN;
    const clamped = Math.min(Math.max(Math.round(mins), 5), 1440);
    const t = setTimeout(() => {
      try {
        runHookHeal();
      } catch {
        /* swallow */
      }
      schedule();
    }, clamped * 60_000);
    t.unref();
  };
  schedule();
}

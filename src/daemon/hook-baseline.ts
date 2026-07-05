// src/daemon/hook-baseline.ts
// Persistence for agent-hook self-heal (P1). Pure fs — imports nothing from
// setup/agent-wiring/config, so setup.ts and cli.ts can record/clear the baseline
// without an import cycle (agent-wiring imports setup).
//
//  - hooks-baseline.json     — node9's INTENDED governance (which agents it wired).
//                              Written by setupAgent, cleared by `node9 uninstall`.
//  - hook-heal-notified.json — which governed-but-now-unwired agents the daemon has
//                              already nudged about (dedup; re-armed on re-wire).
import fs from 'fs';
import path from 'path';
import os from 'os';

const BASELINE_FILE = path.join(os.homedir(), '.node9', 'hooks-baseline.json');
const NOTIFIED_FILE = path.join(os.homedir(), '.node9', 'hook-heal-notified.json');

export type HookBaseline = Record<string, { wiredAt: number }>;

export function loadHookBaseline(): HookBaseline {
  try {
    const raw = JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf-8')) as unknown;
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as HookBaseline) : {};
  } catch {
    return {};
  }
}

function saveHookBaseline(b: HookBaseline): void {
  try {
    const dir = path.dirname(BASELINE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(BASELINE_FILE, JSON.stringify(b, null, 2), { mode: 0o600 });
  } catch {
    /* never crash setup/daemon on a baseline write */
  }
}

/**
 * Record that node9 intends to govern `agentId`. Called from setupAgent after a
 * successful wire; `now` is injected so the caller owns the clock. Idempotent.
 */
export function recordHookBaseline(agentId: string, now: number): void {
  const b = loadHookBaseline();
  if (!b[agentId]) {
    b[agentId] = { wiredAt: now };
    saveHookBaseline(b);
  }
}

/**
 * First-run bootstrap: if there's NO baseline yet (fresh install, or right after
 * an uninstall), seed intent from the agents node9 governs RIGHT NOW so existing
 * installs get heal coverage without having to re-run `node9 init`. Returns true
 * when it seeded (the caller then skips detection this pass — there's no prior
 * intent to diff against). Safe post-uninstall: teardown leaves nothing wired, so
 * `governedNow` is empty and nothing is seeded.
 */
export function seedHookBaselineIfEmpty(governedNow: string[], now: number): boolean {
  if (Object.keys(loadHookBaseline()).length > 0) return false;
  if (governedNow.length === 0) return false;
  const seeded: HookBaseline = {};
  for (const id of governedNow) seeded[id] = { wiredAt: now };
  saveHookBaseline(seeded);
  return true;
}

/** Forget ALL intended governance — called from `node9 uninstall` (all-agent teardown). */
export function clearHookBaseline(): void {
  for (const f of [BASELINE_FILE, NOTIFIED_FILE]) {
    try {
      fs.rmSync(f, { force: true });
    } catch {
      /* ignore */
    }
  }
}

// ── Dedup set: governed agents already nudged while unwired ───────────────────
// Persisted so a daemon restart doesn't re-nudge; an agent is removed when it
// becomes wired again, so a FUTURE wipe re-nudges (re-arm on heal).
export function loadNotified(): Set<string> {
  try {
    const raw = JSON.parse(fs.readFileSync(NOTIFIED_FILE, 'utf-8')) as unknown;
    return new Set(Array.isArray(raw) ? (raw as string[]) : []);
  } catch {
    return new Set();
  }
}

export function saveNotified(s: Set<string>): void {
  try {
    const dir = path.dirname(NOTIFIED_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(NOTIFIED_FILE, JSON.stringify([...s]), { mode: 0o600 });
  } catch {
    /* ignore */
  }
}

// src/daemon/sync.ts
// Periodic sync of cloud policy rules to ~/.node9/rules-cache.json
// The daemon calls startCloudSync() once on startup; it reads the configured
// interval from ~/.node9/config.json (cloudSyncIntervalSeconds, else
// cloudSyncIntervalHours, else the 5h default — see resolveSyncIntervalMs).
// The proxy reads rules-cache.json via getConfig() to enforce cloud-defined rules
// even when offline.
import fs from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import { getConfig } from '../config/index.js';
import { runBlast } from '../cli/commands/blast.js';
import { runPosture } from '../posture/index.js';
import { shipPosture } from '../posture/ship.js';
import { buildPolicySnapshot } from '../policy-snapshot/build.js';
import { readMcpToolsConfig } from './mcp-tools.js';
import { shipPolicySnapshot } from '../policy-snapshot/ship.js';
import { readActiveShields, readShieldOverrides } from '../shields.js';
import {
  summarizeBlast,
  summarizeScan,
  CANONICAL_EXTRACTOR_VERSION,
  type ScanFinding,
  type ScanSignals,
} from '@node9/policy-engine';
import { tickScanWatcher, markUploadComplete, tickForensicBroadcast } from './scan-watermark.js';
import { broadcastForensic } from './state.js';
import { appendToLog, HOOK_DEBUG_LOG } from '../audit/index.js';

// One row per session delta sent on /scan/report. The BE stores
// these in ScanSessionSignals using INSERT-ON-CONFLICT INCREMENT, so
// these counts are *deltas* from this tick, not cumulative totals.
interface SessionDelta {
  runId: string;
  totalToolCalls: number;
  signals: ScanSignals;
}

// Local mapping from finding type → ScanSignals key. Mirrors the engine's
// FINDING_TO_SIGNAL but kept in the proxy because the engine doesn't
// export it (and re-vendoring the engine tarball just for one constant
// is more friction than this 10-line duplicate).
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
 * Group findings by sessionId into per-session deltas. Each delta also
 * carries the count of new tool-call lines parsed for that session in
 * this tick (passed in from the watermark).
 *
 * Sessions with zero findings AND zero tool calls are excluded — the BE
 * has nothing useful to write for them.
 *
 * Exported for unit tests.
 */
export function buildSessionDeltas(
  findings: ScanFinding[],
  toolCallsBySession: Record<string, number>
): SessionDelta[] {
  const bySession = new Map<string, ScanSignals>();
  for (const f of findings) {
    const signals = bySession.get(f.sessionId) ?? emptySignals();
    const key = FINDING_TO_SIGNAL[f.type];
    signals[key]++;
    bySession.set(f.sessionId, signals);
  }
  // Include sessions that had tool calls but no findings — the dashboard
  // still wants to attribute "47 tool calls" to that session.
  for (const sid of Object.keys(toolCallsBySession)) {
    if (!bySession.has(sid)) bySession.set(sid, emptySignals());
  }
  return [...bySession.entries()].map(([runId, signals]) => ({
    runId,
    totalToolCalls: toolCallsBySession[runId] ?? 0,
    signals,
  }));
}

// Computed lazily so tests can mock os.homedir() before any call
const rulesCacheFile = () => path.join(os.homedir(), '.node9', 'rules-cache.json');
const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept/policies/sync';
const DEFAULT_INTERVAL_HOURS = 5;
// Floor + ceiling for the resolved sync interval. The 15s floor keeps a
// misconfigured/aggressive value from hammering the API (the ETag/304 path
// makes empty polls cheap, but not free); the 24h ceiling is a sane upper bound.
const MIN_INTERVAL_SECONDS = 15;
const MAX_INTERVAL_SECONDS = 24 * 60 * 60;

/**
 * Resolve the cloud-sync interval (ms) from config. Precedence:
 *   cloudSyncIntervalSeconds  →  cloudSyncIntervalHours * 3600  →  default 5h.
 * Clamped to [MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS]. Pure (no I/O) so it's
 * unit-testable without timers.
 */
export function resolveSyncIntervalMs(settings: {
  cloudSyncIntervalSeconds?: number;
  cloudSyncIntervalHours?: number;
}): number {
  const rawSeconds =
    settings.cloudSyncIntervalSeconds ??
    (settings.cloudSyncIntervalHours ?? DEFAULT_INTERVAL_HOURS) * 3600;
  const clamped = Math.min(Math.max(rawSeconds, MIN_INTERVAL_SECONDS), MAX_INTERVAL_SECONDS);
  return clamped * 1000;
}

/**
 * Local cache file shape — kept backward-compatible (`rules` field name
 * preserved for the existing config-waterfall reader in `config/index.ts`).
 *
 * The `etag`, `panicMode`, `shadowMode`, `syncIntervalHours`, and
 * `workspaceId` fields are populated from the SaaS sync endpoint response.
 * `etag` is sent back as `If-None-Match` on the next sync to enable
 * cheap 304 polling. `panicMode` and `shadowMode` are stored here so
 * the policy engine can apply them when evaluating tool calls.
 */
export interface RulesCache {
  fetchedAt: string; // ISO-8601
  rules: unknown[];
  etag?: string;
  panicMode?: boolean;
  shadowMode?: boolean;
  syncIntervalHours?: number;
  workspaceId?: string;
  /** Cloud-managed active-shield names (Managed Config M1). */
  shields?: string[];
  /** Cloud-managed settings (Managed Config M2, baseline+lock). */
  managedConfig?: ManagedConfigCache;
}

/** Cloud-managed settings persisted in the cache (M2: mode + egress + dlp). */
export interface ManagedConfigCache {
  mode?: string;
  egress?: {
    enabled?: boolean;
    mode?: string;
    allow?: string[];
    deny?: string[];
    allowPrivate?: boolean;
  };
  dlp?: { enabled?: boolean; pii?: string };
  approvers?: { native?: boolean; browser?: boolean; cloud?: boolean; terminal?: boolean };
  reviewChannel?: string;
  approvalTimeoutMs?: number;
  injectionScan?: { enabled: boolean; minConfidence: string; allow: string[] };
  loopDetection?: { enabled: boolean; threshold: number; windowSeconds: number };
  skillPinning?: { enabled: boolean; mode: string; roots: string[] };
  jailPaths?: { path: string; verdict: string }[];
  trustedHosts?: string[];
  appPermissions?: Record<string, Record<string, string>>;
  locked: string[];
}

/**
 * Result of a single fetch — either a fresh policy snapshot or a 304
 * indicating the server's policy hasn't changed since the last sync.
 */
type FetchResult = { kind: 'fresh'; body: CloudPolicyBody; etag?: string } | { kind: 'unchanged' };

interface CloudPolicyBody {
  policies?: unknown[];
  rules?: unknown[]; // legacy field name from older /api/v1/policy responses
  panicMode?: boolean;
  shadowMode?: boolean;
  syncIntervalHours?: number;
  workspaceId?: string;
  shields?: unknown[]; // cloud-managed shield names (Managed Config M1)
  managedConfig?: {
    mode?: unknown;
    egress?: {
      enabled?: unknown;
      mode?: unknown;
      allow?: unknown;
      deny?: unknown;
      allowPrivate?: unknown;
    };
    dlp?: { enabled?: unknown; pii?: unknown };
    approvers?: { native?: unknown; browser?: unknown; cloud?: unknown; terminal?: unknown };
    reviewChannel?: unknown;
    approvalTimeoutMs?: unknown;
    injectionScan?: { enabled?: unknown; minConfidence?: unknown; allow?: unknown };
    loopDetection?: { enabled?: unknown; threshold?: unknown; windowSeconds?: unknown };
    skillPinning?: { enabled?: unknown; mode?: unknown; roots?: unknown };
    jailPaths?: { path?: unknown; verdict?: unknown }[];
    trustedHosts?: unknown;
    appPermissions?: unknown;
    locked?: unknown;
  }; // M2 settings
}

export function readCredentials(): { apiKey: string; apiUrl: string } | null {
  // 1. Environment variable
  if (process.env.NODE9_API_KEY) {
    return {
      apiKey: process.env.NODE9_API_KEY,
      apiUrl: process.env.NODE9_API_URL ?? DEFAULT_API_URL,
    };
  }
  // 2. ~/.node9/credentials.json (same pattern as getCredentials() in config/index.ts)
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
    const profileName = process.env.NODE9_PROFILE ?? 'default';
    const profile = creds[profileName] as Record<string, unknown> | undefined;
    if (typeof profile?.apiKey === 'string' && profile.apiKey.length > 0) {
      return {
        apiKey: profile.apiKey,
        apiUrl:
          typeof profile.apiUrl === 'string'
            ? // Credentials store the firewall base URL (e.g.
              // `https://api.node9.ai/api/v1/intercept`) so existing CLI
              // calls keep working. Sync lives at `/intercept/policies/sync`
              // — append the suffix when the stored URL ends in `/intercept`.
              // Anything else is taken as-is so users can override the full
              // URL via NODE9_API_URL or a non-standard apiUrl.
              /\/intercept$/.test(profile.apiUrl)
              ? profile.apiUrl + '/policies/sync'
              : profile.apiUrl
            : DEFAULT_API_URL,
      };
    }
    if (typeof creds.apiKey === 'string' && creds.apiKey.length > 0) {
      return { apiKey: creds.apiKey, apiUrl: DEFAULT_API_URL };
    }
  } catch {
    /* fall through */
  }
  return null;
}

/**
 * Read the existing cache file to extract the last-known ETag. Used to
 * send `If-None-Match` on the next sync so the server can short-circuit
 * with 304 when nothing has changed. Silent fallback on any error —
 * a missing or corrupt cache simply means "no cached etag, send 200".
 */
function readCachedEtag(): string | undefined {
  try {
    const raw = JSON.parse(fs.readFileSync(rulesCacheFile(), 'utf-8')) as Record<string, unknown>;
    return typeof raw.etag === 'string' ? raw.etag : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The cloud-pushed sync cadence (hours) from the last sync, if any. Silent
 * fallback on a missing/corrupt cache. Used so the dashboard's admin-set
 * interval — not just the local config — controls how often this device polls.
 */
function readCachedSyncIntervalHours(): number | undefined {
  try {
    const raw = JSON.parse(fs.readFileSync(rulesCacheFile(), 'utf-8')) as Record<string, unknown>;
    return typeof raw.syncIntervalHours === 'number' ? raw.syncIntervalHours : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Pick the sync interval (ms): the cloud-pushed cadence wins (the dashboard
 * decides), else the local config. Both routed through resolveSyncIntervalMs so
 * the [15s, 24h] clamp always applies. Pure — no I/O — so it's unit-testable.
 */
export function pickSyncIntervalMs(
  cloudHours: number | undefined,
  localSettings: {
    cloudSyncIntervalSeconds?: number;
    cloudSyncIntervalHours?: number;
  }
): number {
  if (typeof cloudHours === 'number' && Number.isFinite(cloudHours)) {
    return resolveSyncIntervalMs({ cloudSyncIntervalHours: cloudHours });
  }
  return resolveSyncIntervalMs(localSettings);
}

/** The effective interval now: cloud-cached cadence over local config. */
export function effectiveSyncIntervalMs(): number {
  return pickSyncIntervalMs(readCachedSyncIntervalHours(), getConfig().settings);
}

function fetchCloudPolicy(
  apiKey: string,
  apiUrl: string,
  ifNoneMatch?: string
): Promise<FetchResult> {
  const parsed = new URL(apiUrl);
  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  };
  if (ifNoneMatch) headers['If-None-Match'] = `"${ifNoneMatch}"`;

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) : undefined,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers,
        timeout: 10_000,
      },
      (res) => {
        // 304 Not Modified — server confirms our cache is still valid.
        // No body to parse; the caller keeps the existing cache as-is.
        if (res.statusCode === 304) {
          // Drain the stream so the connection can be reused / closed cleanly.
          res.resume();
          resolve({ kind: 'unchanged' });
          return;
        }

        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`API returned ${res.statusCode ?? 'unknown'}`));
            return;
          }
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString('utf-8')) as
              | CloudPolicyBody
              | unknown[];
            const normalized: CloudPolicyBody = Array.isArray(body) ? { policies: body } : body;
            // Strip surrounding quotes from the ETag header per RFC 7232 §
            // 2.3 — entity tags are quoted on the wire but compared as opaque
            // strings.
            const rawEtag = res.headers.etag;
            const etag = typeof rawEtag === 'string' ? rawEtag.replace(/^"|"$/g, '') : undefined;
            resolve({ kind: 'fresh', body: normalized, etag });
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Cloud policy fetch timed out'));
    });
    req.end();
  });
}

/**
 * Pulls the rules array out of a server response, accommodating three
 * historical shapes:
 *   - new endpoint:  `{ policies: [...] }`
 *   - legacy field:  `{ rules: [...] }`
 *   - oldest:        bare array
 *
 * Returns an empty array on any unrecognised shape. Exported for unit tests.
 */
export function extractRules(body: CloudPolicyBody): unknown[] {
  if (Array.isArray(body.policies)) return body.policies;
  if (Array.isArray(body.rules)) return body.rules;
  return [];
}

/** Cloud-managed shield names from the sync body (Managed Config M1). */
export function extractShields(body: CloudPolicyBody): string[] {
  return Array.isArray(body.shields)
    ? body.shields.filter((s): s is string => typeof s === 'string')
    : [];
}

/** Clamp to a positive int in [min,max]; default when unusable (mirrors the service). */
function coerceInt(v: unknown, min: number, max: number, dflt: number): number {
  return typeof v === 'number' && Number.isFinite(v)
    ? Math.min(Math.max(Math.round(v), min), max)
    : dflt;
}

/**
 * Cloud-managed settings from the sync body (Managed Config M2). Returns
 * undefined when nothing is managed so the cache stays minimal. Defensive
 * filtering keeps junk out of the cache the proxy applies.
 */

export function extractManagedConfig(body: CloudPolicyBody): ManagedConfigCache | undefined {
  const mc = body.managedConfig;
  if (!mc || typeof mc !== 'object') return undefined;
  const out: ManagedConfigCache = {
    locked: Array.isArray(mc.locked)
      ? mc.locked.filter((f): f is string => typeof f === 'string')
      : [],
  };
  if (typeof mc.mode === 'string') out.mode = mc.mode;
  // M2b + Step 2: egress.enabled (bool) + mode (string) + allow/deny (string[])
  // + allowPrivate (bool).
  if (mc.egress && typeof mc.egress === 'object') {
    const e: ManagedConfigCache['egress'] = {};
    if (typeof mc.egress.enabled === 'boolean') e.enabled = mc.egress.enabled;
    if (typeof mc.egress.mode === 'string') e.mode = mc.egress.mode;
    const cleanHosts = (v: unknown): string[] =>
      Array.isArray(v) ? v.filter((h): h is string => typeof h === 'string') : [];
    const allow = cleanHosts(mc.egress.allow);
    const deny = cleanHosts(mc.egress.deny);
    if (allow.length) e.allow = allow;
    if (deny.length) e.deny = deny;
    if (typeof mc.egress.allowPrivate === 'boolean') {
      e.allowPrivate = mc.egress.allowPrivate;
    }
    if (
      e.enabled !== undefined ||
      e.mode !== undefined ||
      e.allow !== undefined ||
      e.deny !== undefined ||
      e.allowPrivate !== undefined
    ) {
      out.egress = e;
    }
  }
  // M2c: dlp.enabled (bool) + dlp.pii (string).
  if (mc.dlp && typeof mc.dlp === 'object') {
    const d: { enabled?: boolean; pii?: string } = {};
    if (typeof mc.dlp.enabled === 'boolean') d.enabled = mc.dlp.enabled;
    if (typeof mc.dlp.pii === 'string') d.pii = mc.dlp.pii;
    if (d.enabled !== undefined || d.pii !== undefined) out.dlp = d;
  }
  // Preferences: approvers (4 bools — where approvals may happen).
  if (mc.approvers && typeof mc.approvers === 'object') {
    const a: NonNullable<ManagedConfigCache['approvers']> = {};
    for (const k of ['native', 'browser', 'cloud', 'terminal'] as const) {
      if (typeof mc.approvers[k] === 'boolean') a[k] = mc.approvers[k] as boolean;
    }
    if (Object.keys(a).length > 0) out.approvers = a;
  }
  // Preferences v2: reviewChannel ('ask'|'approver') + approvalTimeoutMs (number).
  if (mc.reviewChannel === 'ask' || mc.reviewChannel === 'approver') {
    out.reviewChannel = mc.reviewChannel;
  }
  if (typeof mc.approvalTimeoutMs === 'number' && mc.approvalTimeoutMs >= 0) {
    out.approvalTimeoutMs = mc.approvalTimeoutMs;
  }
  // Detection: injectionScan { enabled, minConfidence, allow } — coerced.
  if (mc.injectionScan && typeof mc.injectionScan === 'object') {
    const i = mc.injectionScan;
    out.injectionScan = {
      enabled: i.enabled === true,
      minConfidence: i.minConfidence === 'high' ? 'high' : 'medium',
      allow: Array.isArray(i.allow)
        ? i.allow.filter((x): x is string => typeof x === 'string')
        : [],
    };
  }
  // Detection: loopDetection + skillPinning — coerced.
  if (mc.loopDetection && typeof mc.loopDetection === 'object') {
    const l = mc.loopDetection;
    out.loopDetection = {
      enabled: l.enabled === true,
      threshold: coerceInt(l.threshold, 1, 1000, 5),
      windowSeconds: coerceInt(l.windowSeconds, 1, 3600, 120),
    };
  }
  if (mc.skillPinning && typeof mc.skillPinning === 'object') {
    const sk = mc.skillPinning;
    out.skillPinning = {
      enabled: sk.enabled === true,
      mode: sk.mode === 'block' ? 'block' : 'warn',
      roots: Array.isArray(sk.roots)
        ? sk.roots.filter((x): x is string => typeof x === 'string')
        : [],
    };
  }
  if (Array.isArray(mc.jailPaths)) {
    const jail = mc.jailPaths
      .map((jp) => ({
        path: typeof jp?.path === 'string' ? jp.path.trim() : '',
        verdict: jp?.verdict === 'review' ? 'review' : 'block',
      }))
      .filter((jp) => jp.path);
    if (jail.length) out.jailPaths = jail;
  }
  if (Array.isArray(mc.trustedHosts)) {
    // Drop broad single-label wildcards (*.com) — matches the BE + local
    // addTrustedHost guard so a hand-edited/legacy list can't neuter exfil
    // detection fleet-wide.
    const hosts = mc.trustedHosts.filter(
      (h): h is string => typeof h === 'string' && (!h.startsWith('*.') || h.slice(2).includes('.'))
    );
    if (hosts.length) out.trustedHosts = hosts;
  }
  if (
    mc.appPermissions &&
    typeof mc.appPermissions === 'object' &&
    !Array.isArray(mc.appPermissions)
  ) {
    const ap: Record<string, Record<string, string>> = {};
    for (const [srv, tools] of Object.entries(mc.appPermissions)) {
      if (!tools || typeof tools !== 'object' || Array.isArray(tools)) continue;
      const m: Record<string, string> = {};
      for (const [t, d] of Object.entries(tools as Record<string, unknown>)) {
        if (d === 'allow' || d === 'review' || d === 'block') m[t] = d;
      }
      if (Object.keys(m).length) ap[srv] = m;
    }
    if (Object.keys(ap).length) out.appPermissions = ap;
  }
  // Nothing actually managed → omit entirely.
  return out.mode !== undefined ||
    out.egress !== undefined ||
    out.dlp !== undefined ||
    out.approvers !== undefined ||
    out.reviewChannel !== undefined ||
    out.approvalTimeoutMs !== undefined ||
    out.injectionScan !== undefined ||
    out.loopDetection !== undefined ||
    out.skillPinning !== undefined ||
    out.jailPaths !== undefined ||
    out.trustedHosts !== undefined ||
    out.appPermissions !== undefined
    ? out
    : undefined;
}

/**
 * Write the policy cache atomically. Best-effort: directory creation
 * failures fall through silently — the proxy will fall back to local
 * config and surface the issue via `node9 sync` if the user runs it
 * explicitly.
 */
function writeCache(cache: RulesCache): void {
  const dir = path.dirname(rulesCacheFile());
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(rulesCacheFile(), JSON.stringify(cache, null, 2) + '\n', 'utf-8');
}

async function syncOnce(): Promise<void> {
  const creds = readCredentials();
  if (!creds) return; // No API key configured — silent no-op

  try {
    const result = await fetchCloudPolicy(creds.apiKey, creds.apiUrl, readCachedEtag());
    if (result.kind === 'unchanged') {
      // 304 — keep existing cache as-is. Server confirmed nothing changed.
    } else {
      const cache: RulesCache = {
        fetchedAt: new Date().toISOString(),
        rules: extractRules(result.body),
        etag: result.etag,
        panicMode: result.body.panicMode,
        shadowMode: result.body.shadowMode,
        syncIntervalHours: result.body.syncIntervalHours,
        workspaceId: result.body.workspaceId,
        shields: extractShields(result.body),
        managedConfig: extractManagedConfig(result.body),
      };
      writeCache(cache);
    }
  } catch {
    // Best-effort — stale cache (or no cache) is fine; proxy falls back to local config
  }

  // After the policy fetch (success or 304), push a fresh blast snapshot
  // so the SaaS can render workspace-wide disk-exposure aggregates. This
  // is fire-and-forget — never blocks policy sync, never throws to the
  // caller. Opt-out via NODE9_BLAST_DISABLE=1 for paranoid devs who don't
  // want any path-shaped data on the wire.
  if (process.env.NODE9_BLAST_DISABLE !== '1') {
    void pushBlastSnapshot(creds);
  }

  // Same pattern for the forward-only scan: walk JSONL deltas, summarise,
  // POST to /intercept/scan/report. Watermark module is the source of
  // truth for "what's new since last tick"; it never reads historical
  // content. Opt-out via NODE9_SCAN_DISABLE=1.
  if (process.env.NODE9_SCAN_DISABLE !== '1') {
    void pushScanSnapshot(creds);
  }

  // Same pattern for posture: run the secrets/egress/gate scorecard and POST
  // it so the SaaS Posture tab stays fresh without a manual `node9 posture
  // --ship`. Fire-and-forget. Opt-out via NODE9_POSTURE_DISABLE=1.
  if (process.env.NODE9_POSTURE_DISABLE !== '1') {
    void pushPostureSnapshot(creds);
  }

  // Config mirror: ship the effective local policy so the dashboard can show
  // what this machine enforces. Opt-out via NODE9_POLICY_MIRROR_DISABLE=1.
  if (process.env.NODE9_POLICY_MIRROR_DISABLE !== '1') {
    void pushPolicySnapshot(creds);
  }
}

/**
 * Build the network-safe blast summary and POST it to the SaaS. Fire-and-
 * forget — every error path is silent. Failure here must never break the
 * policy-sync loop.
 *
 * Endpoint shape: POST /intercept/blast/report (sibling of /policies/sync,
 * derived from the same credentials apiUrl).
 */
async function pushBlastSnapshot(creds: { apiKey: string; apiUrl: string }): Promise<void> {
  try {
    const result = runBlast();
    const summary = summarizeBlast(result);

    // Derive the blast endpoint from the policy-sync URL the credentials
    // use. The sync URL ends in `/policies/sync`; replace the last two
    // segments with `/blast/report` so we hit the sibling endpoint.
    // If the URL doesn't match the expected shape, skip the push — better
    // silent no-op than guessing at the host.
    const blastUrl = creds.apiUrl.endsWith('/policies/sync')
      ? creds.apiUrl.replace(/\/policies\/sync$/, '/blast/report')
      : null;
    if (!blastUrl) return;

    const parsed = new URL(blastUrl);
    await new Promise<void>((resolve) => {
      const req = https.request(
        {
          hostname: parsed.hostname,
          port: parsed.port ? parseInt(parsed.port, 10) : undefined,
          path: parsed.pathname + parsed.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${creds.apiKey}`,
          },
          timeout: 10_000,
        },
        (res) => {
          // Drain & discard — we don't need the body, but we do need to
          // let the connection close cleanly.
          res.resume();
          res.on('end', resolve);
          res.on('error', () => resolve());
        }
      );
      req.on('error', () => resolve());
      req.on('timeout', () => {
        req.destroy();
        resolve();
      });
      req.write(JSON.stringify(summary));
      req.end();
    });
  } catch {
    // Silent — never break sync over a blast push.
  }
}

/**
 * Run the posture scorecard and POST the redacted snapshot to the SaaS.
 * Fire-and-forget — mirrors pushBlastSnapshot's failure mode (never throws,
 * never blocks sync). Reuses shipPosture, which derives `/posture/report`
 * from the same `/policies/sync` creds URL — so there is no network code here.
 *
 * cwd is pinned to $HOME: the daemon has no project cwd, and the home-level
 * credential checks (SSH/AWS/etc.) are the meaningful signal for a per-machine
 * snapshot. Same redacted body as the on-demand `node9 posture --ship`.
 */
async function pushPostureSnapshot(creds: { apiKey: string; apiUrl: string }): Promise<void> {
  try {
    const home = os.homedir();
    const result = await runPosture({ home, cwd: home });
    await shipPosture(result, creds);
  } catch {
    // Silent — never break sync over a posture push.
  }
}

// Config mirror (Phase 1b): ship this machine's EFFECTIVE local policy so the
// dashboard's Machines view shows what it enforces. Fire-and-forget like the
// other pushes; opt-out via NODE9_POLICY_MIRROR_DISABLE=1.
async function pushPolicySnapshot(creds: { apiKey: string; apiUrl: string }): Promise<void> {
  try {
    const body = buildPolicySnapshot(
      getConfig(),
      readActiveShields(),
      readShieldOverrides(),
      readMcpToolsConfig()
    );
    await shipPolicySnapshot(body, creds);
  } catch {
    // Silent — never break sync over a policy-mirror push.
  }
}

/** `node9 policy push` — mirror this machine's policy to the dashboard now. */
export async function runPolicyPush(): Promise<{ ok: true } | { ok: false; reason: string }> {
  const creds = readCredentials();
  if (!creds) {
    return {
      ok: false,
      reason: 'No API key configured. Add credentials with: node9 login',
    };
  }
  try {
    const body = buildPolicySnapshot(
      getConfig(),
      readActiveShields(),
      readShieldOverrides(),
      readMcpToolsConfig()
    );
    const sent = await shipPolicySnapshot(body, creds);
    return sent ? { ok: true } : { ok: false, reason: 'Push failed (network or server error)' };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Run the forward-only scan watermark and POST the summary to the SaaS.
 * Fire-and-forget. Mirrors pushBlastSnapshot one-for-one, including URL
 * derivation (replace `/policies/sync` → `/scan/report`) and silent
 * failure mode.
 *
 * Privacy: the watermark module produces ScanFinding objects that contain
 * pattern names + counts only; summarizeScan reduces them to a per-tier
 * aggregate. Nothing in this payload contains prompt text, tool args, or
 * file paths.
 */
// Exported for tests. Internal — called from syncOnce on the policy-sync
// timer in production. The exported surface lets sync.test.ts assert the
// POST builder dispatches on tick.uploadAs ('totals' vs 'deltas') without
// driving the full timer loop.
export async function pushScanSnapshot(creds: { apiKey: string; apiUrl: string }): Promise<void> {
  try {
    const tick = await tickScanWatcher();
    // Refuse to POST when the watermark file is from a newer daemon —
    // we don't trust our own state machine for that case (see
    // scan-watermark.ts WatermarkState 'schema-future').
    if (tick.schemaFuture) return;
    // Skip the network round-trip when there's nothing new to report —
    // empty summaries waste an API call and inflate the SaaS rate limit.
    if (tick.findings.length === 0 && tick.totalToolCalls === 0) {
      return;
    }
    const summary = summarizeScan(tick.findings, {
      totalToolCalls: tick.totalToolCalls,
    });
    // Per-session breakdown — sibling to the workspace-level summary.
    // Powers the Sessions tab. New on the wire; BE writes to the new
    // ScanSessionSignals table independently of ScanSnapshot.
    //
    // Wire-field choice depends on tick.uploadAs:
    //   'deltas' (normal flow) → sessionDeltas, BE atomic-increments.
    //   'totals' (first tick after extractor-stale reset) → sessionTotals,
    //     BE replaces the whole row. Avoids double-counting on top of any
    //     prior `node9 scan --upload-history` baseline. See
    //     scan-watermark.ts WatermarkState 'extractor-stale' for the
    //     reset trigger.
    const perSession = buildSessionDeltas(tick.findings, tick.toolCallsBySession);

    const scanUrl = creds.apiUrl.endsWith('/policies/sync')
      ? creds.apiUrl.replace(/\/policies\/sync$/, '/scan/report')
      : null;
    if (!scanUrl) return;

    const body =
      tick.uploadAs === 'totals'
        ? { ...summary, sessionTotals: perSession, extractorVersion: CANONICAL_EXTRACTOR_VERSION }
        : { ...summary, sessionDeltas: perSession, extractorVersion: CANONICAL_EXTRACTOR_VERSION };

    const parsed = new URL(scanUrl);
    let posted = false;
    await new Promise<void>((resolve) => {
      const req = https.request(
        {
          hostname: parsed.hostname,
          port: parsed.port ? parseInt(parsed.port, 10) : undefined,
          path: parsed.pathname + parsed.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${creds.apiKey}`,
          },
          timeout: 10_000,
        },
        (res) => {
          // Treat 2xx as success; other status codes leave pendingResetUploadAs
          // set so the next tick retries with sessionTotals (idempotent on the BE).
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            posted = true;
          }
          res.resume();
          res.on('end', resolve);
          res.on('error', () => resolve());
        }
      );
      req.on('error', () => resolve());
      req.on('timeout', () => {
        req.destroy();
        resolve();
      });
      req.write(JSON.stringify(body));
      req.end();
    });

    // Clear the one-shot post-reset flag only after the overwrite POST
    // landed. If the network failed, a future tick re-tries with
    // sessionTotals — safe because the BE upsert is idempotent on the
    // overwrite path.
    if (posted && tick.uploadAs === 'totals') {
      markUploadComplete();
    }
  } catch {
    // Silent — never break sync over a scan push.
  }
}

/**
 * Run a single cloud policy sync and return a result summary.
 * Exported for use by `node9 sync` CLI command.
 */
export async function runCloudSync(): Promise<
  | { ok: true; rules: number; fetchedAt: string; unchanged?: boolean }
  | { ok: false; reason: string }
> {
  const creds = readCredentials();
  if (!creds) {
    return { ok: false, reason: 'No API key configured. Add credentials with: node9 login' };
  }
  // Whether the policy fetch succeeded or failed, kick off the blast
  // push fire-and-forget so the manual `node9 policy sync` command also
  // refreshes the SaaS-side disk exposure aggregate. Same opt-out env
  // var as the daemon path. Scan piggybacks the same way.
  const maybePushBlast = () => {
    if (process.env.NODE9_BLAST_DISABLE !== '1') {
      void pushBlastSnapshot(creds);
    }
    if (process.env.NODE9_SCAN_DISABLE !== '1') {
      void pushScanSnapshot(creds);
    }
    if (process.env.NODE9_POSTURE_DISABLE !== '1') {
      void pushPostureSnapshot(creds);
    }
    if (process.env.NODE9_POLICY_MIRROR_DISABLE !== '1') {
      void pushPolicySnapshot(creds);
    }
  };

  try {
    const result = await fetchCloudPolicy(creds.apiKey, creds.apiUrl, readCachedEtag());
    if (result.kind === 'unchanged') {
      // 304 — keep existing cache. Report success against the cached
      // counts so the CLI still tells the user how many rules are active.
      const status = getCloudSyncStatus();
      maybePushBlast();
      return status.cached
        ? { ok: true, rules: status.rules, fetchedAt: status.fetchedAt, unchanged: true }
        : { ok: true, rules: 0, fetchedAt: new Date().toISOString(), unchanged: true };
    }
    const cache: RulesCache = {
      fetchedAt: new Date().toISOString(),
      rules: extractRules(result.body),
      etag: result.etag,
      panicMode: result.body.panicMode,
      shadowMode: result.body.shadowMode,
      syncIntervalHours: result.body.syncIntervalHours,
      workspaceId: result.body.workspaceId,
      shields: extractShields(result.body),
      managedConfig: extractManagedConfig(result.body),
    };
    writeCache(cache);
    maybePushBlast();
    return { ok: true, rules: cache.rules.length, fetchedAt: cache.fetchedAt };
  } catch (err) {
    maybePushBlast();
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Return info about the current rules cache (last fetch time, rule count,
 * cloud-pushed runtime flags). Used by `node9 policy status` and the daemon
 * HUD to show admins/users whether their workspace has any active policy
 * overrides in effect.
 */
export function getCloudSyncStatus():
  | { cached: false }
  | {
      cached: true;
      rules: number;
      fetchedAt: string;
      panicMode?: boolean;
      shadowMode?: boolean;
      workspaceId?: string;
      syncIntervalHours?: number;
    } {
  try {
    const raw = JSON.parse(fs.readFileSync(rulesCacheFile(), 'utf-8')) as Record<string, unknown>;
    if (!Array.isArray(raw.rules) || typeof raw.fetchedAt !== 'string') return { cached: false };
    return {
      cached: true,
      rules: (raw.rules as unknown[]).length,
      fetchedAt: raw.fetchedAt,
      panicMode: typeof raw.panicMode === 'boolean' ? raw.panicMode : undefined,
      shadowMode: typeof raw.shadowMode === 'boolean' ? raw.shadowMode : undefined,
      workspaceId: typeof raw.workspaceId === 'string' ? raw.workspaceId : undefined,
      syncIntervalHours:
        typeof raw.syncIntervalHours === 'number' ? raw.syncIntervalHours : undefined,
    };
  } catch {
    return { cached: false };
  }
}

/**
 * Return the raw rules array from the cache, or null if not available.
 */
export function getCloudRules(): unknown[] | null {
  try {
    const raw = JSON.parse(fs.readFileSync(rulesCacheFile(), 'utf-8')) as Record<string, unknown>;
    return Array.isArray(raw.rules) ? (raw.rules as unknown[]) : null;
  } catch {
    return null;
  }
}

/**
 * Start the background cloud-policy sync loop.
 * Called once by startDaemon(). Timer is unref'd so it doesn't prevent process exit.
 */
export function startCloudSync(): void {
  // Self-rescheduling: re-resolve the interval after every sync so a changed
  // cloud cadence (pushed on the last sync) takes effect on the next cycle, not
  // only on daemon restart. The cloud value wins over local config.
  const scheduleNext = (ms: number): void => {
    const t = setTimeout(() => {
      // syncOnce handles its own errors; reschedule regardless so the loop
      // never dies on a transient failure.
      void syncOnce()
        .catch(() => {})
        .finally(() => scheduleNext(effectiveSyncIntervalMs()));
    }, ms);
    t.unref();
  };

  // First sync 30 s after boot (avoids slowing daemon boot), then on the interval.
  scheduleNext(30_000);
}

// Local-broadcast cadence for forensic findings. Decoupled from the SaaS
// sync interval (hourly) so the monitor's RISK panel updates within ~30 s
// of a finding instead of waiting a full hour. The two paths use separate
// state: this timer maintains in-memory file offsets via tickForensicBroadcast,
// while the SaaS path advances the persistent watermark via tickScanWatcher.
const FORENSIC_BROADCAST_INTERVAL_MS = 30_000;
const FORENSIC_INITIAL_DELAY_MS = 5_000;

// Per-process in-memory offsets, keyed by JSONL file path. Reset on daemon
// restart — first tick after start initializes each file's offset to its
// current EOF, so historical findings are not re-broadcast.
const forensicBroadcastOffsets = new Map<string, number>();

/**
 * Start the local-broadcast loop for forensic findings.
 * Called once by startDaemon(). Timer is unref'd so it doesn't prevent
 * process exit. Errors inside the tick never propagate — the timer must
 * keep firing even if a single tick fails.
 */
export function startForensicBroadcast(): void {
  const tick = async () => {
    try {
      const findings = await tickForensicBroadcast(forensicBroadcastOffsets);
      for (const f of findings) broadcastForensic(f);
    } catch (err) {
      // Never break the timer loop — the next tick re-attempts. But do
      // record the failure in hook-debug.log so pathological JSONL parse
      // errors / fs problems are diagnosable. Mirrors the pattern in
      // src/cli/commands/log.ts.
      const msg = err instanceof Error ? err.message : String(err);
      appendToLog(HOOK_DEBUG_LOG, {
        ts: new Date().toISOString(),
        kind: 'forensic-broadcast-error',
        error: msg,
      });
    }
  };

  const initial = setTimeout(() => void tick(), FORENSIC_INITIAL_DELAY_MS);
  initial.unref();

  const recurring = setInterval(() => void tick(), FORENSIC_BROADCAST_INTERVAL_MS);
  recurring.unref();
}

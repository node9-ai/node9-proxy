// src/daemon/sync.ts
// Periodic sync of cloud policy rules to ~/.node9/rules-cache.json
// The daemon calls startCloudSync() once on startup; it reads the configured
// interval from ~/.node9/config.json (settings.cloudSyncIntervalHours, default 5).
// The proxy reads rules-cache.json via getConfig() to enforce cloud-defined rules
// even when offline.
import fs from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import { getConfig } from '../config/index.js';
import { runBlast } from '../cli/commands/blast.js';
import { summarizeBlast } from '@node9/policy-engine';

// Computed lazily so tests can mock os.homedir() before any call
const rulesCacheFile = () => path.join(os.homedir(), '.node9', 'rules-cache.json');
const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept/policies/sync';
const DEFAULT_INTERVAL_HOURS = 5;
const MIN_INTERVAL_HOURS = 1;

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
}

function readCredentials(): { apiKey: string; apiUrl: string } | null {
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
  // var as the daemon path.
  const maybePushBlast = () => {
    if (process.env.NODE9_BLAST_DISABLE !== '1') {
      void pushBlastSnapshot(creds);
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
  const rawHours = getConfig().settings.cloudSyncIntervalHours ?? DEFAULT_INTERVAL_HOURS;
  // Clamp to a reasonable minimum so a misconfigured value of 0 doesn't hammer the API
  const intervalHours = Math.max(rawHours, MIN_INTERVAL_HOURS);
  const intervalMs = intervalHours * 60 * 60 * 1000;

  // Sync once shortly after startup (30 s delay avoids slowing down daemon boot)
  const initial = setTimeout(() => void syncOnce(), 30_000);
  initial.unref();

  // Then on the configured interval
  const recurring = setInterval(() => void syncOnce(), intervalMs);
  recurring.unref();
}

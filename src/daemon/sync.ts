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

// Computed lazily so tests can mock os.homedir() before any call
const rulesCacheFile = () => path.join(os.homedir(), '.node9', 'rules-cache.json');
const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/policy';
const DEFAULT_INTERVAL_HOURS = 5;
const MIN_INTERVAL_HOURS = 1;

export interface RulesCache {
  fetchedAt: string; // ISO-8601
  rules: unknown[];
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
            ? profile.apiUrl.replace(/\/intercept$/, '/policy')
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

function fetchCloudRules(apiKey: string, apiUrl: string): Promise<unknown[]> {
  const parsed = new URL(apiUrl);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) : undefined,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 10_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`API returned ${res.statusCode ?? 'unknown'}`));
            return;
          }
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString('utf-8')) as unknown;
            const rules = Array.isArray(body)
              ? body
              : Array.isArray((body as Record<string, unknown>).rules)
                ? ((body as Record<string, unknown>).rules as unknown[])
                : [];
            resolve(rules);
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

async function syncOnce(): Promise<void> {
  const creds = readCredentials();
  if (!creds) return; // No API key configured — silent no-op

  try {
    const rules = await fetchCloudRules(creds.apiKey, creds.apiUrl);
    const cache: RulesCache = { fetchedAt: new Date().toISOString(), rules };
    const dir = path.dirname(rulesCacheFile());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(rulesCacheFile(), JSON.stringify(cache, null, 2) + '\n', 'utf-8');
  } catch {
    // Best-effort — stale cache (or no cache) is fine; proxy falls back to local config
  }
}

/**
 * Run a single cloud policy sync and return a result summary.
 * Exported for use by `node9 sync` CLI command.
 */
export async function runCloudSync(): Promise<
  { ok: true; rules: number; fetchedAt: string } | { ok: false; reason: string }
> {
  const creds = readCredentials();
  if (!creds) {
    return { ok: false, reason: 'No API key configured. Add credentials with: node9 login' };
  }
  try {
    const rules = await fetchCloudRules(creds.apiKey, creds.apiUrl);
    const cache: RulesCache = { fetchedAt: new Date().toISOString(), rules };
    const dir = path.dirname(rulesCacheFile());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(rulesCacheFile(), JSON.stringify(cache, null, 2) + '\n', 'utf-8');
    return { ok: true, rules: rules.length, fetchedAt: cache.fetchedAt };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Return info about the current rules cache (last fetch time, rule count).
 */
export function getCloudSyncStatus():
  | { cached: false }
  | { cached: true; rules: number; fetchedAt: string } {
  try {
    const raw = JSON.parse(fs.readFileSync(rulesCacheFile(), 'utf-8')) as Record<string, unknown>;
    if (!Array.isArray(raw.rules) || typeof raw.fetchedAt !== 'string') return { cached: false };
    return { cached: true, rules: (raw.rules as unknown[]).length, fetchedAt: raw.fetchedAt };
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

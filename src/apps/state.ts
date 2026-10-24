// src/apps/state.ts
// ~/.node9/apps.json: what node9 found and what a person decided
// (node9Firewall#390, phase 2).
//
// The rule, agreed with the founder 2026-10-24: found = protected; turned off
// stays off. Detection records an app it has not seen before as `on` and turns
// its shield on; an entry a person set to `off` is never touched by
// detection. On a machine the workspace manages, detection records but does
// not turn shields on: the workspace decides.

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { APP_BY_SLUG } from './catalog';
import type { AppSignal, FoundApp } from './detect';
import { readActiveShields, writeActiveShields } from '../shields';
import { appendConfigAudit } from '../audit';

export type AppState = 'on' | 'off';
export type AppDecidedBy = 'detected' | 'user';

export interface AppRecord {
  state: AppState;
  by: AppDecidedBy;
  at: string;
  signals: AppSignal[];
}

export interface AppsFile {
  version: 1;
  apps: Record<string, AppRecord>;
  /** MCP server label -> app slug: a server a person said is that app. */
  links: Record<string, string>;
}

export function appsFilePath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'apps.json');
}

const EMPTY: AppsFile = { version: 1, apps: {}, links: {} };

export function readAppsFile(home?: string): AppsFile {
  try {
    const raw = JSON.parse(fs.readFileSync(appsFilePath(home), 'utf8')) as Partial<AppsFile>;
    const apps: Record<string, AppRecord> = {};
    for (const [slug, r] of Object.entries(raw.apps ?? {})) {
      if (!APP_BY_SLUG.has(slug) || !r || (r.state !== 'on' && r.state !== 'off')) continue;
      apps[slug] = {
        state: r.state,
        by: r.by === 'user' ? 'user' : 'detected',
        at: typeof r.at === 'string' ? r.at : '',
        signals: Array.isArray(r.signals) ? r.signals : [],
      };
    }
    const links: Record<string, string> = {};
    for (const [server, slug] of Object.entries(raw.links ?? {})) {
      if (typeof slug === 'string' && APP_BY_SLUG.has(slug)) links[server.toLowerCase()] = slug;
    }
    return { version: 1, apps, links };
  } catch {
    return { ...EMPTY, apps: {}, links: {} };
  }
}

export function writeAppsFile(data: AppsFile, home?: string): void {
  const file = appsFilePath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export interface ApplyResult {
  /** Apps seen for the first time and turned on. */
  turnedOn: string[];
  /** Apps seen for the first time on a managed machine: recorded, not enabled. */
  recordedOnly: string[];
}

/**
 * Record what detection found. A new app is `on`; its shield is turned on
 * unless the workspace manages this machine. An app a person turned off is
 * left alone; signals of an app already known are refreshed.
 */
export function applyDetection(
  found: FoundApp[],
  opts: { managed: boolean; home?: string; now?: Date } = { managed: false }
): ApplyResult {
  const file = readAppsFile(opts.home);
  const at = (opts.now ?? new Date()).toISOString();
  const result: ApplyResult = { turnedOn: [], recordedOnly: [] };
  const toEnable: string[] = [];
  for (const f of found) {
    const app = APP_BY_SLUG.get(f.slug);
    if (!app) continue;
    const known = file.apps[f.slug];
    if (known) {
      known.signals = f.signals;
      continue;
    }
    file.apps[f.slug] = { state: 'on', by: 'detected', at, signals: f.signals };
    if (opts.managed) result.recordedOnly.push(f.slug);
    else {
      toEnable.push(app.shield);
      result.turnedOn.push(f.slug);
    }
  }
  writeAppsFile(file, opts.home);
  if (toEnable.length > 0) {
    const active = readActiveShields();
    const next = [...active, ...toEnable.filter((s) => !active.includes(s))];
    if (next.length !== active.length) writeActiveShields(next);
    for (const slug of result.turnedOn) {
      appendConfigAudit({
        event: 'app-protected',
        app: slug,
        by: 'detection',
        signals: file.apps[slug].signals.map((s) => `${s.kind}:${s.value}`),
      });
    }
  }
  return result;
}

/** A person's decision, from `node9 apps` or `node9 shield enable|disable`. */
export function recordUserDecision(slug: string, state: AppState, home?: string): void {
  if (!APP_BY_SLUG.has(slug)) return;
  const file = readAppsFile(home);
  const prev = file.apps[slug];
  file.apps[slug] = {
    state,
    by: 'user',
    at: new Date().toISOString(),
    signals: prev?.signals ?? [],
  };
  writeAppsFile(file, home);
}

/** Link an MCP server label to an app, or remove the link. */
export function setLink(server: string, slug: string | null, home?: string): void {
  const file = readAppsFile(home);
  const key = server.toLowerCase();
  if (slug === null) delete file.links[key];
  else if (APP_BY_SLUG.has(slug)) file.links[key] = slug;
  writeAppsFile(file, home);
}

// The gate reads links on every MCP call: cache by mtime.
let linkCache: { mtimeMs: number; file: string; links: Record<string, string> } | null = null;

/**
 * The server label the gate should judge: a label a person linked to an app
 * becomes that app's slug, so the app's shield meets it and the general
 * checks leave it. Unlinked labels pass through.
 */
export function resolveLinkedServer(label: string | undefined): string | undefined {
  if (!label) return label;
  const file = appsFilePath();
  try {
    const mtimeMs = fs.statSync(file).mtimeMs;
    if (!linkCache || linkCache.file !== file || linkCache.mtimeMs !== mtimeMs) {
      linkCache = { mtimeMs, file, links: readAppsFile().links };
    }
  } catch {
    return label;
  }
  return linkCache.links[label.toLowerCase()] ?? label;
}

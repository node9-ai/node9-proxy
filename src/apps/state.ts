// src/apps/state.ts
// ~/.node9/apps.json: what node9 found and what a person decided
// (node9Firewall#390, phase 2).
//
// The rule, agreed with the founder 2026-10-24: found = protected; turned off
// stays off. Detection records an app it has not seen before as `on` and turns
// its shield on; an entry a person set to `off` is never touched by
// detection. On a machine the workspace manages, detection records but does
// not turn shields on: the workspace decides (`by: 'workspace'`; such a record
// counts as new again if the machine leaves the workspace).
//
// Every map here is keyed by outside names (server labels, slugs), so lookups
// go through own properties only: a server named `constructor` must not read
// Object.prototype.

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { APP_BY_SLUG } from './catalog';
import type { AppSignal, FoundApp } from './detect';
import { readActiveShields, writeActiveShields } from '../shields';
import { appendConfigAudit } from '../audit';
import { readMcpToolsConfig } from '../daemon/mcp-tools';

export type AppState = 'on' | 'off';
export type AppDecidedBy = 'detected' | 'user' | 'workspace';

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

const SIGNAL_KINDS: ReadonlySet<string> = new Set(['mcp-server', 'command', 'package', 'env-name']);

function emptyFile(): AppsFile {
  return { version: 1, apps: Object.create(null), links: Object.create(null) };
}

/** An own string value of `map[key]`, never an inherited one. */
export function ownString(map: Record<string, unknown>, key: string): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(map, key)) return undefined;
  const v = map[key];
  return typeof v === 'string' ? v : undefined;
}

function readSignals(raw: unknown): AppSignal[] {
  if (!Array.isArray(raw)) return [];
  const out: AppSignal[] = [];
  for (const x of raw as Array<Record<string, unknown>>) {
    if (!x || typeof x.kind !== 'string' || typeof x.value !== 'string') continue;
    if (!SIGNAL_KINDS.has(x.kind)) continue;
    out.push({
      kind: x.kind as AppSignal['kind'],
      value: x.value.slice(0, 256),
      ...(typeof x.project === 'string' ? { project: x.project } : {}),
    });
  }
  return out;
}

function parseAppsFile(text: string): AppsFile {
  const raw = JSON.parse(text) as Partial<AppsFile>;
  const file = emptyFile();
  for (const [slug, r] of Object.entries(raw.apps ?? {})) {
    if (!APP_BY_SLUG.has(slug) || !r || (r.state !== 'on' && r.state !== 'off')) continue;
    file.apps[slug] = {
      state: r.state,
      by: r.by === 'user' || r.by === 'workspace' ? r.by : 'detected',
      at: typeof r.at === 'string' ? r.at : '',
      signals: readSignals(r.signals),
    };
  }
  for (const [server, slug] of Object.entries(raw.links ?? {})) {
    if (typeof slug === 'string' && APP_BY_SLUG.has(slug)) file.links[server.toLowerCase()] = slug;
  }
  return file;
}

/** apps.json, or an empty one when it is missing or unreadable. */
export function readAppsFile(home?: string): AppsFile {
  return readAppsFileStrict(home) ?? emptyFile();
}

/** apps.json; empty when missing; null when it exists but cannot be read,
 *  so a writer does not replace a person's decisions with nothing. */
function readAppsFileStrict(home?: string): AppsFile | null {
  let text: string;
  try {
    text = fs.readFileSync(appsFilePath(home), 'utf8');
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'ENOENT' ? emptyFile() : null;
  }
  try {
    return parseAppsFile(text);
  } catch {
    return null;
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
  /** apps.json exists but could not be read: nothing was changed. */
  unreadable?: boolean;
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
  const result: ApplyResult = { turnedOn: [], recordedOnly: [] };
  // Read right before writing (detection itself can take a while), so a
  // decision a person made meanwhile is the one kept.
  const file = readAppsFileStrict(opts.home);
  if (!file) return { ...result, unreadable: true };
  const at = (opts.now ?? new Date()).toISOString();
  const toEnable: string[] = [];
  for (const f of found) {
    const app = APP_BY_SLUG.get(f.slug);
    if (!app) continue;
    const known = Object.prototype.hasOwnProperty.call(file.apps, f.slug)
      ? file.apps[f.slug]
      : undefined;
    // Recorded while the workspace decided: on its own again, it is new.
    if (known && !(known.by === 'workspace' && !opts.managed)) {
      known.signals = f.signals;
      continue;
    }
    file.apps[f.slug] = {
      state: 'on',
      by: opts.managed ? 'workspace' : 'detected',
      at,
      signals: f.signals,
    };
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
  // An unreadable file is replaced: the person's decision is the newer fact.
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
const NO_LINKS: Record<string, string> = Object.create(null);

function localLinks(): Record<string, string> {
  const file = appsFilePath();
  try {
    const mtimeMs = fs.statSync(file).mtimeMs;
    if (!linkCache || linkCache.file !== file || linkCache.mtimeMs !== mtimeMs) {
      linkCache = { mtimeMs, file, links: readAppsFile().links };
    }
    return linkCache.links;
  } catch {
    return NO_LINKS;
  }
}

/**
 * The server label the gate should judge: a label a person linked to an app
 * becomes that app's slug, so the app's shield meets it and the general
 * checks leave it. Two sources:
 *  - this machine's links (`node9 apps link`), by label; not on a machine
 *    the workspace governs, where local policy stores are inert;
 *  - the workspace's links (`appLinks`, managed, keyed by server key): by the
 *    gateway's server key when the call has one, else by the name the
 *    gateway recorded for that key in mcp-tools.json (the hook's path).
 * A link counts only while the app's shield is applied: a link to an app
 * that is off would take the server out of the general checks with nothing
 * in their place. Unlinked labels pass through.
 */
export function resolveLinkedServer(
  label: string | undefined,
  opts: {
    serverKey?: string;
    managedLinks?: Record<string, string>;
    /** Shields the config applied; a link to an app outside them is ignored. */
    appliedShields?: readonly string[];
    /** The workspace governs this machine: local links are ignored. */
    workspaceGoverned?: boolean;
  } = {}
): string | undefined {
  if (typeof label !== 'string' || !label) return label;
  const applied = new Set(opts.appliedShields ?? []);
  const live = (slug: string | undefined): string | undefined => {
    const app = slug ? APP_BY_SLUG.get(slug) : undefined;
    return app && applied.has(app.shield) ? slug : undefined;
  };
  const lower = label.toLowerCase();
  if (!opts.workspaceGoverned) {
    const local = live(ownString(localLinks(), lower));
    if (local) return local;
  }
  const managed = opts.managedLinks ?? {};
  if (opts.serverKey) {
    const byKey = live(ownString(managed, opts.serverKey));
    if (byKey) return byKey;
  }
  const keys = Object.keys(managed);
  if (keys.length === 0) return label;
  const tools = readMcpToolsConfig();
  for (const key of keys) {
    // A server that never launched is keyed `cfg:<agent>:<name>` in the
    // snapshot (policy-snapshot/build.ts); its name is the rest of the key.
    const name = key.startsWith('cfg:')
      ? key.split(':').slice(2).join(':')
      : Object.prototype.hasOwnProperty.call(tools, key)
        ? tools[key]?.name
        : undefined;
    if (typeof name === 'string' && name.toLowerCase() === lower) {
      const linked = live(ownString(managed, key));
      if (linked) return linked;
    }
  }
  return label;
}

// src/addons/mcp-seen.ts
// MCP servers that are in no agent config (node9Firewall#376 item 6, docs
// roadmap/active/addons-mcp-seen-in-calls-plan.md). The add-ons inventory
// reads config files, and four kinds of server reach an agent without one: a
// tool the agent's own app adds to a session, a claude.ai connector, a
// server a plugin brings, and one passed when the agent starts. The hook
// audits every call to them, so the audit log is where they are found.
//
// This module keeps ~/.node9/mcp-seen.json: one entry per (agent, server
// name) with the days of its first and newest call. It reads only the part
// of the audit log written since its last read. For a claude.ai connector
// the desktop app names the server by an id; the app's own session files
// map that id to the connector's name and URL, which gives the row a
// readable label and the identity a configured remote server has
// (`url:<host>`).
//
// Daemon and CLI only: the hook never loads this file. It reads the entries
// from the MCP index (index-file.ts) like any other server.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { atomicWriteSync } from '../utils/atomic-write';
import { readSmallFile } from '../utils/read-small-file';
import { mcpServerFromToolName } from '@node9/policy-engine';
import { mcpIdentityFromUrl } from './identity';
import { agentIdOf } from './agent-ids';

export interface SeenServer {
  /** Agent id (`claude`, `codex`...). */
  agent: string;
  /** The server name as the agent spells it in `mcp__<name>__<tool>`. */
  name: string;
  /** Days (YYYY-MM-DD) of the first and the newest call seen. */
  first: string;
  last: string;
  /** A claude.ai connector's readable name and URL host, once found. */
  label?: string;
  host?: string;
  /** When the app's session files were last searched for this id (ms). */
  triedAt?: number;
}

interface SeenFile {
  v: 1;
  /** How far into the audit log the entries reach. */
  audit: { size: number; ino: number };
  servers: SeenServer[];
}

/** The audit log is read this far back at most on a first or a late read. */
const AUDIT_TAIL_BYTES = 5 * 1024 * 1024;
const MAX_SERVERS = 200;
/** A server with no call for this long is dropped. */
const KEEP_DAYS = 30;
const MAX_FILE_BYTES = 512 * 1024;
/** The offset is saved on its own only after this many new bytes: a restart
 *  then reads at most that much again, and reading a call twice is harmless. */
const SAVE_OFFSET_EVERY = 1024 * 1024;
/** An id the session files did not name is looked up again after this long. */
const RETRY_NAME_MS = 6 * 60 * 60_000;
const MAX_SESSION_FILES = 40;
const MAX_SESSION_BYTES = 1024 * 1024;

const SERVER_NAME = /^[A-Za-z0-9_-]{1,120}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const HOST = /^[a-z0-9.-]{1,160}$/;
/** Folders read at each level above the session files, and files per folder. */
const MAX_SESSION_DIRS = 20;
const MAX_SESSION_LISTING = 2000;

export function mcpSeenPath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'mcp-seen.json');
}

function emptyFile(): SeenFile {
  return { v: 1, audit: { size: 0, ino: 0 }, servers: [] };
}

function readSeenFile(home: string): SeenFile {
  try {
    const text = readSmallFile(mcpSeenPath(home), MAX_FILE_BYTES, { noFollow: true });
    if (text === null) return emptyFile();
    const raw = JSON.parse(text) as Partial<SeenFile> | null;
    if (!raw || !Array.isArray(raw.servers)) return emptyFile();
    const servers: SeenServer[] = [];
    for (const e of raw.servers.slice(0, MAX_SERVERS)) {
      const s = e as Partial<SeenServer> | null;
      if (
        typeof s?.agent !== 'string' ||
        !/^[A-Za-z0-9-]{1,32}$/.test(s.agent) ||
        typeof s.name !== 'string' ||
        !SERVER_NAME.test(s.name) ||
        typeof s.first !== 'string' ||
        !DAY.test(s.first) ||
        typeof s.last !== 'string' ||
        !DAY.test(s.last)
      )
        continue;
      servers.push({
        agent: s.agent,
        name: s.name,
        first: s.first,
        last: s.last,
        ...(typeof s.label === 'string' && s.label.length <= 128 ? { label: s.label } : {}),
        ...(typeof s.host === 'string' && HOST.test(s.host) ? { host: s.host } : {}),
        ...(typeof s.triedAt === 'number' ? { triedAt: s.triedAt } : {}),
      });
    }
    const size = Number(raw.audit?.size);
    const ino = Number(raw.audit?.ino);
    return {
      v: 1,
      audit: {
        size: Number.isFinite(size) && size >= 0 ? size : 0,
        ino: Number.isFinite(ino) ? ino : 0,
      },
      servers,
    };
  } catch {
    return emptyFile();
  }
}

/** The stored entries. Never throws. */
export function readSeenServers(home: string = os.homedir()): SeenServer[] {
  return readSeenFile(home).servers;
}

/** The day of an audit row, never after `today`: a row dated in the future
 *  (a wrong clock, a hand-written line) would otherwise never age out. */
function dayOf(ts: unknown, today: string): string {
  if (typeof ts !== 'string') return today;
  const d = ts.slice(0, 10);
  return DAY.test(d) && !Number.isNaN(Date.parse(ts)) && d <= today ? d : today;
}

/** One MCP call an audit row records: which agent called which server, when. */
export interface SeenCall {
  agent: string;
  name: string;
  day: string;
}

/** The MCP calls in a piece of the audit log. Rows of other tools are not
 *  parsed at all; a row that names no known agent is skipped. */
export function mcpCallsIn(text: string, today: string): SeenCall[] {
  const out: SeenCall[] = [];
  for (const line of text.split('\n')) {
    if (!line.includes('"mcp__')) continue;
    let row: { tool?: unknown; agent?: unknown; ts?: unknown };
    try {
      row = JSON.parse(line) as typeof row;
    } catch {
      continue;
    }
    if (typeof row.tool !== 'string' || typeof row.agent !== 'string') continue;
    const name = mcpServerFromToolName(row.tool);
    const agent = agentIdOf(row.agent);
    if (!name || !agent || !SERVER_NAME.test(name)) continue;
    out.push({ agent, name, day: dayOf(row.ts, today) });
  }
  return out;
}

/**
 * The audit log from `from` to its last complete line. `from` is where the
 * previous read ended (a line start); a first read, a read after the log was
 * replaced, or one too far behind starts at most AUDIT_TAIL_BYTES back and
 * drops the cut first line.
 */
function readAuditSince(
  auditFile: string,
  from: { size: number; ino: number }
): { text: string; size: number; ino: number } | null {
  let fd: number | undefined;
  try {
    fd = fs.openSync(auditFile, 'r');
    const st = fs.fstatSync(fd);
    const sameFile = from.ino === st.ino && from.size <= st.size;
    let start = sameFile ? from.size : 0;
    let midLine = false;
    if (st.size - start > AUDIT_TAIL_BYTES) {
      start = st.size - AUDIT_TAIL_BYTES;
      midLine = true;
    }
    if (start >= st.size) return { text: '', size: st.size, ino: st.ino };
    const buf = Buffer.alloc(st.size - start);
    const read = fs.readSync(fd, buf, 0, buf.length, start);
    const chunk = buf.subarray(0, read);
    // Stop at the last complete line: a row being appended is read next time.
    const end = chunk.lastIndexOf(0x0a);
    if (end < 0) return { text: '', size: start, ino: st.ino };
    let text = chunk.subarray(0, end + 1).toString('utf8');
    if (midLine) text = text.slice(text.indexOf('\n') + 1);
    return { text, size: start + end + 1, ino: st.ino };
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* nothing to do */
      }
    }
  }
}

/** Where the Claude desktop app keeps its Code sessions, per platform
 *  (confirmed 2026-11-27 on Linux, macOS and a Microsoft Store install on
 *  Windows; `%APPDATA%\Claude` is the guess for a plain Windows install). */
export function desktopSessionRoots(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform
): string[] {
  const leaf = 'claude-code-sessions';
  if (platform === 'darwin')
    return [path.join(home, 'Library', 'Application Support', 'Claude', leaf)];
  if (platform === 'win32') {
    const out: string[] = [];
    const local = env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    try {
      // A Store install: Claude-Data\claude_<package id>\claude-code-sessions.
      for (const d of fs.readdirSync(path.join(local, 'Claude-Data')).slice(0, 20))
        if (/^claude_/i.test(d)) out.push(path.join(local, 'Claude-Data', d, leaf));
    } catch {
      /* not a Store install */
    }
    out.push(path.join(env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Claude', leaf));
    return out;
  }
  return [path.join(env.XDG_CONFIG_HOME || path.join(home, '.config'), 'Claude', leaf)];
}

/** The newest session files under the roots (`<root>/<a>/<b>/local_*.json`). */
function newestSessionFiles(roots: string[]): string[] {
  const files: Array<{ file: string; mtime: number }> = [];
  const list = (dir: string, max: number): string[] => {
    try {
      return fs.readdirSync(dir).slice(0, max);
    } catch {
      return [];
    }
  };
  // Two levels of folders (account, organisation), a handful of each.
  for (const root of roots)
    for (const a of list(root, MAX_SESSION_DIRS))
      for (const b of list(path.join(root, a), MAX_SESSION_DIRS))
        for (const f of list(path.join(root, a, b), MAX_SESSION_LISTING)) {
          if (!/^local_.*\.json$/.test(f)) continue;
          const file = path.join(root, a, b, f);
          try {
            files.push({ file, mtime: fs.statSync(file).mtimeMs });
          } catch {
            /* gone since the listing */
          }
        }
  return files
    .sort((x, y) => y.mtime - x.mtime)
    .slice(0, MAX_SESSION_FILES)
    .map((f) => f.file);
}

/**
 * The readable name and URL host of the connectors the desktop app lists
 * under these ids. The session files are the app's own and undocumented, so
 * every step is best effort: an id that is not found stays unnamed.
 */
export function connectorNames(
  ids: ReadonlySet<string>,
  roots: string[]
): Map<string, { label?: string; host?: string }> {
  const out = new Map<string, { label?: string; host?: string }>();
  if (ids.size === 0) return out;
  const wanted = new Set([...ids].map((i) => i.toLowerCase()));
  for (const file of newestSessionFiles(roots)) {
    if (out.size >= wanted.size) break;
    try {
      const text = readSmallFile(file, MAX_SESSION_BYTES);
      if (text === null) continue;
      const list = (JSON.parse(text) as { remoteMcpServersConfig?: unknown } | null)
        ?.remoteMcpServersConfig;
      if (!Array.isArray(list)) continue;
      for (const e of list.slice(0, 200)) {
        const c = e as { uuid?: unknown; name?: unknown; url?: unknown } | null;
        const id = typeof c?.uuid === 'string' ? c.uuid.toLowerCase() : '';
        if (!wanted.has(id) || out.has(id)) continue;
        const identity = mcpIdentityFromUrl(c?.url);
        // Only a host the stored file keeps: one it would drop on the next
        // read would change the row's identity from one round to the next.
        const h = identity.slice('url:'.length);
        const host = identity !== 'url:unknown' && HOST.test(h) ? h : undefined;
        const label =
          typeof c?.name === 'string' && c.name.trim() && c.name.length <= 128
            ? c.name.replace(/\p{Cc}/gu, ' ').trim()
            : undefined;
        if (label || host) out.set(id, { ...(label ? { label } : {}), ...(host ? { host } : {}) });
      }
    } catch {
      /* an unreadable session file names nothing */
    }
  }
  return out;
}

/** In memory, per home folder: how far the audit log was read, and how far
 *  the saved file says it was (see SAVE_OFFSET_EVERY). */
const cursor = new Map<string, { size: number; ino: number; saved: number }>();

/** For tests: forget how far each audit log was read. */
export function _resetMcpSeenCursor(): void {
  cursor.clear();
}

/**
 * Bring ~/.node9/mcp-seen.json up to date with the audit log. Returns true
 * when the set of servers, or what is known about one, changed (the MCP index
 * must then be rebuilt). Never throws.
 */
export function refreshMcpSeen(
  home: string = os.homedir(),
  now: number = Date.now(),
  roots: string[] = desktopSessionRoots(home)
): boolean {
  try {
    const stored = readSeenFile(home);
    const mem = cursor.get(home);
    const from = mem ? { size: mem.size, ino: mem.ino } : stored.audit;
    const today = new Date(now).toISOString().slice(0, 10);
    const audit = readAuditSince(path.join(home, '.node9', 'audit.log'), from);

    const byKey = new Map(stored.servers.map((s) => [`${s.agent}\0${s.name}`, { ...s }]));
    let changed = false;
    // A stored day after today (a hand-edited file) would never age out.
    for (const s of byKey.values()) {
      if (s.last > today) {
        s.last = today;
        changed = true;
      }
      if (s.first > s.last) s.first = s.last;
    }
    for (const call of audit ? mcpCallsIn(audit.text, today) : []) {
      const key = `${call.agent}\0${call.name}`;
      const cur = byKey.get(key);
      if (!cur) {
        byKey.set(key, { agent: call.agent, name: call.name, first: call.day, last: call.day });
        changed = true;
        continue;
      }
      if (call.day < cur.first) {
        cur.first = call.day;
        changed = true;
      }
      if (call.day > cur.last) {
        cur.last = call.day;
        changed = true;
      }
    }

    const oldest = new Date(now - KEEP_DAYS * 86_400_000).toISOString().slice(0, 10);
    let servers = [...byKey.values()].filter((s) => s.last >= oldest);
    if (servers.length > MAX_SERVERS)
      servers = servers.sort((a, b) => (a.last < b.last ? 1 : -1)).slice(0, MAX_SERVERS);
    if (servers.length !== byKey.size) changed = true;

    // Name the connectors: ids Claude Code called that no session file named yet.
    const unnamed = servers.filter(
      (s) =>
        s.agent === 'claude' &&
        UUID.test(s.name) &&
        !s.host &&
        !s.label &&
        (s.triedAt === undefined || now - s.triedAt > RETRY_NAME_MS)
    );
    // A lookup that found nothing is saved (so it waits for its next try)
    // but changes no row: the index is not rebuilt for it.
    let tried = false;
    if (unnamed.length > 0) {
      const names = connectorNames(new Set(unnamed.map((s) => s.name)), roots);
      for (const s of unnamed) {
        const n = names.get(s.name.toLowerCase());
        if (n?.label) s.label = n.label;
        if (n?.host) s.host = n.host;
        if (n) changed = true;
        else {
          s.triedAt = now;
          tried = true;
        }
      }
    }

    const size = audit?.size ?? from.size;
    const ino = audit?.ino ?? from.ino;
    const saved = mem?.saved ?? stored.audit.size;
    const save =
      changed || tried || ino !== stored.audit.ino || Math.abs(size - saved) > SAVE_OFFSET_EVERY;
    if (save) {
      servers.sort((a, b) => (a.agent + a.name < b.agent + b.name ? -1 : 1));
      const file: SeenFile = { v: 1, audit: { size, ino }, servers };
      atomicWriteSync(mcpSeenPath(home), JSON.stringify(file), { mode: 0o600 });
    }
    cursor.set(home, { size, ino, saved: save ? size : saved });
    return changed;
  } catch {
    return false;
  }
}

/** One seen server as the add-ons report and the MCP index carry it. */
export interface SeenMcpRow {
  name: string;
  /** `url:<host>` when the app's files named it, else `name:<server name>`. */
  identity: string;
  agents: string[];
  state: 'seen';
  label?: string;
  lastSeenDay: string;
}

/**
 * The stored servers that no agent config names, newest first. `configured`
 * holds the names the agents' configs give their servers, as a tool name
 * spells them: a server with a config row is judged by what the config runs,
 * never by its name.
 */
export function seenMcpRows(
  configured: ReadonlySet<string>,
  home: string = os.homedir(),
  servers: SeenServer[] = readSeenServers(home)
): SeenMcpRow[] {
  const byKey = new Map<string, SeenMcpRow>();
  for (const s of servers) {
    if (configured.has(s.name)) continue;
    const identity = s.host ? `url:${s.host}` : `name:${s.name}`;
    const key = `${s.name}\0${identity}`;
    const row = byKey.get(key);
    if (row) {
      if (!row.agents.includes(s.agent)) row.agents.push(s.agent);
      if (s.last > row.lastSeenDay) row.lastSeenDay = s.last;
      if (!row.label && s.label) row.label = s.label;
      continue;
    }
    byKey.set(key, {
      name: s.name,
      identity,
      agents: [s.agent],
      state: 'seen',
      ...(s.label ? { label: s.label } : {}),
      lastSeenDay: s.last,
    });
  }
  return [...byKey.values()].sort((a, b) => (a.lastSeenDay < b.lastSeenDay ? 1 : -1));
}

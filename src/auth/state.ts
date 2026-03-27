// src/auth/state.ts
// Persistent state helpers: pause sessions, trust sessions, and persistent allow/deny decisions.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { matchesPattern } from '../policy';

const PAUSED_FILE = path.join(os.homedir(), '.node9', 'PAUSED');
const TRUST_FILE = path.join(os.homedir(), '.node9', 'trust.json');

interface PauseState {
  expiry: number;
  duration: string;
}
interface TrustEntry {
  tool: string;
  expiry: number;
}
interface TrustFile {
  entries: TrustEntry[];
}

export function checkPause(): { paused: boolean; expiresAt?: number; duration?: string } {
  try {
    if (!fs.existsSync(PAUSED_FILE)) return { paused: false };
    const state = JSON.parse(fs.readFileSync(PAUSED_FILE, 'utf-8')) as PauseState;
    if (state.expiry > 0 && Date.now() >= state.expiry) {
      try {
        fs.unlinkSync(PAUSED_FILE);
      } catch {}
      return { paused: false };
    }
    return { paused: true, expiresAt: state.expiry, duration: state.duration };
  } catch {
    return { paused: false };
  }
}

function atomicWriteSync(filePath: string, data: string, options?: fs.WriteFileOptions): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.${os.hostname()}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, data, options);
  fs.renameSync(tmpPath, filePath);
}

export function pauseNode9(durationMs: number, durationStr: string): void {
  const state: PauseState = { expiry: Date.now() + durationMs, duration: durationStr };
  atomicWriteSync(PAUSED_FILE, JSON.stringify(state, null, 2));
}

export function resumeNode9(): void {
  try {
    if (fs.existsSync(PAUSED_FILE)) fs.unlinkSync(PAUSED_FILE);
  } catch {}
}

export function getActiveTrustSession(toolName: string): boolean {
  try {
    if (!fs.existsSync(TRUST_FILE)) return false;
    const trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
    const now = Date.now();
    const active = trust.entries.filter((e) => e.expiry > now);
    if (active.length !== trust.entries.length) {
      fs.writeFileSync(TRUST_FILE, JSON.stringify({ entries: active }, null, 2));
    }
    return active.some((e) => e.tool === toolName || matchesPattern(toolName, e.tool));
  } catch {
    return false;
  }
}

export function writeTrustSession(toolName: string, durationMs: number): void {
  try {
    let trust: TrustFile = { entries: [] };

    // 1. Try to read existing trust state
    try {
      if (fs.existsSync(TRUST_FILE)) {
        trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
      }
    } catch {
      // If the file is corrupt, start with a fresh object
    }

    // 2. Filter out the specific tool (to overwrite) and remove any expired entries
    const now = Date.now();
    trust.entries = trust.entries.filter((e) => e.tool !== toolName && e.expiry > now);

    // 3. Add the new time-boxed entry
    trust.entries.push({ tool: toolName, expiry: now + durationMs });

    // 4. Perform the ATOMIC write
    atomicWriteSync(TRUST_FILE, JSON.stringify(trust, null, 2));
  } catch (err) {
    // Silent fail: Node9 should never crash an AI agent session due to a file error
    if (process.env.NODE9_DEBUG === '1') {
      console.error('[Node9 Trust Error]:', err);
    }
  }
}

export function getPersistentDecision(toolName: string): 'allow' | 'deny' | null {
  try {
    const file = path.join(os.homedir(), '.node9', 'decisions.json');
    if (!fs.existsSync(file)) return null;
    const decisions = JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<string, string>;
    const d = decisions[toolName];
    if (d === 'allow' || d === 'deny') return d;
  } catch {
    /* ignore */
  }
  return null;
}

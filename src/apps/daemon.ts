// src/apps/daemon.ts
// The daemon looks for apps 30 seconds after it starts and then every hour
// (node9Firewall#390, phase 2). Found = protected; turned off stays off
// (apps/state.ts). Never under NODE9_TESTING: a test's HOME must not change
// behind its back.
import { detectApps } from './detect';
import { applyDetection } from './state';
import { isKeyedForPolicy } from '../config/keyed-guard';

const FIRST_RUN_MS = 30_000;
const EVERY_MS = 60 * 60 * 1000;

export function runAppDetection(): void {
  try {
    applyDetection(detectApps(), { managed: isKeyedForPolicy() });
  } catch {
    // Detection is best effort: a broken manifest or an unreadable audit log
    // must never take the daemon down. The next run tries again.
  }
}

export function startAppDetection(): void {
  if (process.env.NODE9_TESTING) return;
  setTimeout(runAppDetection, FIRST_RUN_MS).unref();
  setInterval(runAppDetection, EVERY_MS).unref();
}

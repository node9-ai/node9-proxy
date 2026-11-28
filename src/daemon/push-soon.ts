// src/daemon/push-soon.ts
// A push asked for between policy syncs. The policy snapshot carries the
// add-ons report, and the sync that sends it runs hours apart (1 to 5): a
// server first seen in a call waited that long to reach the Add-ons page.

/** How long after the first request the push goes out, so a burst of new
 *  servers (several rounds of 30 s) is sent together. */
export const PUSH_SOON_DELAY_MS = 90_000;
/** Pushes asked for this way are at least this far apart. */
export const PUSH_SOON_MIN_GAP_MS = 10 * 60_000;

/**
 * Returns `request()`: the first call schedules one `push` `delayMs` later
 * (or when `minGapMs` since the last one has passed, if that is later), and
 * calls while it is pending add nothing. A request made after it fired, the
 * push itself still running, schedules the next one: what the running push
 * collected may predate it. A push that resolves `false` sent nothing (no key
 * yet) and does not count toward the gap. Never throws; the timer does not
 * keep the process alive.
 */
export function createPushSoon(
  push: () => Promise<boolean>,
  delayMs: number = PUSH_SOON_DELAY_MS,
  minGapMs: number = PUSH_SOON_MIN_GAP_MS,
  now: () => number = Date.now
): () => void {
  let pending = false;
  let lastAt = -Infinity;
  return () => {
    if (pending) return;
    pending = true;
    const wait = Math.max(delayMs, lastAt + minGapMs - now());
    const timer = setTimeout(() => {
      pending = false;
      const prev = lastAt;
      const at = now();
      lastAt = at;
      void Promise.resolve()
        .then(push)
        .then((sent) => {
          if (!sent && lastAt === at) lastAt = prev;
        })
        .catch(() => {});
    }, wait);
    timer.unref();
  };
}

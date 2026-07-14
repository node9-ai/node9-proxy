// src/lib/relative-time.ts
// One canonical relative-time formatter for CLI surfaces (status, doctor, …).
// New code should use this instead of hand-rolling another "N min ago" (there
// are already a few divergent copies in scan surfaces — consolidate on demand).

/** Human relative age of an ISO timestamp, e.g. "4 min ago" / "7 days ago". */
export function agoLabel(iso: string, now: number = Date.now()): string {
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return 'just now';
  const min = Math.floor(ms / 60_000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min} min ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr} hour${hr === 1 ? '' : 's'} ago`;
  const d = Math.floor(hr / 24);
  return `${d} day${d === 1 ? '' : 's'} ago`;
}

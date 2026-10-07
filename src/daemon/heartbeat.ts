import { getConfig } from '../config';
import { appendToLog, HOOK_DEBUG_LOG } from '../audit';
import { buildBatchEndpoint, outboxBacklog } from './audit-shipper';
import { autostartState } from './service';
import { readCachedEtag, readCredentials, safeNode9Version, triggerSyncNow } from './sync';

export const HEARTBEAT_INTERVAL_MS = 5 * 60_000;
const startedAt = new Date().toISOString();
let lastErrorAt = -Infinity;

export interface HeartbeatDeps {
  cloudEnabled?: boolean;
  creds?: { apiKey: string; apiUrl: string } | null;
  fetchImpl?: typeof fetch;
  backlog?: typeof outboxBacklog;
  syncNow?: () => Promise<void>;
}

/** Only explicitly selected operational metadata can leave the machine. */
export function buildHeartbeatBody() {
  return {
    cliVersion: safeNode9Version() ?? '0.0.0',
    daemonStartedAt: startedAt,
    policyEtag: readCachedEtag() ?? null,
    ...outboxBacklog(),
    autostart: autostartState(),
  };
}

export async function heartbeatOnce(
  deps: HeartbeatDeps = {}
): Promise<'sent' | 'disabled' | 'no-creds' | 'error'> {
  try {
    if (!(deps.cloudEnabled ?? getConfig().settings.approvers.cloud)) return 'disabled';
    const creds = deps.creds !== undefined ? deps.creds : readCredentials();
    if (!creds) return 'no-creds';
    const batchEndpoint = buildBatchEndpoint(creds.apiUrl);
    if (!batchEndpoint) return 'no-creds';
    const body = buildHeartbeatBody();
    if (deps.backlog) Object.assign(body, deps.backlog());
    const response = await (deps.fetchImpl ?? fetch)(
      batchEndpoint.replace(/\/audit\/batch$/, '/heartbeat'),
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${creds.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      }
    );
    if (!response.ok) throw new Error('Heartbeat rejected');
    const result: unknown = await response.json();
    if (
      result &&
      typeof result === 'object' &&
      'policyChanged' in result &&
      result.policyChanged === true
    ) {
      await (deps.syncNow ?? triggerSyncNow)();
    }
    return 'sent';
  } catch {
    if (Date.now() - lastErrorAt >= 60 * 60_000) {
      lastErrorAt = Date.now();
      try {
        appendToLog(HOOK_DEBUG_LOG, {
          ts: new Date().toISOString(),
          kind: 'heartbeat-error',
          message: 'Heartbeat failed; retrying on the next scheduled interval',
        });
      } catch {
        /* Best-effort diagnostics. */
      }
    }
    return 'error';
  }
}

let stopHeartbeat: (() => void) | undefined;
/** One self-rescheduling loop per daemon; no overlapping network requests. */
export function startHeartbeat(once: () => Promise<unknown> = heartbeatOnce): () => void {
  if (stopHeartbeat) return stopHeartbeat;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout>;
  const schedule = (delay: number) => {
    timer = setTimeout(() => {
      void once()
        .catch(() => {})
        .finally(() => {
          if (!stopped) schedule(HEARTBEAT_INTERVAL_MS);
        });
    }, delay);
    timer.unref();
  };
  const stop = () => {
    stopped = true;
    clearTimeout(timer);
    if (stopHeartbeat === stop) stopHeartbeat = undefined;
  };
  stopHeartbeat = stop;
  schedule(10_000);
  return stop;
}

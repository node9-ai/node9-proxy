// A dashboard older than the proxy validates the snapshot strictly and answers
// 400 to a field it does not know, which rejected the whole snapshot (config
// mirror, drift, device info). The proxy sends it once more without the newer
// fields (node9Firewall#390: `apps`). A real HTTP server plays the dashboard.
import { describe, it, expect, afterEach } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';
import { shipPolicySnapshot } from '../policy-snapshot/ship';
import type { PolicySnapshotBody } from '../policy-snapshot/build';

type Seen = Array<Record<string, unknown>>;
const servers: http.Server[] = [];

/** A dashboard that answers `respond(body)` to each snapshot it receives. */
async function dashboard(respond: (body: Record<string, unknown>) => number) {
  const seen: Seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const body = JSON.parse(raw) as Record<string, unknown>;
      seen.push(body);
      res.statusCode = respond(body);
      res.end();
    });
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return { seen, creds: { apiKey: 'k', apiUrl: `http://127.0.0.1:${port}/policies/sync` } };
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const snapshot = (extra: Partial<PolicySnapshotBody> = {}) =>
  ({
    mode: 'standard',
    activeShields: ['stripe'],
    apps: [{ slug: 'stripe', state: 'on', by: 'detected', signals: [] }],
    ...extra,
  }) as unknown as PolicySnapshotBody;

/** The production dashboard before fw#390: strict, no `apps`. */
const strictOld = (b: Record<string, unknown>) => ('apps' in b ? 400 : 201);

describe('shipPolicySnapshot against a dashboard older than the proxy', () => {
  it('a 400 for a newer field: sent again without it, and that counts as shipped', async () => {
    const d = await dashboard(strictOld);
    expect(await shipPolicySnapshot(snapshot(), d.creds)).toBe(true);
    expect(d.seen).toHaveLength(2);
    expect('apps' in d.seen[0]).toBe(true);
    expect('apps' in d.seen[1]).toBe(false);
    // Everything else rides the retry unchanged.
    expect(d.seen[1]).toMatchObject({ mode: 'standard', activeShields: ['stripe'] });
  });

  it('a dashboard that knows the field gets it in one request', async () => {
    const d = await dashboard(() => 201);
    expect(await shipPolicySnapshot(snapshot(), d.creds)).toBe(true);
    expect(d.seen).toHaveLength(1);
    expect('apps' in d.seen[0]).toBe(true);
  });

  it('no retry for another failure, or a 400 with no newer field to drop', async () => {
    const down = await dashboard(() => 500);
    expect(await shipPolicySnapshot(snapshot(), down.creds)).toBe(false);
    expect(down.seen).toHaveLength(1);

    const bad = await dashboard(() => 400);
    const body = snapshot();
    delete (body as { apps?: unknown }).apps;
    expect(await shipPolicySnapshot(body, bad.creds)).toBe(false);
    expect(bad.seen).toHaveLength(1);
  });
});

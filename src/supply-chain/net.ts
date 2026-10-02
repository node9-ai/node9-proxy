// src/supply-chain/net.ts
// Endpoints and a bounded JSON fetch for the package check.
//
// URL overrides exist for tests only: they are honoured when NODE9_TESTING=1
// and ignored otherwise, so an inherited environment variable cannot point a
// real install at a lookalike advisory service. Under NODE9_TESTING=1 with no
// override, the hot-path lookups make NO network call at all (they record a
// miss), so the suite never depends on the internet.

export interface Endpoints {
  osvBucket: string | null;
  osvApi: string | null;
  npmRegistry: string | null;
  pypi: string | null;
}

const DEFAULTS = {
  osvBucket: 'https://osv-vulnerabilities.storage.googleapis.com',
  osvApi: 'https://api.osv.dev',
  npmRegistry: 'https://registry.npmjs.org',
  pypi: 'https://pypi.org',
};

const OVERRIDES: Record<keyof Endpoints, string> = {
  osvBucket: 'NODE9_OSV_BUCKET_URL',
  osvApi: 'NODE9_OSV_API_URL',
  npmRegistry: 'NODE9_NPM_REGISTRY_URL',
  pypi: 'NODE9_PYPI_URL',
};

export function endpoints(): Endpoints {
  const testing = process.env.NODE9_TESTING === '1';
  const pick = (k: keyof Endpoints): string | null => {
    if (!testing) return DEFAULTS[k];
    const v = process.env[OVERRIDES[k]];
    return v ? v.replace(/\/+$/, '') : null;
  };
  return {
    osvBucket: pick('osvBucket'),
    osvApi: pick('osvApi'),
    npmRegistry: pick('npmRegistry'),
    pypi: pick('pypi'),
  };
}

/**
 * GET or POST, parse JSON, with a hard timeout and a response-size cap. The
 * body is read as a stream and abandoned past `maxBytes`, so a huge registry
 * document costs at most that much. Throws on any failure; callers fail open.
 */
export async function fetchJson(
  url: string,
  opts: { timeoutMs: number; maxBytes: number; headers?: Record<string, string>; body?: string }
): Promise<unknown> {
  const res = await fetch(url, {
    method: opts.body !== undefined ? 'POST' : 'GET',
    headers: {
      ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...opts.headers,
    },
    body: opts.body,
    signal: AbortSignal.timeout(opts.timeoutMs),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > opts.maxBytes) throw new Error('response too large');
  if (!res.body) throw new Error('empty body');
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > opts.maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error('response too large');
    }
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

import { describe, it, expect, vi, beforeEach } from 'vitest';
import http from 'http';

// Mock heavy dependencies before importing tail
vi.mock('fs');
vi.mock('os', () => ({ default: { homedir: () => '/mock/home', tmpdir: () => '/tmp' } }));
vi.mock('../daemon', () => ({ DAEMON_PORT: 7391 }));
vi.mock('chalk', () => ({
  default: {
    green: (s: string) => s,
    red: (s: string) => s,
    cyan: { bold: (s: string) => ({ toString: () => s }) },
    dim: (s: string) => s,
    yellow: (s: string) => s,
    gray: (s: string) => s,
    white: { bold: (s: string) => s },
  },
}));
vi.mock('child_process', () => ({ spawn: vi.fn() }));

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Replace http.request with a mock that:
 *  - captures the response callback via mockImplementationOnce so `callbacks.respond`
 *    can invoke it with a synthetic IncomingMessage (no fragile mock.calls lookup)
 *  - exposes timeout/error triggers through the same `callbacks` object
 *  - calls the test-supplied `handler` when req.end() fires, giving the handler
 *    a chance to drive whichever scenario it needs */
function mockHttpRequest(
  handler: (
    req: {
      setTimeout: ReturnType<typeof vi.fn>;
      on: ReturnType<typeof vi.fn>;
      once: ReturnType<typeof vi.fn>;
      end: ReturnType<typeof vi.fn>;
      destroy: ReturnType<typeof vi.fn>;
    },
    callbacks: {
      respond?: (statusCode: number) => void;
      error?: (code: string) => void;
      timeout?: () => void;
    }
  ) => void
): void {
  vi.spyOn(http, 'request').mockImplementationOnce((...args: unknown[]) => {
    // tail.ts always uses the 2-arg form: http.request(options, callback).
    // Fail loudly if the signature ever changes to 3-arg (url, options, callback).
    if (args.length < 2 || typeof args[1] !== 'function')
      throw new Error(`http.request call signature changed: expected 2 args, got ${args.length}`);
    const resCallback = args[1] as (res: unknown) => void;

    const callbacks: {
      respond?: (statusCode: number) => void;
      error?: (code: string) => void;
      timeout?: () => void;
    } = {};

    const mockReq: Record<string, ReturnType<typeof vi.fn>> = {
      setTimeout: vi.fn((_ms: number, cb: () => void) => {
        callbacks.timeout = cb;
      }),
      on: vi.fn(),
      once: vi.fn((event: string, cb: (err?: NodeJS.ErrnoException) => void) => {
        if (event === 'error')
          callbacks.error = (code: string) => cb(Object.assign(new Error(), { code }));
      }),
      end: vi.fn(),
      destroy: vi.fn(),
    };

    // Wire up respond: builds a minimal IncomingMessage-like object and invokes
    // the real response callback captured above — no mock.calls lookup needed.
    callbacks.respond = (statusCode: number) => {
      const mockRes = {
        statusCode,
        resume: vi.fn(),
        on: vi.fn((event: string, endHandler: () => void) => {
          if (event === 'end') endHandler();
        }),
      };
      resCallback?.(mockRes);
    };

    mockReq.end.mockImplementation(() => handler(mockReq as never, callbacks));

    return mockReq as unknown as http.ClientRequest;
  });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('startTail --clear error handling', () => {
  beforeEach(() => {
    // resetModules() forces each test to re-import tail.js fresh, which means
    // the http.request spy MUST be set up (via mockHttpRequest) before the
    // dynamic import — otherwise the module captures the unspied original.
    vi.resetModules();
    vi.clearAllMocks();
    // ensureDaemon: make the health-check fetch succeed so we reach the --clear logic
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
  });

  it('resolves without throwing when daemon returns 200', async () => {
    mockHttpRequest((_req, cb) => {
      cb.respond?.(200);
    });

    const { startTail } = await import('../tui/tail.js');
    const getSpy = vi.spyOn(http, 'get');
    await expect(startTail({ clear: true })).resolves.toBeUndefined();
    // --clear must never open an SSE streaming connection
    expect(getSpy).not.toHaveBeenCalled();
  });

  it('resolves without throwing for any 2xx status (e.g. 299)', async () => {
    mockHttpRequest((_req, cb) => {
      cb.respond?.(299);
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).resolves.toBeUndefined();
  });

  it('throws with ECONNREFUSED message when daemon is not running', async () => {
    mockHttpRequest((_req, cb) => {
      cb.error?.('ECONNREFUSED');
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/not running/i);
  });

  it('throws with ETIMEDOUT message when daemon hangs and destroys the request', async () => {
    let capturedReq: { destroy: ReturnType<typeof vi.fn> } | undefined;
    mockHttpRequest((req, cb) => {
      capturedReq = req;
      cb.timeout?.();
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/did not respond/i);
    expect(capturedReq?.destroy).toHaveBeenCalledOnce();
  });

  it('throws with HTTP status when daemon returns non-2xx', async () => {
    mockHttpRequest((_req, cb) => {
      cb.respond?.(500);
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/HTTP 500/);
  });

  it('throws for 3xx status (boundary: 300 is not a success)', async () => {
    mockHttpRequest((_req, cb) => {
      cb.respond?.(300);
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/HTTP 300/);
  });

  it('throws with error code for unrecognised network errors (e.g. ECONNRESET)', async () => {
    mockHttpRequest((_req, cb) => {
      cb.error?.('ECONNRESET');
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/ECONNRESET/);
  });
});

// ── startTail --history ───────────────────────────────────────────────────────

describe('startTail --history flag', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
  });

  it('opens an SSE /events connection (does not call /events/clear)', async () => {
    // The streaming path uses http.get — mock it to capture the call.
    // We don't invoke the response callback, so readline is never created and
    // the function returns as soon as it has set up the request.
    const mockReq = { on: vi.fn() };
    const getSpy = vi
      .spyOn(http, 'get')
      .mockReturnValueOnce(mockReq as unknown as http.ClientRequest);

    const { startTail } = await import('../tui/tail.js');
    await startTail({ history: true });

    expect(getSpy).toHaveBeenCalledOnce();
    // Connects to the SSE endpoint, not the clear endpoint
    expect(String(getSpy.mock.calls[0][0])).toContain('/events');
    expect(String(getSpy.mock.calls[0][0])).not.toContain('/clear');
    // Error listener is always registered on the request
    expect(mockReq.on).toHaveBeenCalledWith('error', expect.any(Function));
  });
});

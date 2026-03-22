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
    // If the call signature ever changes to 3-arg (url, options, callback),
    // update this index from 1 to 2.
    const resCallback = args[1] as ((res: unknown) => void) | undefined;

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
    await expect(startTail({ clear: true })).resolves.toBeUndefined();
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

  it('throws with error code for unrecognised network errors (e.g. ECONNRESET)', async () => {
    mockHttpRequest((_req, cb) => {
      cb.error?.('ECONNRESET');
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/ECONNRESET/);
  });
});

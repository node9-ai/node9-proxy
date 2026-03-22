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

/** Build a minimal mock http.ClientRequest that immediately calls the
 *  supplied handler, simulating the network outcome for --clear tests. */
function mockHttpRequest(
  handler: (
    req: {
      setTimeout: ReturnType<typeof vi.fn>;
      on: ReturnType<typeof vi.fn>;
      end: ReturnType<typeof vi.fn>;
    },
    callbacks: {
      respond?: (statusCode: number) => void;
      error?: (code: string) => void;
      timeout?: () => void;
    }
  ) => void
): {
  respond?: (statusCode: number) => void;
  error?: (code: string) => void;
  timeout?: () => void;
} {
  const callbacks: {
    respond?: (statusCode: number) => void;
    error?: (code: string) => void;
    timeout?: () => void;
  } = {};

  const mockReq: Record<string, ReturnType<typeof vi.fn>> = {
    setTimeout: vi.fn((_ms: number, cb: () => void) => {
      callbacks.timeout = cb;
    }),
    on: vi.fn((event: string, cb: (err?: NodeJS.ErrnoException) => void) => {
      if (event === 'error')
        callbacks.error = (code: string) => cb(Object.assign(new Error(), { code }));
    }),
    end: vi.fn(),
    destroy: vi.fn(),
  };
  mockReq.end.mockImplementation(() => handler(mockReq as never, callbacks));

  vi.spyOn(http, 'request').mockReturnValueOnce(mockReq as unknown as http.ClientRequest);
  return callbacks;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('startTail --clear error handling', () => {
  beforeEach(() => {
    vi.resetModules();
    // ensureDaemon: make the health-check fetch succeed so we reach the --clear logic
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
  });

  it('resolves without throwing when daemon returns 200', async () => {
    mockHttpRequest((_req, _cb) => {
      // Simulate daemon responding with 200
      const mockRes = {
        statusCode: 200,
        resume: vi.fn(),
        on: vi.fn((event: string, handler: () => void) => {
          if (event === 'end') handler();
        }),
      };
      // http.request callback receives the response
      const requestSpy = vi.mocked(http.request);
      const requestCallback = requestSpy.mock.calls[0]?.[1] as
        | ((res: typeof mockRes) => void)
        | undefined;
      requestCallback?.(mockRes);
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

  it('throws with ETIMEDOUT message when daemon hangs', async () => {
    mockHttpRequest((_req, cb) => {
      cb.timeout?.();
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/did not respond/i);
  });

  it('throws with HTTP status when daemon returns non-2xx', async () => {
    mockHttpRequest((_req, _cb) => {
      const mockRes = {
        statusCode: 500,
        resume: vi.fn(),
        on: vi.fn((event: string, handler: () => void) => {
          if (event === 'end') handler();
        }),
      };
      const requestSpy = vi.mocked(http.request);
      const requestCallback = requestSpy.mock.calls[0]?.[1] as
        | ((res: typeof mockRes) => void)
        | undefined;
      requestCallback?.(mockRes);
    });

    const { startTail } = await import('../tui/tail.js');
    await expect(startTail({ clear: true })).rejects.toThrow(/HTTP 500/);
  });
});

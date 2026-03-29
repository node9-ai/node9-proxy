import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import http from 'http';
import { PassThrough } from 'stream';
import { EventEmitter } from 'events';

// Mock heavy dependencies before importing tail
vi.mock('fs');
vi.mock('os', () => ({ default: { homedir: () => '/mock/home', tmpdir: () => '/tmp' } }));
vi.mock('../daemon', () => ({ DAEMON_PORT: 7391 }));
vi.mock('chalk', () => {
  const fn = (s: string) => s;
  const withBold = (s: string) => Object.assign(fn(s), { toString: () => s });
  return {
    default: {
      green: fn,
      red: fn,
      // chalk.cyan('…') and chalk.cyan.bold('…') are both used
      cyan: Object.assign(fn, { bold: withBold }),
      dim: fn,
      yellow: fn,
      gray: fn,
      bold: fn,
      white: Object.assign(fn, { bold: fn }),
      bgRed: { white: { bold: fn } },
    },
  };
});
vi.mock('child_process', () => ({ spawn: vi.fn(), execSync: vi.fn() }));
vi.mock('../core', () => ({
  getConfig: vi.fn(() => ({ settings: { approvers: { browser: false } } })),
}));

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

// ── Interactive approval card – keypress regression ───────────────────────────
//
// Regression for: tail card rendered but [A]/[D] keypresses completely
// unresponsive — caused by using raw `stdin.on('data', ...)` instead of
// `readline.emitKeypressEvents` + `stdin.on('keypress', ...)`.
//
// Strategy:
//   - Replace process.stdin with an EventEmitter that has isTTY=true and
//     TTY methods (setRawMode, resume, pause) so canApprove=true.
//   - Use a PassThrough stream as the fake SSE HTTP response — real readline
//     parses it, no readline mock needed.
//   - Spy on mockStdin.on AFTER startTail() initialises (so emitKeypressEvents
//     internal data listener is not captured) to verify only 'keypress' is
//     registered when a card arrives, never 'data'.
//   - Invoke the captured keypress handler directly to test allow/deny logic.

describe('interactive approval card – keypress regression', () => {
  const originalStdin = process.stdin;

  type MockStdin = EventEmitter & {
    isTTY: boolean;
    setRawMode: ReturnType<typeof vi.fn>;
    resume: ReturnType<typeof vi.fn>;
    pause: ReturnType<typeof vi.fn>;
  };

  let mockStdin: MockStdin;
  let sseStream: PassThrough & { statusCode: number };

  const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

  function sendSse(event: string, data: unknown): void {
    sseStream.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  /** Spy on http.request and capture the last POSTed body + call the 200 callback. */
  function captureDecision(): { getBody: () => string } {
    let requestBody = '';
    vi.spyOn(http, 'request').mockImplementation(
      (_opts: unknown, callback?: unknown) =>
        ({
          on: vi.fn(),
          end: vi.fn((body: string) => {
            requestBody = body;
            if (typeof callback === 'function')
              (callback as (r: unknown) => void)({ statusCode: 200, resume: vi.fn() });
          }),
        }) as unknown as http.ClientRequest
    );
    return { getBody: () => requestBody };
  }

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));

    // Prevent process.exit() from killing the test runner when the SSE stream
    // closes (tail.ts calls process.exit(1) on disconnect).
    vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);
    // Prevent SIGINT listener accumulation across test runs.
    vi.spyOn(process, 'on').mockReturnValue(process);

    // Fake TTY stdin: EventEmitter + TTY-specific methods.
    mockStdin = Object.assign(new EventEmitter(), {
      isTTY: true,
      setRawMode: vi.fn().mockReturnThis(),
      resume: vi.fn().mockReturnThis(),
      pause: vi.fn().mockReturnThis(),
    }) as MockStdin;
    Object.defineProperty(process, 'stdin', { value: mockStdin, configurable: true });

    // Fake TTY stdout (suppresses terminal writes in test output).
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    // PassThrough stream acts as an http.IncomingMessage for readline.
    sseStream = Object.assign(new PassThrough(), { statusCode: 200 });
    vi.spyOn(http, 'get').mockImplementation((_url: unknown, callback?: unknown) => {
      if (typeof callback === 'function')
        (callback as (r: unknown) => void)(sseStream as unknown as http.IncomingMessage);
      return { on: vi.fn() } as unknown as http.ClientRequest;
    });
  });

  afterEach(() => {
    Object.defineProperty(process, 'stdin', { value: originalStdin, configurable: true });
    Object.defineProperty(process.stdout, 'isTTY', { value: undefined, configurable: true });
    sseStream.destroy();
    vi.restoreAllMocks();
  });

  it('registers keypress listener (not data) on stdin when an interactive card arrives', async () => {
    const { startTail } = await import('../tui/tail.js');
    void startTail({});
    await tick(); // let readline attach to sseStream

    // Spy AFTER init so emitKeypressEvents internal `data` listener is not captured.
    const stdinOnSpy = vi.spyOn(mockStdin, 'on');

    sendSse('csrf', { token: 'tok' });
    sendSse('add', { id: 'r1', toolName: 'bash', args: { command: 'ls' }, interactive: true });
    await tick();

    const events = stdinOnSpy.mock.calls.map((c) => c[0]);
    // Must register a 'keypress' listener for the card — regression guard against
    // reverting to raw 'data' events (tests 2 & 3 verify the handler fires correctly).
    expect(events).toContain('keypress');
    expect(mockStdin.setRawMode).toHaveBeenCalledWith(true);
  });

  it('[A] keypress sends allow decision to daemon', async () => {
    const { getBody } = captureDecision();
    const { startTail } = await import('../tui/tail.js');
    void startTail({});
    await tick();

    const stdinOnSpy = vi.spyOn(mockStdin, 'on');
    sendSse('csrf', { token: 'csrf123' });
    sendSse('add', { id: 'r2', toolName: 'bash', args: {}, interactive: true });
    await tick();

    const call = stdinOnSpy.mock.calls.find((c) => c[0] === 'keypress');
    expect(call).toBeDefined();
    const handler = call![1] as (str: string, key: { name: string }) => void;

    handler('a', { name: 'a' });
    await tick();

    expect(JSON.parse(getBody())).toMatchObject({ decision: 'allow' });
  });

  it('[Enter/return] keypress sends allow decision to daemon', async () => {
    const { getBody } = captureDecision();
    const { startTail } = await import('../tui/tail.js');
    void startTail({});
    await tick();

    const stdinOnSpy = vi.spyOn(mockStdin, 'on');
    sendSse('csrf', { token: 'csrf789' });
    sendSse('add', { id: 'r2b', toolName: 'bash', args: {}, interactive: true });
    await tick();

    const handler = stdinOnSpy.mock.calls.find((c) => c[0] === 'keypress')![1] as (
      str: string,
      key: { name: string }
    ) => void;

    handler('\r', { name: 'return' });
    await tick();

    expect(JSON.parse(getBody())).toMatchObject({ decision: 'allow' });
  });

  it('[D] keypress sends deny decision to daemon', async () => {
    const { getBody } = captureDecision();
    const { startTail } = await import('../tui/tail.js');
    void startTail({});
    await tick();

    const stdinOnSpy = vi.spyOn(mockStdin, 'on');
    sendSse('csrf', { token: 'csrf456' });
    sendSse('add', { id: 'r3', toolName: 'bash', args: {}, interactive: true });
    await tick();

    const handler = stdinOnSpy.mock.calls.find((c) => c[0] === 'keypress')![1] as (
      str: string,
      key: { name: string }
    ) => void;

    handler('d', { name: 'd' });
    await tick();

    expect(JSON.parse(getBody())).toMatchObject({ decision: 'deny' });
  });

  it('does not register any keypress listener when interactive:false', async () => {
    const { startTail } = await import('../tui/tail.js');
    void startTail({});
    await tick();

    const stdinOnSpy = vi.spyOn(mockStdin, 'on');
    sendSse('csrf', { token: 'tok' });
    sendSse('add', { id: 'r4', toolName: 'bash', args: {}, interactive: false });
    await tick();

    expect(stdinOnSpy.mock.calls.map((c) => c[0])).not.toContain('keypress');
  });
});

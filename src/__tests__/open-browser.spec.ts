// openBrowser receives `verificationUrl` straight out of the cloud's
// /device/start response, so the value is attacker-controlled whenever the
// endpoint is (a spoofed backend, or `node9 login --api-url ...`).
//
// It used to call spawn('start', [url], { shell: true }) on Windows. With the
// shell option set, Node concatenates the args into one command string and
// does NOT escape them — Node's own DEP0190 warning says exactly this — so a
// URL containing `&` ran whatever followed it under cmd.exe.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

type SpawnArgs = [string, string[], Record<string, unknown>?];
const spawnMock = vi.fn((..._a: SpawnArgs) => ({ on: vi.fn(), unref: vi.fn() }));
vi.mock('child_process', () => ({
  spawn: (...a: SpawnArgs) => spawnMock(...a),
}));

let openBrowser: typeof import('../utils/open-browser').openBrowser;
const savedEnv = { ...process.env };

beforeEach(async () => {
  vi.resetModules();
  spawnMock.mockClear();
  // A "desktop" machine: not SSH, and a display present so the Linux guard
  // does not short-circuit the thing we are testing.
  delete process.env.SSH_CONNECTION;
  delete process.env.SSH_TTY;
  process.env.DISPLAY = ':0';
  ({ openBrowser } = await import('../utils/open-browser.js'));
});

afterEach(() => {
  process.env = { ...savedEnv };
});

describe('openBrowser URL validation', () => {
  it('opens an ordinary https URL', () => {
    expect(openBrowser('https://app.node9.ai/device?code=ABCD')).toBe(true);
    expect(spawnMock).toHaveBeenCalledTimes(1);
  });

  it('refuses a URL carrying a shell metacharacter', () => {
    // The payload that mattered: everything after `&` used to run.
    expect(openBrowser('https://ok.example/ & calc.exe')).toBe(false);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('refuses quotes and backticks', () => {
    expect(openBrowser('https://ok.example/"x')).toBe(false);
    expect(openBrowser('https://ok.example/`x`')).toBe(false);
    expect(openBrowser("https://ok.example/'x")).toBe(false);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('refuses embedded newlines and control characters', () => {
    expect(openBrowser('https://ok.example/\n& whoami')).toBe(false);
    expect(openBrowser('https://ok.example/\x00')).toBe(false);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('refuses non-web schemes', () => {
    expect(openBrowser('file:///etc/passwd')).toBe(false);
    expect(openBrowser('javascript:alert(1)')).toBe(false);
    expect(openBrowser('data:text/html,<script>')).toBe(false);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('refuses a value that is not a URL at all', () => {
    expect(openBrowser('')).toBe(false);
    expect(openBrowser('not a url')).toBe(false);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('never passes the shell option, so args cannot be concatenated', () => {
    openBrowser('https://app.node9.ai/device');
    const opts = spawnMock.mock.calls[0][2];
    expect(opts?.shell).toBeUndefined();
  });

  it('keeps the URL in its own argument slot', () => {
    const url = 'https://app.node9.ai/device?code=ABCD';
    openBrowser(url);
    const args = spawnMock.mock.calls[0][1];
    expect(args).toContain(url);
  });

  it('still refuses to open over SSH', () => {
    process.env.SSH_CONNECTION = '1.2.3.4 1 5.6.7.8 22';
    expect(openBrowser('https://app.node9.ai/device')).toBe(false);
    expect(spawnMock).not.toHaveBeenCalled();
  });
});

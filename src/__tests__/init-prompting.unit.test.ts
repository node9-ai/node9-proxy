import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import https from 'https';
vi.mock('../machine-id', () => ({ getMachineId: () => 'test-machine' }));
vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));
import { confirm } from '@inquirer/prompts';
import { askTelemetry, TELEMETRY_PROMPT } from '../cli/commands/init';
let request: ReturnType<typeof vi.spyOn>;
const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
beforeEach(() => {
  vi.stubEnv('CI', '');
  vi.stubEnv('GITHUB_ACTIONS', '');
  vi.stubEnv('NODE9_NONINTERACTIVE', '');
  Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: true });
  Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: true });
  vi.mocked(confirm).mockReset();
  request = vi.spyOn(https, 'request').mockImplementation((() => {
    const req = { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    return req;
  }) as never);
});
afterEach(() => {
  for (const [stream, descriptor] of [
    [process.stdin, stdinDescriptor],
    [process.stdout, stdoutDescriptor],
  ] as const) {
    if (descriptor) Object.defineProperty(stream, 'isTTY', descriptor);
    else Reflect.deleteProperty(stream, 'isTTY');
  }
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});
describe('install statistics consent', () => {
  it('uses the requested payload description without claiming anonymity', () => {
    expect(TELEMETRY_PROMPT).toBe(
      'Send usage stats to help improve node9? (a random install ID, detected agents, OS and version. No code, no args.)'
    );
  });
  it('still asks when no agents were found, and sends only after yes', async () => {
    vi.mocked(confirm).mockResolvedValue(true);
    await askTelemetry([], true);
    expect(confirm).toHaveBeenCalledWith({ message: TELEMETRY_PROMPT, default: true });
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('does not send after no', async () => {
    vi.mocked(confirm).mockResolvedValue(false);
    await askTelemetry([], true);
    expect(request).not.toHaveBeenCalled();
  });
  it('does not ask or send in CI', async () => {
    vi.stubEnv('CI', '1');
    await askTelemetry([], true);
    expect(confirm).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
  });
  it('requires interactive input as well as output', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: false });
    await askTelemetry([], true);
    expect(confirm).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
  });
});

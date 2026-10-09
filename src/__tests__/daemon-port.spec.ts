// NODE9_DAEMON_PORT: honoured under NODE9_TESTING=1 only, validated, and the
// exported DAEMON_PORT constant follows it at module load.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { resolveDaemonPort } from '../auth/daemon';

const DEFAULT = 7391;

describe('resolveDaemonPort', () => {
  it('is 7391 with nothing set', () => {
    expect(resolveDaemonPort({})).toBe(DEFAULT);
  });

  it('ignores the override outside test mode', () => {
    expect(resolveDaemonPort({ NODE9_DAEMON_PORT: '7392' })).toBe(DEFAULT);
    expect(resolveDaemonPort({ NODE9_DAEMON_PORT: '7392', NODE9_TESTING: '0' })).toBe(DEFAULT);
  });

  it('honours a valid override under NODE9_TESTING=1', () => {
    expect(resolveDaemonPort({ NODE9_TESTING: '1', NODE9_DAEMON_PORT: '7392' })).toBe(7392);
    expect(resolveDaemonPort({ NODE9_TESTING: '1', NODE9_DAEMON_PORT: '65535' })).toBe(65535);
  });

  it('keeps the default for an invalid override, even in test mode', () => {
    for (const bad of ['', 'abc', '0', '80', '1023', '65536', '-1', '7392.5', '7392abc']) {
      expect(
        resolveDaemonPort({ NODE9_TESTING: '1', NODE9_DAEMON_PORT: bad }),
        `value ${JSON.stringify(bad)}`
      ).toBe(DEFAULT);
    }
  });
});

describe('DAEMON_PORT constant', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('follows the override at module load under test mode', async () => {
    vi.stubEnv('NODE9_TESTING', '1');
    vi.stubEnv('NODE9_DAEMON_PORT', '7393');
    vi.resetModules();
    const mod = await import('../auth/daemon.js');
    expect(mod.DAEMON_PORT).toBe(7393);
  });

  it('stays 7391 when the override is set outside test mode', async () => {
    vi.stubEnv('NODE9_TESTING', '');
    vi.stubEnv('NODE9_DAEMON_PORT', '7393');
    vi.resetModules();
    const mod = await import('../auth/daemon.js');
    expect(mod.DAEMON_PORT).toBe(DEFAULT);
  });
});

// Code review of the fw#318 fixes: a failure writing the exposure-source audit
// row is reported in hook-debug.log (node9-proxy CLAUDE.md: catch blocks that
// guard the audit trail always write there), and the session is still marked.
import { describe, it, expect, vi, beforeEach } from 'vitest';

const appendToLog = vi.fn();
const markSessionExposed = vi.fn();
const notifySessionExposure = vi.fn(async (..._a: unknown[]) => undefined);

vi.mock('../audit', async (importOriginal) => {
  const real = await importOriginal<typeof import('../audit')>();
  return {
    ...real,
    appendLocalAudit: vi.fn(() => {
      throw new Error('disk full');
    }),
    appendToLog: (...a: unknown[]) => appendToLog(...a),
  };
});
vi.mock('../exposure/marker', () => ({
  markSessionExposed: (...a: unknown[]) => markSessionExposed(...a),
}));
vi.mock('../auth/daemon', () => ({
  notifySessionExposure: (...a: unknown[]) => notifySessionExposure(...a),
}));

import { recordExposureSource } from '../exposure/source';
import { HOOK_DEBUG_LOG } from '../audit';

beforeEach(() => {
  appendToLog.mockClear();
  markSessionExposed.mockClear();
  notifySessionExposure.mockClear();
});

describe('recordExposureSource when the audit row fails', () => {
  it('writes the failure to hook-debug.log and still marks the session', async () => {
    const eid = await recordExposureSource({
      tool: 'WebFetch',
      args: { url: 'https://x.example' },
      sessionId: 's1',
      destinations: [],
      hashArgs: true,
    });
    expect(eid).toBeUndefined();
    expect(appendToLog).toHaveBeenCalledWith(
      HOOK_DEBUG_LOG,
      expect.objectContaining({
        event: 'exposure-source-row-fail',
        tool: 'WebFetch',
        error: 'disk full',
      })
    );
    expect(markSessionExposed).toHaveBeenCalledWith('s1');
    expect(notifySessionExposure).toHaveBeenCalledTimes(1);
  });
});

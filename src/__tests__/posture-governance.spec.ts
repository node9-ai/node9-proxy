// Unit tests for the governed-config posture checks (Report UI v2 · P3).
// Each check reads getConfig(cwd) and returns Finding[]; we mock getConfig to
// drive the config permutations and assert the finding shape/severity.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const getConfig = vi.fn();
vi.mock('../config', () => ({ getConfig: (...a: unknown[]) => getConfig(...a) }));

import {
  checkData,
  checkApprovalConfig,
  checkToolGovernance,
  checkFiles,
  checkCost,
} from '../posture/governance';

const ctx = { home: '/home/u', cwd: '/proj' };

// Minimal config the checks read; override per test.
function cfg(over: {
  dlp?: { enabled?: boolean; pii?: string };
  smartRules?: unknown[];
  appPermissions?: Record<string, Record<string, string>>;
  approvers?: { native: boolean; browser: boolean; cloud: boolean; terminal: boolean };
  reviewChannel?: string;
  approvalTimeoutMs?: number;
}) {
  return {
    policy: {
      dlp: over.dlp ?? { enabled: true, pii: 'block' },
      smartRules: over.smartRules ?? [],
      appPermissions: over.appPermissions ?? {},
    },
    settings: {
      approvers: over.approvers ?? {
        native: false,
        browser: false,
        cloud: false,
        terminal: false,
      },
      reviewChannel: over.reviewChannel,
      approvalTimeoutMs: over.approvalTimeoutMs,
    },
  };
}

beforeEach(() => getConfig.mockReset());

describe('checkData', () => {
  it('flags DLP off as a high finding', () => {
    getConfig.mockReturnValue(cfg({ dlp: { enabled: false } }));
    const f = checkData(ctx)[0];
    expect(f.category).toBe('Data');
    expect(f.severity).toBe('high');
    expect(f.owner).toBe('node9');
  });

  it('flags PII detect-only as medium when DLP is on but PII is not blocking', () => {
    getConfig.mockReturnValue(cfg({ dlp: { enabled: true, pii: 'off' } }));
    const f = checkData(ctx)[0];
    expect(f.severity).toBe('medium');
    expect(f.scoreWeight).toBeGreaterThan(0);
  });

  it('is covered (advisory) when DLP on + PII block', () => {
    getConfig.mockReturnValue(cfg({ dlp: { enabled: true, pii: 'block' } }));
    const f = checkData(ctx)[0];
    expect(f.severity).toBe('advisory');
    expect(f.coverageProbe).toEqual({ kind: 'fileRead', paths: ['/home/u/.aws/credentials'] });
  });
});

describe('checkApprovalConfig', () => {
  it('flags a zero approval timeout (every review auto-denies)', () => {
    getConfig.mockReturnValue(
      cfg({
        approvalTimeoutMs: 0,
        approvers: { native: true, browser: false, cloud: false, terminal: false },
      })
    );
    const f = checkApprovalConfig(ctx)[0];
    expect(f.severity).toBe('high');
    expect(f.title).toMatch(/timeout is 0/i);
  });

  it('flags no approver channel as high', () => {
    getConfig.mockReturnValue(cfg({}));
    const f = checkApprovalConfig(ctx)[0];
    expect(f.severity).toBe('high');
    expect(f.title).toMatch(/no approver/i);
  });

  it('passes (no finding) when the inline ask channel is set', () => {
    getConfig.mockReturnValue(cfg({ reviewChannel: 'ask' }));
    expect(checkApprovalConfig(ctx)).toEqual([]);
  });

  it('passes (no finding) when a terminal approver is enabled', () => {
    getConfig.mockReturnValue(
      cfg({ approvers: { native: false, browser: false, cloud: false, terminal: true } })
    );
    expect(checkApprovalConfig(ctx)).toEqual([]);
  });
});

describe('checkToolGovernance', () => {
  it('flags no rules + no governed apps as medium', () => {
    getConfig.mockReturnValue(cfg({ smartRules: [], appPermissions: {} }));
    const f = checkToolGovernance(ctx)[0];
    expect(f.severity).toBe('medium');
    expect(f.scoreWeight).toBeGreaterThan(0);
  });

  it('passes (no finding) when a smart rule exists', () => {
    getConfig.mockReturnValue(cfg({ smartRules: [{ name: 'r' }] }));
    expect(checkToolGovernance(ctx)).toEqual([]);
  });

  it('passes (no finding) when a governed MCP app exists', () => {
    getConfig.mockReturnValue(cfg({ appPermissions: { redis: { set: 'block' } } }));
    expect(checkToolGovernance(ctx)).toEqual([]);
  });

  it('does not count an app with zero tool decisions as governed', () => {
    getConfig.mockReturnValue(cfg({ appPermissions: { redis: {} } }));
    expect(checkToolGovernance(ctx)[0].severity).toBe('medium');
  });
});

describe('checkFiles + checkCost', () => {
  it('Files is baseline-covered (advisory) with a jail coverage probe', () => {
    getConfig.mockReturnValue(cfg({}));
    const f = checkFiles(ctx)[0];
    expect(f.category).toBe('Files');
    expect(f.severity).toBe('advisory');
    expect(f.coverageProbe?.kind).toBe('fileRead');
  });

  it('Cost is an advisory AVAILABLE opportunity (no budget field yet)', () => {
    const f = checkCost(ctx)[0];
    expect(f.category).toBe('Cost');
    expect(f.severity).toBe('advisory');
    expect(f.node9Reduces).toBe(true);
    expect(f.scoreWeight).toBeGreaterThan(0);
  });
});

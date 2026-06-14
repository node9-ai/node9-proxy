/**
 * Unit tests for the MCP rug-pull cloud alert (B-Tier2).
 *
 * When the gateway detects that a server's pinned tool definitions changed
 * (possible tool poisoning), it emits a synthetic audit row to the SaaS via
 * auditLocalAllow with checkedBy 'mcp-pin-mismatch'. These tests verify the
 * emit shape, the credential gate, and that it never throws (fail-open).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../config', () => ({ getCredentials: vi.fn() }));
vi.mock('../auth/cloud', () => ({ auditLocalAllow: vi.fn() }));

import { getCredentials } from '../config';
import { auditLocalAllow } from '../auth/cloud';
import {
  reportPinMismatchToCloud,
  reportInventoryToCloud,
  reportLargeResponseToCloud,
} from '../mcp-gateway/index';

const CREDS = { apiKey: 'n9_live_abc', apiUrl: 'https://api.node9.ai/api/v1/intercept' };

describe('reportPinMismatchToCloud (B-Tier2 rug-pull alert)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('emits a synthetic audit row with checkedBy mcp-pin-mismatch when logged in', () => {
    vi.mocked(getCredentials).mockReturnValue(CREDS);

    reportPinMismatchToCloud('github', 'Claude');

    expect(auditLocalAllow).toHaveBeenCalledTimes(1);
    const call = vi.mocked(auditLocalAllow).mock.calls[0];
    expect(call[0]).toBe('mcp-server:github'); // toolName
    expect(call[2]).toBe('mcp-pin-mismatch'); // checkedBy → firewall maps to AUTO_BLOCKED
    expect(call[3]).toEqual(CREDS); // creds
    expect(call[4]).toEqual({ mcpServer: 'github', agent: 'Claude' }); // meta → shellType mcp::github
    // riskMetadata (8th positional arg) carries the rule attribution
    expect(call[7]).toMatchObject({
      ruleName: expect.stringContaining('rug pull'),
      ruleDescription: expect.stringContaining('github'),
    });
  });

  it('does nothing when not logged in (no credentials)', () => {
    vi.mocked(getCredentials).mockReturnValue(undefined as unknown as typeof CREDS);

    reportPinMismatchToCloud('github', 'Claude');

    expect(auditLocalAllow).not.toHaveBeenCalled();
  });

  it('never throws if getCredentials throws (fail-open)', () => {
    vi.mocked(getCredentials).mockImplementation(() => {
      throw new Error('cred read failed');
    });

    expect(() => reportPinMismatchToCloud('github')).not.toThrow();
    expect(auditLocalAllow).not.toHaveBeenCalled();
  });
});

describe('reportInventoryToCloud (B-Tier2 tool inventory)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('emits an mcp-discovered row carrying mcpToolCount when logged in', () => {
    vi.mocked(getCredentials).mockReturnValue(CREDS);

    reportInventoryToCloud('github', 12, 'Claude');

    expect(auditLocalAllow).toHaveBeenCalledTimes(1);
    const call = vi.mocked(auditLocalAllow).mock.calls[0];
    expect(call[0]).toBe('mcp-server:github'); // toolName
    expect(call[2]).toBe('mcp-discovered'); // checkedBy (informational, AUTO_ALLOWED)
    expect(call[4]).toEqual({ mcpServer: 'github', agent: 'Claude' });
    expect(call[7]).toEqual({ mcpToolCount: 12 }); // numeric riskMetadata
  });

  it('skips when not logged in and never throws', () => {
    vi.mocked(getCredentials).mockReturnValue(undefined as unknown as typeof CREDS);
    reportInventoryToCloud('github', 12);
    expect(auditLocalAllow).not.toHaveBeenCalled();

    vi.mocked(getCredentials).mockImplementation(() => {
      throw new Error('boom');
    });
    expect(() => reportInventoryToCloud('github', 12)).not.toThrow();
  });
});

describe('reportLargeResponseToCloud (B-Tier2 context-bloat)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('emits an mcp-large-response row carrying mcpResponseBytes', () => {
    vi.mocked(getCredentials).mockReturnValue(CREDS);

    reportLargeResponseToCloud('github', 800_000, 'Claude');

    const call = vi.mocked(auditLocalAllow).mock.calls[0];
    expect(call[0]).toBe('mcp-server:github');
    expect(call[2]).toBe('mcp-large-response');
    expect(call[7]).toEqual({ mcpResponseBytes: 800_000 });
  });

  it('skips when not logged in and never throws', () => {
    vi.mocked(getCredentials).mockReturnValue(undefined as unknown as typeof CREDS);
    reportLargeResponseToCloud('github', 800_000);
    expect(auditLocalAllow).not.toHaveBeenCalled();

    vi.mocked(getCredentials).mockImplementation(() => {
      throw new Error('boom');
    });
    expect(() => reportLargeResponseToCloud('github', 1)).not.toThrow();
  });
});

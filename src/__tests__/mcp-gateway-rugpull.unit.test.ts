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

  it('emits mcp-pin-mismatch with the FRIENDLY label as mcpServer, serverKey kept as identity (F4b)', () => {
    vi.mocked(getCredentials).mockReturnValue(CREDS);

    // Production sends a 16-hex serverKey — the display label rides separately.
    reportPinMismatchToCloud('0c654ece65fb5d6f', 'github', 'Claude');

    expect(auditLocalAllow).toHaveBeenCalledTimes(1);
    const call = vi.mocked(auditLocalAllow).mock.calls[0];
    expect(call[0]).toBe('mcp-server:0c654ece65fb5d6f'); // resource keeps the KEY (identity)
    expect(call[2]).toBe('mcp-pin-mismatch'); // checkedBy → firewall maps to AUTO_BLOCKED
    expect(call[3]).toEqual(CREDS); // creds
    // meta → shellType mcp::github — the dashboard shows the NAME, never the hash
    expect(call[4]).toEqual({ mcpServer: 'github', agent: 'Claude' });
    // riskMetadata carries the rule attribution; the remediation command
    // needs the KEY (the CLI takes a serverKey, not a label).
    expect(call[7]).toMatchObject({
      ruleName: expect.stringContaining('rug pull'),
      ruleDescription: expect.stringContaining('node9 mcp pin update 0c654ece65fb5d6f'),
    });
    // The display sentence names the server by its label.
    expect((call[7] as { ruleDescription: string }).ruleDescription).toContain('"github"');
  });

  it('does nothing when not logged in (no credentials)', () => {
    vi.mocked(getCredentials).mockReturnValue(undefined as unknown as typeof CREDS);

    reportPinMismatchToCloud('github', 'github', 'Claude');

    expect(auditLocalAllow).not.toHaveBeenCalled();
  });

  it('never throws if getCredentials throws (fail-open)', () => {
    vi.mocked(getCredentials).mockImplementation(() => {
      throw new Error('cred read failed');
    });

    expect(() => reportPinMismatchToCloud('github', 'github')).not.toThrow();
    expect(auditLocalAllow).not.toHaveBeenCalled();
  });
});

describe('reportInventoryToCloud (B-Tier2 tool inventory)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('emits an mcp-discovered row carrying mcpToolCount when logged in', () => {
    vi.mocked(getCredentials).mockReturnValue(CREDS);

    // The "hash · N tools, 0 calls" dashboard rows came from THIS reporter
    // sending the raw serverKey as mcpServer (F4b root cause).
    reportInventoryToCloud('0c654ece65fb5d6f', 'redis-dev', 12, 'Claude');

    expect(auditLocalAllow).toHaveBeenCalledTimes(1);
    const call = vi.mocked(auditLocalAllow).mock.calls[0];
    expect(call[0]).toBe('mcp-server:0c654ece65fb5d6f'); // resource keeps the KEY
    expect(call[2]).toBe('mcp-discovered'); // checkedBy (informational, AUTO_ALLOWED)
    expect(call[4]).toEqual({ mcpServer: 'redis-dev', agent: 'Claude' }); // label, not hash
    expect(call[7]).toEqual({ mcpToolCount: 12 }); // numeric riskMetadata
  });

  it('skips when not logged in and never throws', () => {
    vi.mocked(getCredentials).mockReturnValue(undefined as unknown as typeof CREDS);
    reportInventoryToCloud('github', 'github', 12);
    expect(auditLocalAllow).not.toHaveBeenCalled();

    vi.mocked(getCredentials).mockImplementation(() => {
      throw new Error('boom');
    });
    expect(() => reportInventoryToCloud('github', 'github', 12)).not.toThrow();
  });
});

describe('reportLargeResponseToCloud (B-Tier2 context-bloat)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('emits an mcp-large-response row carrying mcpResponseBytes', () => {
    vi.mocked(getCredentials).mockReturnValue(CREDS);

    reportLargeResponseToCloud('0c654ece65fb5d6f', 'redis-dev', 800_000, 'Claude');

    const call = vi.mocked(auditLocalAllow).mock.calls[0];
    expect(call[0]).toBe('mcp-server:0c654ece65fb5d6f'); // resource keeps the KEY
    expect(call[2]).toBe('mcp-large-response');
    expect(call[4]).toEqual({ mcpServer: 'redis-dev', agent: 'Claude' }); // label, not hash (F4b)
    expect(call[7]).toEqual({ mcpResponseBytes: 800_000 });
  });

  it('skips when not logged in and never throws', () => {
    vi.mocked(getCredentials).mockReturnValue(undefined as unknown as typeof CREDS);
    reportLargeResponseToCloud('github', 'github', 800_000);
    expect(auditLocalAllow).not.toHaveBeenCalled();

    vi.mocked(getCredentials).mockImplementation(() => {
      throw new Error('boom');
    });
    expect(() => reportLargeResponseToCloud('github', 'github', 1)).not.toThrow();
  });
});

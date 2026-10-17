/**
 * B-Tier2: auditLocalAllow's riskMetadata cleaner must keep finite NUMBERS
 * (mcpToolCount / mcpResponseBytes) — previously it kept only non-empty
 * strings, which would have silently dropped the MCP-visibility counts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { auditLocalAllow } from '../auth/cloud';

describe('auditLocalAllow riskMetadata cleaning (numeric fields)', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('keeps finite numbers and drops empty strings', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    await auditLocalAllow(
      'mcp-server:github',
      { serverKey: 'github' },
      'mcp-discovered',
      { apiKey: 'n9_live_x', apiUrl: 'https://api.node9.ai' },
      { mcpServer: 'github' },
      undefined,
      false,
      { mcpToolCount: 12, ruleName: '' }
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse((fetchMock.mock.calls[0][1] as { body: string }).body);
    // number kept; empty-string ruleName dropped by the cleaner
    expect(body.riskMetadata).toEqual({ mcpToolCount: 12 });
    expect(body.checkedBy).toBe('mcp-discovered');
  });

  it('fw#318 2b: keeps exposureDestinations on the wire, drops other arrays', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);
    await auditLocalAllow(
      'mcp__gmail__send_email',
      { to: 'x@drop.example' },
      'local-policy',
      { apiKey: 'n9_live_x', apiUrl: 'https://api.node9.ai' },
      { mcpServer: 'gmail' },
      undefined,
      false,
      {
        ruleName: 'exposure',
        exposureDestinations: ['email:x@drop.example'],
        other: ['a'],
      } as never
    );
    const body = JSON.parse((fetchMock.mock.calls[0][1] as { body: string }).body);
    expect(body.riskMetadata).toEqual({
      ruleName: 'exposure',
      exposureDestinations: ['email:x@drop.example'],
    });
  });
});

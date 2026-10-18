/**
 * B-Tier2: auditLocalAllow's riskMetadata cleaner must keep finite NUMBERS
 * (mcpToolCount / mcpResponseBytes) — previously it kept only non-empty
 * strings, which would have silently dropped the MCP-visibility counts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { hashDestination } from '@node9/policy-engine';
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

  // fw#318 review F4/P1: the destinations travel masked with their hashes,
  // the arguments and the review sentence are masked too.
  it('fw#318: sends destinations masked with hashes, masks args, drops other arrays', async () => {
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
        ruleDescription: 'This call sends to x@drop.example and to host drop.example.',
        exposureDestinations: ['email:x@drop.example', 'host:drop.example'],
        other: ['a'],
      } as never
    );
    const body = JSON.parse((fetchMock.mock.calls[0][1] as { body: string }).body);
    expect(body.riskMetadata).toEqual({
      ruleName: 'exposure',
      ruleDescription: 'This call sends to x***@drop.example and to host drop.example.',
      exposureDestinations: ['email:x***@drop.example', 'host:drop.example'],
      exposureDestinationHashes: [hashDestination('email:x@drop.example'), ''],
    });
    expect(body.args).toEqual({ to: 'x***@drop.example' });
    expect(JSON.stringify(body)).not.toContain('x@drop.example');
  });
});

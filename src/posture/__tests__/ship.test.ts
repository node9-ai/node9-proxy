// Tests for the posture snapshot shipper: redaction (no values/paths leave the
// box) + URL derivation + a real round-trip against a local HTTP server.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';
import { buildShipBody, postureUrlFrom, shipPosture } from '../ship';
import type { PostureResult } from '../types';

const result: PostureResult = {
  agent: 'hermes on this host',
  score: 58,
  tier: 'at-risk',
  checksRun: 8,
  passedCategories: ['Supply chain'],
  headline: { risk: 'An agent here can read your credentials.', action: 'lock egress.' },
  findings: [
    {
      category: 'Secrets',
      severity: 'critical',
      title: '3 credential files readable by the agent',
      detail: ['~/.ssh/id_rsa', '~/.aws/credentials'], // must NOT be shipped
      fix: 'node9 can block reads of sensitive paths.', // must NOT be shipped
    },
  ],
};

describe('buildShipBody (redaction)', () => {
  it('ships score/tier/agent/headline + finding category/severity/title only', () => {
    const body = buildShipBody(result);
    expect(body.score).toBe(58);
    expect(body.tier).toBe('at-risk');
    expect(body.headline?.action).toBe('lock egress.');
    expect(body.findings).toEqual([
      {
        category: 'Secrets',
        severity: 'critical',
        title: '3 credential files readable by the agent',
      },
    ]);
  });

  it('drops finding detail[] and fix (paths/locations never leave the box)', () => {
    const serialized = JSON.stringify(buildShipBody(result));
    expect(serialized).not.toContain('id_rsa');
    expect(serialized).not.toContain('.aws/credentials');
    expect(serialized).not.toContain('block reads of sensitive paths');
  });
});

describe('postureUrlFrom', () => {
  it('derives /posture/report from the policies/sync base', () => {
    expect(postureUrlFrom('https://api.node9.ai/api/v1/intercept/policies/sync')).toBe(
      'https://api.node9.ai/api/v1/intercept/posture/report'
    );
  });

  it('returns null for a URL that is not a policies/sync base', () => {
    expect(postureUrlFrom('https://api.node9.ai/something/else')).toBeNull();
  });
});

describe('shipPosture', () => {
  let server: http.Server;
  let received: { auth?: string; body?: unknown } = {};
  let baseUrl = '';

  beforeEach(async () => {
    received = {};
    server = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        received.auth = req.headers.authorization;
        received.body = JSON.parse(raw);
        res.statusCode = 200;
        res.end(JSON.stringify({ ok: true }));
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}/api/v1/intercept/policies/sync`;
  });

  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
  });

  it('POSTs the redacted body with the Bearer key and resolves true on 2xx', async () => {
    const ok = await shipPosture(result, { apiKey: 'n9_live_test', apiUrl: baseUrl });
    expect(ok).toBe(true);
    expect(received.auth).toBe('Bearer n9_live_test');
    expect(received.body).toMatchObject({ score: 58, tier: 'at-risk' });
  });

  it('resolves false (never throws) when the URL is not a policies/sync base', async () => {
    const ok = await shipPosture(result, { apiKey: 'n9_live_test', apiUrl: 'https://x/y' });
    expect(ok).toBe(false);
  });
});

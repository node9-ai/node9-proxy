import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { auditLocalAllow } from '../auth/cloud.js';

interface CapturedRequest {
  url: string;
  body: Record<string, unknown>;
}

describe('auditLocalAllow — sensitive-args redaction', () => {
  let captured: CapturedRequest[];
  let originalFetch: typeof fetch;

  beforeEach(() => {
    captured = [];
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
      const body =
        init?.body && typeof init.body === 'string' ? (JSON.parse(init.body) as object) : {};
      captured.push({ url: u, body: body as Record<string, unknown> });
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const creds = { apiKey: 'k', apiUrl: 'http://127.0.0.1:0' };
  const secretArgs = { command: 'curl -H "Authorization: Bearer sk-live-SECRET123" example.com' };

  it('redacts args when containsSensitiveArgs=true regardless of checkedBy tag', async () => {
    // The security regression: previously the function used checkedBy.includes('dlp')
    // to decide whether to strip args. A caller-controlled string is not a sound
    // basis for a redaction decision — any tag without "dlp" leaked raw args.
    await auditLocalAllow('bash', secretArgs, 'loop-detected', creds, undefined, undefined, true);
    expect(captured).toHaveLength(1);
    expect(captured[0].body.args).toEqual({ tool: 'bash', redacted: true });
    expect(JSON.stringify(captured[0].body)).not.toContain('sk-live-SECRET123');
  });

  it('forwards raw args when containsSensitiveArgs is false (default)', async () => {
    const args = { command: 'ls -la' };
    await auditLocalAllow('bash', args, 'local-policy', creds);
    expect(captured[0].body.args).toEqual(args);
  });

  it('does NOT inspect checkedBy for the redaction decision (no substring magic)', async () => {
    // checkedBy contains "dlp" but the explicit boolean is false → args MUST be sent.
    // This pins the new contract: redaction is decided by the explicit parameter only.
    const args = { foo: 'bar' };
    await auditLocalAllow('bash', args, 'dlp-block', creds, undefined, undefined, false);
    expect(captured[0].body.args).toEqual(args);
  });

  it('redacts loop-detected payloads (regression: previously sent raw args)', async () => {
    // Direct regression test for the HIGH finding: the loop-detected branch
    // must not exfiltrate raw args to the audit endpoint.
    await auditLocalAllow('bash', secretArgs, 'loop-detected', creds, undefined, undefined, true);
    expect(captured[0].body.args).toEqual({ tool: 'bash', redacted: true });
  });

  it('caps dlpInfo.redactedSample length before transmission', async () => {
    // LOW finding: an upstream redaction bug could let an oversized partially-
    // redacted secret through. Cap defensively at the boundary.
    const longSample = 'x'.repeat(5000);
    await auditLocalAllow(
      'bash',
      secretArgs,
      'dlp-block',
      creds,
      undefined,
      { pattern: 'aws-key', redactedSample: longSample },
      true
    );
    const sent = captured[0].body.dlpSample as string;
    expect(typeof sent).toBe('string');
    expect(sent.length).toBeLessThanOrEqual(200);
  });
});

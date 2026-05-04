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

  it('caps dlpInfo.pattern length before transmission', async () => {
    // MEDIUM finding: pattern must also be bounded — an unbounded pattern
    // string can be persisted in audit logs or used to probe backend behavior.
    const longPattern = 'p'.repeat(5000);
    await auditLocalAllow(
      'bash',
      secretArgs,
      'dlp-block',
      creds,
      undefined,
      { pattern: longPattern, redactedSample: 'x' },
      true
    );
    const sent = captured[0].body.dlpPattern as string;
    expect(typeof sent).toBe('string');
    expect(sent.length).toBeLessThanOrEqual(100);
  });

  // ── A1: rule attribution propagated to /audit ────────────────────────
  // Without these, the SaaS Report severity classifier falls back to
  // "<toolName> block" for every smart-rule match — the engine's friendly
  // labels (engine.narrativeRuleLabel) never get a chance to fire.

  it('forwards riskMetadata.ruleName to the /audit body when provided', async () => {
    await auditLocalAllow(
      'bash',
      { command: 'rm -rf $HOME' },
      'smart-rule-block',
      creds,
      undefined,
      undefined,
      false,
      {
        ruleName: 'block-rm-rf-home',
        ruleDescription: 'rm -rf on $HOME is irreversible',
        blockedByLabel: '🛑 rm -rf home',
      }
    );
    const meta = captured[0].body.riskMetadata as Record<string, unknown> | undefined;
    expect(meta).toBeDefined();
    expect(meta!.ruleName).toBe('block-rm-rf-home');
    expect(meta!.ruleDescription).toContain('irreversible');
  });

  it('omits riskMetadata from the body when not provided (older call sites)', async () => {
    await auditLocalAllow('bash', { command: 'ls' }, 'local-policy', creds);
    expect(captured[0].body.riskMetadata).toBeUndefined();
  });

  it('drops empty-string riskMetadata fields rather than sending them', async () => {
    // Defensive: callers may build the metadata object from a policy result
    // that has empty fields. Empty strings would pass Zod's optional string
    // check on the backend but carry no signal — drop them at the boundary.
    await auditLocalAllow(
      'bash',
      { command: 'ls' },
      'local-policy',
      creds,
      undefined,
      undefined,
      false,
      { ruleName: 'block-read-aws', matchedField: '', matchedWord: '' }
    );
    const meta = captured[0].body.riskMetadata as Record<string, unknown>;
    expect(meta.ruleName).toBe('block-read-aws');
    expect(meta.matchedField).toBeUndefined();
    expect(meta.matchedWord).toBeUndefined();
  });

  it('omits riskMetadata entirely when every field is empty/undefined', async () => {
    await auditLocalAllow(
      'bash',
      { command: 'ls' },
      'local-policy',
      creds,
      undefined,
      undefined,
      false,
      { ruleName: '', ruleDescription: undefined }
    );
    expect(captured[0].body.riskMetadata).toBeUndefined();
  });
});

describe('auditLocalAllow — apiUrl validation (SSRF / key-leak guard)', () => {
  let captured: CapturedRequest[];
  let originalFetch: typeof fetch;

  beforeEach(() => {
    captured = [];
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
      const body = init?.body
        ? (JSON.parse(init.body as string) as Record<string, unknown>)
        : ({} as Record<string, unknown>);
      captured.push({ url: u, body });
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const args = { command: 'ls' };

  it('refuses to send the bearer token to non-HTTPS public hosts', async () => {
    // HIGH finding: a malicious apiUrl (e.g. supply-chain compromise) must not
    // receive Authorization: Bearer <token>.
    await auditLocalAllow('bash', args, 'local-policy', {
      apiKey: 'sk-secret-token',
      apiUrl: 'http://attacker.example.com',
    });
    expect(captured).toHaveLength(0);
  });

  it('refuses URLs containing userinfo (https://attacker@real.host)', async () => {
    await auditLocalAllow('bash', args, 'local-policy', {
      apiKey: 'sk-secret-token',
      apiUrl: 'https://attacker.example.com@api.node9.ai',
    });
    expect(captured).toHaveLength(0);
  });

  it('refuses malformed URLs', async () => {
    await auditLocalAllow('bash', args, 'local-policy', {
      apiKey: 'k',
      apiUrl: 'not a url',
    });
    expect(captured).toHaveLength(0);
  });

  it('refuses non-http(s) schemes (file://, data://, javascript:)', async () => {
    for (const apiUrl of ['file:///etc/passwd', 'data://text', 'ftp://x.example.com']) {
      await auditLocalAllow('bash', args, 'local-policy', { apiKey: 'k', apiUrl });
    }
    expect(captured).toHaveLength(0);
  });

  it('allows HTTPS public hosts', async () => {
    await auditLocalAllow('bash', args, 'local-policy', {
      apiKey: 'k',
      apiUrl: 'https://api.node9.ai/v1',
    });
    expect(captured).toHaveLength(1);
    expect(captured[0].url).toBe('https://api.node9.ai/v1/audit');
  });

  it('allows http on loopback (test/dev fixtures)', async () => {
    await auditLocalAllow('bash', args, 'local-policy', {
      apiKey: 'k',
      apiUrl: 'http://127.0.0.1:8080',
    });
    expect(captured).toHaveLength(1);
    expect(captured[0].url).toBe('http://127.0.0.1:8080/audit');
  });
});

describe('auditLocalAllow — checkedBy allowlist', () => {
  let captured: CapturedRequest[];
  let originalFetch: typeof fetch;

  beforeEach(() => {
    captured = [];
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
      const body = init?.body
        ? (JSON.parse(init.body as string) as Record<string, unknown>)
        : ({} as Record<string, unknown>);
      captured.push({ url: u, body });
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const creds = { apiKey: 'k', apiUrl: 'http://127.0.0.1:0' };

  it('passes through known checkedBy values verbatim', async () => {
    for (const v of ['dlp-block', 'loop-detected', 'local-policy', 'persistent', 'trust']) {
      captured.length = 0;
      await auditLocalAllow('bash', {}, v, creds);
      expect(captured[0].body.checkedBy).toBe(v);
    }
  });

  it('normalizes unknown checkedBy values to "unknown" (log-injection guard)', async () => {
    // LOW finding: free-form strings could be used for log injection or to
    // confuse downstream JSON parsers. Anything not on the allowlist is
    // replaced before transmission.
    await auditLocalAllow('bash', {}, '{"injected":"json","newline":"\\n[admin]"}', creds);
    expect(captured[0].body.checkedBy).toBe('unknown');
  });
});

// ── runId + transcriptPath propagation ─────────────────────────────────
// Closes the gap where the proxy knew the agent's session_id (Claude
// Code + Gemini CLI both populate it in the hook payload) but never
// forwarded it. Without this the dashboard Sessions tab can't correlate
// audit rows back to the on-disk transcript.
describe('auditLocalAllow — session correlation fields', () => {
  let captured: CapturedRequest[];
  let originalFetch: typeof fetch;

  beforeEach(() => {
    captured = [];
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
      const body = init?.body
        ? (JSON.parse(init.body as string) as Record<string, unknown>)
        : ({} as Record<string, unknown>);
      captured.push({ url: u, body });
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const creds = { apiKey: 'k', apiUrl: 'http://127.0.0.1:0' };

  it('forwards meta.sessionId as body.runId when present', async () => {
    await auditLocalAllow('bash', {}, 'local-policy', creds, {
      agent: 'Claude Code',
      sessionId: 'ea385d8a-0c49-4ebe-8b66-c649672cc19e',
    });
    expect(captured[0].body.runId).toBe('ea385d8a-0c49-4ebe-8b66-c649672cc19e');
  });

  it('forwards meta.transcriptPath verbatim when present', async () => {
    const transcriptPath = '/home/nadav/.claude/projects/-home-nadav-node9/ea385d8a.jsonl';
    await auditLocalAllow('bash', {}, 'local-policy', creds, {
      agent: 'Claude Code',
      sessionId: 'ea385d8a',
      transcriptPath,
    });
    expect(captured[0].body.transcriptPath).toBe(transcriptPath);
  });

  it('omits both fields when meta is undefined (older call sites)', async () => {
    await auditLocalAllow('bash', {}, 'local-policy', creds);
    expect(captured[0].body.runId).toBeUndefined();
    expect(captured[0].body.transcriptPath).toBeUndefined();
  });

  it('omits both fields when meta has agent but no session info (MCP case)', async () => {
    // Cursor / Codex / VSCode go through MCP and don't carry a session_id —
    // the body must not contain phantom keys for these flows.
    await auditLocalAllow('bash', {}, 'local-policy', creds, {
      agent: 'Cursor',
      mcpServer: 'node9',
    });
    expect(captured[0].body.runId).toBeUndefined();
    expect(captured[0].body.transcriptPath).toBeUndefined();
  });

  it('treats empty-string sessionId as absent (does not send runId="")', async () => {
    await auditLocalAllow('bash', {}, 'local-policy', creds, {
      agent: 'Claude Code',
      sessionId: '',
      transcriptPath: '',
    });
    expect(captured[0].body.runId).toBeUndefined();
    expect(captured[0].body.transcriptPath).toBeUndefined();
  });

  it('forwards Gemini-style session info (UUID + ~/.gemini/tmp transcript)', async () => {
    // The Gemini case is exactly why transcriptPath matters: session_id is
    // useful as a group key, but the on-disk file lives at a path that
    // session_id alone cannot reconstruct.
    await auditLocalAllow('list_directory', {}, 'local-policy', creds, {
      agent: 'Gemini CLI',
      sessionId: '3745cf2a-c7e2-440a-bd57-4f3568b366f0',
      transcriptPath: '/home/nadav/.gemini/tmp/node9/chats/session-2026-04-17T11-00-3745cf2a.json',
    });
    expect(captured[0].body.runId).toBe('3745cf2a-c7e2-440a-bd57-4f3568b366f0');
    expect(captured[0].body.transcriptPath).toContain('/.gemini/tmp/');
  });
});

// ── initNode9SaaS body parity ──────────────────────────────────────────
// initNode9SaaS is the /intercept POST. It must forward the same
// runId/transcriptPath fields so audit rows created by the live firewall
// (not just /audit fast-path rows) carry session correlation too.
describe('initNode9SaaS — session correlation fields', () => {
  let captured: CapturedRequest[];
  let originalFetch: typeof fetch;

  beforeEach(() => {
    captured = [];
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
      const body = init?.body
        ? (JSON.parse(init.body as string) as Record<string, unknown>)
        : ({} as Record<string, unknown>);
      captured.push({ url: u, body });
      return new Response(JSON.stringify({ pending: false, approved: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const creds = { apiKey: 'k', apiUrl: 'http://127.0.0.1:8080/intercept' };

  it('forwards meta.sessionId + meta.transcriptPath in the /intercept body', async () => {
    const { initNode9SaaS } = await import('../auth/cloud.js');
    await initNode9SaaS('bash', { command: 'ls' }, creds, {
      agent: 'Claude Code',
      sessionId: 'sid-123',
      transcriptPath: '/home/u/.claude/projects/x/sid-123.jsonl',
    });
    expect(captured).toHaveLength(1);
    expect(captured[0].body.runId).toBe('sid-123');
    expect(captured[0].body.transcriptPath).toBe('/home/u/.claude/projects/x/sid-123.jsonl');
  });

  it('omits both fields when meta lacks session info', async () => {
    const { initNode9SaaS } = await import('../auth/cloud.js');
    await initNode9SaaS('bash', { command: 'ls' }, creds, { agent: 'Claude Code' });
    expect(captured[0].body.runId).toBeUndefined();
    expect(captured[0].body.transcriptPath).toBeUndefined();
  });
});

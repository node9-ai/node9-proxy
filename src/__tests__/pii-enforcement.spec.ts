// src/__tests__/pii-enforcement.spec.ts
//
// GAP-7: wire the existing PII detector into the realtime authorize path.
// PII enforcement is a reliable on/off block (no fragile "review" routing):
//   dlp.pii: 'block'  → SSN / Credit Card in tool args is denied in realtime
//   dlp.pii: 'off'    → detector does not gate (default — opt-in for compliance)
//
// Scoped to high-signal PII (SSN, Credit Card). Email/Phone are excluded from
// realtime gating (too noisy) — see detectArgsPii.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { authorizeHeadless, _resetConfigCache } from '../core.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));
vi.mock('../ui/native', () => ({
  askNativePopup: vi.fn().mockResolvedValue('deny'),
  sendDesktopNotification: vi.fn(),
}));

const existsSpy = vi.spyOn(fs, 'existsSync');
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'appendFileSync').mockImplementation(() => undefined);
const homeSpy = vi.spyOn(os, 'homedir');

function mockConfig(policy: Record<string, unknown>) {
  const globalPath = path.join('/mock/home', '.node9', 'config.json');
  existsSpy.mockImplementation((p) => String(p) === globalPath);
  readSpy.mockImplementation((p) =>
    String(p) === globalPath
      ? JSON.stringify({
          settings: { mode: 'standard', approvalTimeoutMs: 0, approvers: { native: false } },
          policy,
        })
      : ''
  );
}

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  homeSpy.mockReturnValue('/mock/home');
  delete process.env.NODE9_API_KEY;
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

const SSN = '123-45-6789';

describe('GAP-7 — realtime PII enforcement', () => {
  it('blocks an SSN in tool args when dlp.pii = "block"', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: `echo ${SSN}` });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/PII/);
  });

  it('allows the same SSN when dlp.pii = "off"', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'off' } });
    const r = await authorizeHeadless('Bash', { command: `echo ${SSN}` });
    expect(r.approved).toBe(true);
  });

  it('is OFF by default (no pii key) — SSN allowed', async () => {
    mockConfig({ dlp: { enabled: true } });
    const r = await authorizeHeadless('Bash', { command: `echo ${SSN}` });
    expect(r.approved).toBe(true);
  });

  it('does not block a plain email even when pii = "block" (high-signal only)', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: 'git log --author=alice@example.com' });
    expect(r.approved).toBe(true);
  });

  it('blocks PII even when dlp.enabled = false (PII gate is independent)', async () => {
    // Fix 2: disabling secret-DLP must NOT silently disable PII blocking.
    mockConfig({ dlp: { enabled: false, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: `echo ${SSN}` });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/PII/);
  });
});

// ── Credit cards at the real gate ────────────────────────────────────────────
// Split parts, not literals: see packages/policy-engine/src/scan/pii.fixtures.ts
// for the convention. Duplicated here because that module is deliberately not
// exported from the engine package. Every row asserts blockedByLabel so a deny
// for some OTHER reason (the secret-DLP gate runs first) cannot pass as a PII
// block.
const VISA = ['4111', '1111', '1111', '1111'];
const VISA_BAD = ['4111', '1111', '1111', '1112'];
const AMEX = ['3782', '822463', '10005'];
const j = (parts: string[], sep = '') => parts.join(sep);

describe('GAP-7 — credit cards at the real gate', () => {
  it('blocks a Luhn-valid Visa', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: 'echo ' + j(VISA, ' ') });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/PII/);
  });

  it('allows the same shape with the check digit changed (Luhn rejects it)', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: 'echo ' + j(VISA_BAD, ' ') });
    expect(r.approved).toBe(true);
  });

  it('blocks a 15-digit Amex (was a complete false negative)', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: 'echo ' + j(AMEX, ' ') });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/PII/);
  });

  it('blocks a valid card preceded by a decoy 4xxx token (overlapping search)', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: ['4000', ' ', j(VISA, ' ')].join('') });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/PII/);
  });

  it('blocks a card that begins a line in a multi-line Write (A5)', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const content = ['name,card', '\n', 'alice,', j(VISA), '\n'].join('');
    const r = await authorizeHeadless('Write', { file_path: '/tmp/x.csv', content });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/PII/);
  });

  it('observe mode: approved but observeWouldBlock, so a bare approved===false is not the witness', async () => {
    const globalPath = path.join('/mock/home', '.node9', 'config.json');
    existsSpy.mockImplementation((p) => String(p) === globalPath);
    readSpy.mockImplementation((p) =>
      String(p) === globalPath
        ? JSON.stringify({
            settings: { mode: 'observe', approvalTimeoutMs: 0, approvers: { native: false } },
            policy: { dlp: { enabled: true, pii: 'block' } },
          })
        : ''
    );
    const r = await authorizeHeadless('Bash', { command: 'echo ' + j(VISA, ' ') });
    expect(r.approved).toBe(true);
    expect(r.observeWouldBlock).toBe(true);
    expect(r.blockedByLabel).toMatch(/PII/);
  });
});

// ── DLP-2 at the real gate ──────────────────────────────────────────────────
// The unit rows in audit-pii-row.unit.test.ts prove the guard; this proves the
// seam that actually leaked: authorizeHeadless -> PII gate -> appendLocalAudit.
// It reads mock.calls off the module-level appendFileSync spy rather than
// re-spying, so the capture is exactly what the gate wrote and nothing leaks
// into later tests.
describe('DLP-2 — the PII block row written at the real gate carries no PII', () => {
  it('argsPreview absent, argsHash present, raw SSN absent from the audit line', async () => {
    mockConfig({ dlp: { enabled: true, pii: 'block' } });
    const r = await authorizeHeadless('Bash', { command: `echo ${SSN}` });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/PII/);

    const calls = (fs.appendFileSync as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(calls.length, 'the gate must have written at least one line').toBeGreaterThan(0);
    const rows = calls
      .map((c) => {
        try {
          return JSON.parse(String(c[1])) as Record<string, unknown>;
        } catch {
          return null;
        }
      })
      .filter((x): x is Record<string, unknown> => x !== null);
    const piiRow = rows.find((x) => String(x.checkedBy ?? '').includes('pii'));
    expect(piiRow, 'a pii-block row must exist').toBeDefined();
    expect(piiRow!.argsPreview).toBeUndefined();
    expect(typeof piiRow!.argsHash).toBe('string');
    expect(JSON.stringify(piiRow)).not.toContain(SSN);
  });
});

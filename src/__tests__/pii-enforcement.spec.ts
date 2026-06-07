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

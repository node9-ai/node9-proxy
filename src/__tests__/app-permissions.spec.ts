// src/__tests__/app-permissions.spec.ts
// P3 Phase 2 (GOVERN) — managed MCP per-tool permissions applied to config +
// enforced in the authorize path. Keyed by (serverKey, bareTool). A tightening
// gate: block/review deny; allow/unset fall through to normal policy.
// Mirrors trust-managed.spec.ts (managedConfig via rules-cache.json).
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';

describe('managed appPermissions apply + enforce (P3 Phase 2)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-appperm-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    // standard mode, every approver surface off so a fall-through can't prompt.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 0,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
        policy: {},
      })
    );
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: [],
        managedConfig: {
          appPermissions: {
            srv1: { read_file: 'allow', write_file: 'block', edit_file: 'review' },
          },
          locked: [],
        },
      })
    );
    _resetConfigCache();
    _resetCore();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  const call = (tool: string) =>
    authorizeHeadless(
      `mcp__fs__${tool}`,
      { path: '/x' },
      { agent: 'MCP-Gateway', mcpServer: 'fs', serverKey: 'srv1' }
    );

  it('applies the managed map to config.policy.appPermissions (coerced)', () => {
    expect(getConfig().policy.appPermissions).toEqual({
      srv1: { read_file: 'allow', write_file: 'block', edit_file: 'review' },
    });
  });

  it('BLOCKS a tool set to block', async () => {
    const r = await call('write_file');
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toContain('App Permission');
  });

  it('DENIES a tool set to review (human must approve)', async () => {
    const r = await call('edit_file');
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toContain('Review');
  });

  it('does NOT app-permission-block a tool set to allow (falls through)', async () => {
    const r = await call('read_file');
    // 'allow' is not a bypass, but it is NOT the app-permission denial.
    expect(r.blockedByLabel ?? '').not.toContain('App Permission');
  });

  it('does NOT app-permission-block an unset tool (falls through)', async () => {
    const r = await call('list_directory');
    expect(r.blockedByLabel ?? '').not.toContain('App Permission');
  });

  it('ignores app permissions for a different serverKey', async () => {
    const r = await authorizeHeadless(
      'mcp__fs__write_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', mcpServer: 'fs', serverKey: 'OTHER' }
    );
    expect(r.blockedByLabel ?? '').not.toContain('App Permission');
  });
});

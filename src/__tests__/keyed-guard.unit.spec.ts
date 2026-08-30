// src/__tests__/keyed-guard.unit.spec.ts
// PR-2 §G — unit rows on the write-guard seam itself (src/config/keyed-guard.ts).
//
// THE LAW UNDER TEST: `isKeyedForPolicy()` delegates to the ONE introspection
// truth (`getConfig().policySource === 'workspace'`) — it never re-derives
// keyedness from credentials. `cliGuardPolicyWrite(action)` is the shared CLI
// seam: keyed → print the refusal, set a NON-ZERO exit code, return false;
// unkeyed → return true, print nothing, leave the exit code alone.
//
// MUTATION PREP (which row kills which mutant):
//   - inverting isKeyedForPolicy                 → 'true when keyed' + 'false unkeyed'
//   - guard re-derives keyedness from creds
//     (ignoring localOnly / named profiles)      → localOnly + named-profile rows
//   - guard checks rules-cache presence instead
//     of policySource                            → 'keyed with NO rules-cache still guards'
//   - "guard prints but exits 0" (the DECISIONS
//     dead-DO rule)                              → exitCode assertions
//   - refusal message loses the dashboard pointer→ message-content assertions

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { _resetConfigCache } from '../config';
import {
  isKeyedForPolicy,
  cliGuardPolicyWrite,
  keyedPolicyWriteMessage,
  KEYED_POLICY_WRITE_REASON,
} from '../config/keyed-guard';

describe('§G unit — keyed-guard seam', () => {
  let home: string;
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = ['NODE9_API_KEY', 'NODE9_API_URL', 'NODE9_PROFILE', 'NODE9_MODE'];
  let savedExitCode: typeof process.exitCode;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-guard-'));
    savedEnv.HOME = process.env.HOME;
    savedEnv.USERPROFILE = process.env.USERPROFILE;
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    for (const k of ENV_KEYS) delete process.env[k];
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    // The guard sets process.exitCode — save it so a passing refusal row can
    // never leak exit 1 into the vitest process itself.
    savedExitCode = process.exitCode;
    _resetConfigCache();
  });

  afterEach(() => {
    process.exitCode = savedExitCode;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v !== undefined) process.env[k] = v;
      else delete process.env[k];
    }
    fs.rmSync(home, { recursive: true, force: true });
    _resetConfigCache();
  });

  const keyed = () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({ default: { apiKey: 'n9_test_matrix' } })
    );
    _resetConfigCache();
  };

  describe('isKeyedForPolicy — delegates to policySource, never re-derived', () => {
    it('false on a plain unkeyed machine (policySource local)', () => {
      expect(isKeyedForPolicy()).toBe(false);
    });

    it('true with a default-profile credentials.json (policySource workspace)', () => {
      keyed();
      expect(isKeyedForPolicy()).toBe(true);
    });

    it('true with NO rules-cache present — keyedness = credentials, not cache (mutant: keyed=cache-exists)', () => {
      keyed();
      expect(fs.existsSync(path.join(home, '.node9', 'rules-cache.json'))).toBe(false);
      expect(isKeyedForPolicy()).toBe(true);
    });

    it('false for a localOnly key (`node9 login --local` — the printed promise, §0.1)', () => {
      fs.writeFileSync(
        path.join(home, '.node9', 'credentials.json'),
        JSON.stringify({ default: { apiKey: 'n9_local', localOnly: true } })
      );
      _resetConfigCache();
      expect(isKeyedForPolicy()).toBe(false);
    });

    it('false for a NAMED profile key (§0.11 — profiles never policy-sync)', () => {
      fs.writeFileSync(
        path.join(home, '.node9', 'credentials.json'),
        JSON.stringify({ work: { apiKey: 'n9_work' } })
      );
      process.env.NODE9_PROFILE = 'work';
      _resetConfigCache();
      expect(isKeyedForPolicy()).toBe(false);
    });

    it('true for an env key (CI service keys have no localOnly channel)', () => {
      process.env.NODE9_API_KEY = 'n9_ci_key';
      _resetConfigCache();
      expect(isKeyedForPolicy()).toBe(true);
    });
  });

  describe('cliGuardPolicyWrite — refusal contract', () => {
    it('unkeyed: returns true, prints NOTHING, leaves the exit code untouched', () => {
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const before = process.exitCode;
      expect(cliGuardPolicyWrite('egress lock')).toBe(true);
      expect(errSpy).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(before);
      errSpy.mockRestore();
    });

    it('keyed: returns false, sets exitCode=1, and the message names the workspace + dashboard', () => {
      keyed();
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      expect(cliGuardPolicyWrite('shield enable postgres')).toBe(false);
      // "guard prints but exits 0" mutant — a script that believes it hardened
      // a keyed machine must fail loudly.
      expect(process.exitCode).toBe(1);
      const printed = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(printed).toContain('workspace configuration');
      expect(printed).toContain('app.node9.ai');
      expect(printed).toContain('shield enable postgres');
      errSpy.mockRestore();
    });

    it('keyed with NO rules-cache: still refuses (mutant: guard keyed on cache presence)', () => {
      keyed();
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      expect(cliGuardPolicyWrite('trust add x.com')).toBe(false);
      expect(process.exitCode).toBe(1);
      errSpy.mockRestore();
    });

    it('localOnly key: the guard lets the write proceed (unkeyed-for-policy)', () => {
      fs.writeFileSync(
        path.join(home, '.node9', 'credentials.json'),
        JSON.stringify({ default: { apiKey: 'n9_local', localOnly: true } })
      );
      _resetConfigCache();
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      expect(cliGuardPolicyWrite('egress lock')).toBe(true);
      expect(errSpy).not.toHaveBeenCalled();
      errSpy.mockRestore();
    });
  });

  describe('keyedPolicyWriteMessage — one message, shared by CLI and MCP', () => {
    it('carries the shared reason, the action, and both paved paths back (logout / login --local)', () => {
      const msg = keyedPolicyWriteMessage('jail add /tmp/x');
      expect(msg).toContain(KEYED_POLICY_WRITE_REASON);
      expect(msg).toContain('jail add /tmp/x');
      expect(msg).toContain('app.node9.ai');
      expect(msg).toContain('node9 logout');
      expect(msg).toContain('node9 login --local');
    });

    it('the shared reason names the workspace configuration (the gauntlet asserts on this string)', () => {
      expect(KEYED_POLICY_WRITE_REASON).toContain('workspace configuration');
    });
  });
});

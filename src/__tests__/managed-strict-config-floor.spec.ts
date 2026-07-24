// src/__tests__/managed-strict-config-floor.spec.ts
//
// Task #16 — a CLOUD-managed strict mode must not be silently disabled by
// local/repo config. Two confirmed bypass vectors, both closed here:
//
//   A. environments.requireApproval:false — the engine's strict escape
//      (policy/index.ts: `if (activeEnvironment?.requireApproval === false)
//      return { decision: 'allow' }`). A cloned repo's node9.config.json can
//      define it and neutralise managed strict for that project.
//   B. local ignoredTools — the engine's ignored-tool fast-path allows a tool
//      BEFORE policy eval. A repo can add `ignoredTools:['Bash']` to skip strict.
//
// The fix applies the existing config-home law (org floor wins; local may only
// tighten) to both escapes, gated on the mode being cloud-managed. A LOCALLY
// chosen strict keeps its dev-convenience escapes — verified below so the fix
// doesn't over-tighten.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, getActiveEnvironment, _resetConfigCache } from '../config';
import { evaluatePolicy } from '../policy';

function writeHome(tmpHome: string, opts: { local: object; cache?: object }): void {
  fs.writeFileSync(path.join(tmpHome, '.node9', 'config.json'), JSON.stringify(opts.local));
  if (opts.cache)
    fs.writeFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), JSON.stringify(opts.cache));
}

describe('managed strict floor is not weakened by local/repo config (task #16)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;
  let origNodeEnv: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-floor-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    origNodeEnv = process.env.NODE_ENV;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    // getActiveEnvironment falls back to NODE_ENV; pin it out so the config's
    // own settings.environment decides which env is active.
    delete process.env.NODE_ENV;
    delete process.env.NODE9_MODE;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    _resetConfigCache();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
  });

  const STRICT_CACHE = { managedConfig: { mode: 'strict' }, shields: [], rules: [] };

  it('vector A: managed strict strips environments.requireApproval:false (the engine escape)', () => {
    writeHome(tmpHome, {
      local: {
        settings: { environment: 'development' },
        environments: { development: { requireApproval: false } },
      },
      cache: STRICT_CACHE,
    });
    const cfg = getConfig();
    expect(cfg.settings.mode).toBe('strict'); // sanity: managed strict applied
    // The escape must be gone → the engine can never be handed requireApproval:false.
    expect(getActiveEnvironment(cfg)?.requireApproval).not.toBe(false);
  });

  it('vector B: managed strict resets local ignoredTools so a repo cannot fast-path past strict', () => {
    writeHome(tmpHome, {
      local: { policy: { ignoredTools: ['Bash'] } },
      cache: STRICT_CACHE,
    });
    const cfg = getConfig();
    expect(cfg.settings.mode).toBe('strict');
    expect(cfg.policy.ignoredTools).not.toContain('Bash');
  });

  it('does NOT over-tighten: a LOCALLY-chosen strict keeps the requireApproval:false escape', () => {
    writeHome(tmpHome, {
      // No managed cache → mode is local, dev convenience preserved.
      local: {
        settings: { mode: 'strict', environment: 'development' },
        environments: { development: { requireApproval: false } },
      },
    });
    const cfg = getConfig();
    expect(cfg.settings.mode).toBe('strict');
    expect(getActiveEnvironment(cfg)?.requireApproval).toBe(false);
  });

  it('does NOT over-tighten: a LOCALLY-chosen strict keeps local ignoredTools', () => {
    writeHome(tmpHome, {
      local: { settings: { mode: 'strict' }, policy: { ignoredTools: ['Bash'] } },
    });
    const cfg = getConfig();
    expect(cfg.policy.ignoredTools).toContain('Bash');
  });

  // End-to-end at the REAL gate: the proxy's evaluatePolicy wrapper builds the
  // engine context from getConfig()+getActiveEnvironment, so these prove the
  // bypass is closed where verdicts are actually produced, not just in config.
  it('E2E: managed strict + repo requireApproval:false → an unmatched tool still REVIEWS', async () => {
    writeHome(tmpHome, {
      local: {
        settings: { environment: 'development' },
        environments: { development: { requireApproval: false } },
      },
      cache: STRICT_CACHE,
    });
    _resetConfigCache();
    const v = await evaluatePolicy('TotallyUnknownTool', { note: 'x' });
    expect(v.decision).toBe('review'); // was 'allow' via the stripped escape
  });

  it('E2E: managed strict + repo ignoredTools:[Bash] → Bash is NOT fast-path allowed', async () => {
    writeHome(tmpHome, {
      local: { policy: { ignoredTools: ['Bash'] } },
      cache: STRICT_CACHE,
    });
    _resetConfigCache();
    const v = await evaluatePolicy('Bash', { command: 'echo hi' });
    expect(v.decision).not.toBe('allow'); // strict review, not the fast-path allow
  });
});

// src/__tests__/keyed-explain-waterfall.spec.ts
// PR-2 §I row I4 — the explain waterfall tells the replace-mode truth.
//
// THE LAW UNDER TEST (matrix §0.13): on a workspace-governed machine the tier
// list must invert its story — tier 2 is relabeled 'Workspace config' and
// marked authoritative; the local tiers (3 project / 4 global) say "present —
// ignored"; tier 1 says the env-var mode override is ignored. Unkeyed keeps
// today's labels byte-for-byte ('Cloud policy', no ignored notes) — explain
// stays not-ground-truth, so these rows assert LABELS only, never verdicts.
//
// In-process unit rows at the explainPolicy() seam (same harness as
// keyed-replace.spec.ts: temp HOME, file-keyed fixture, mocked shields store —
// the shields.json path is a module-load const frozen to the real home).
//
// MUTATION PREP:
//   - dropping the wsGoverned branch in deriveExplainTrace → every keyed row
//   - inverting it (labeling unkeyed machines workspace)   → every unkeyed row
//   - keyed notes added only when files are MISSING        → 'no ignored notes
//     when the local files do not exist'
//   - tier-2 label keyed off credentials presence instead
//     of policySource                                      → localOnly row

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const shieldState = vi.hoisted(() => ({
  active: [] as string[],
}));

vi.mock('../shields', async () => {
  const actual = await vi.importActual<typeof import('../shields')>('../shields');
  return {
    ...actual,
    readActiveShields: () => shieldState.active,
    readShieldOverrides: () => ({}),
  };
});

import { _resetConfigCache } from '../config';
import { explainPolicy, type WaterfallTier } from '../policy';

describe('I4 — explain waterfall labels under replace-mode', () => {
  let home: string;
  let proj: string;
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = ['NODE9_API_KEY', 'NODE9_API_URL', 'NODE9_PROFILE', 'NODE9_MODE'];
  let cwdSpy: ReturnType<typeof vi.spyOn> | undefined;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-explain-'));
    proj = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-explain-proj-'));
    savedEnv.HOME = process.env.HOME;
    savedEnv.USERPROFILE = process.env.USERPROFILE;
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    for (const k of ENV_KEYS) delete process.env[k];
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    // deriveExplainTrace resolves the project tier from process.cwd() — pin it
    // to the temp project dir so the repo's own node9.config.json never leaks in.
    cwdSpy = vi.spyOn(process, 'cwd').mockReturnValue(proj) as ReturnType<typeof vi.spyOn>;
    shieldState.active = [];
    _resetConfigCache();
  });

  afterEach(() => {
    cwdSpy?.mockRestore();
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v !== undefined) process.env[k] = v;
      else delete process.env[k];
    }
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(proj, { recursive: true, force: true });
    _resetConfigCache();
  });

  const keyed = () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({ default: { apiKey: 'n9_test_matrix' } })
    );
  };
  const writeGlobal = () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ version: '1.0', settings: {} })
    );
  };
  const writeRepo = () => {
    fs.writeFileSync(
      path.join(proj, 'node9.config.json'),
      JSON.stringify({ version: '1.0', settings: {} })
    );
  };

  const tiers = async (): Promise<Record<number, WaterfallTier>> => {
    _resetConfigCache();
    const r = await explainPolicy('bash', { command: 'ls -la' });
    const byTier: Record<number, WaterfallTier> = {};
    for (const t of r.waterfall) byTier[t.tier] = t;
    return byTier;
  };

  describe('keyed', () => {
    it("tier 2 is relabeled 'Workspace config' and marked authoritative", async () => {
      keyed();
      const t = await tiers();
      expect(t[2].label).toBe('Workspace config');
      expect(t[2].status).toBe('active');
      expect(t[2].note).toContain('authoritative');
      expect(t[2].note).toContain('app.node9.ai');
    });

    it("tiers 3 and 4 say 'present — ignored' when the files exist", async () => {
      keyed();
      writeGlobal();
      writeRepo();
      const t = await tiers();
      expect(t[3].note).toContain('ignored');
      expect(t[4].note).toContain('ignored');
    });

    it('no ignored notes when the local files do not exist (nothing to disclaim)', async () => {
      keyed();
      const t = await tiers();
      expect(t[3].status).toBe('missing');
      expect(t[4].status).toBe('missing');
      expect(t[3].note ?? '').not.toContain('ignored');
      expect(t[4].note ?? '').not.toContain('ignored');
    });

    it("tier 1 marks NODE9_MODE 'ignored (workspace config controls mode)'", async () => {
      keyed();
      process.env.NODE9_MODE = 'observe';
      const t = await tiers();
      expect(t[1].note).toContain('NODE9_MODE=observe');
      expect(t[1].note).toContain('ignored');
      expect(t[1].note).toContain('workspace config controls mode');
    });
  });

  describe('unkeyed — labels unchanged byte-for-byte', () => {
    it("tier 2 stays 'Cloud policy' (missing) and no tier carries an ignored note", async () => {
      writeGlobal();
      writeRepo();
      const t = await tiers();
      expect(t[2].label).toBe('Cloud policy');
      for (const n of [1, 2, 3, 4, 5]) {
        expect(t[n].note ?? '').not.toContain('ignored');
      }
    });

    it('NODE9_MODE renders plain (no ignored suffix) unkeyed', async () => {
      process.env.NODE9_MODE = 'observe';
      const t = await tiers();
      expect(t[1].note).toBe('NODE9_MODE=observe');
    });

    it("a localOnly key renders the UNKEYED story: 'Cloud policy' active, credentials note, no ignored notes", async () => {
      // Mutant kill: labeling keyed off credentials-file presence instead of
      // policySource would flip this machine to the workspace story while its
      // policy is fully local (`node9 login --local`'s printed promise).
      fs.writeFileSync(
        path.join(home, '.node9', 'credentials.json'),
        JSON.stringify({ default: { apiKey: 'n9_local', localOnly: true } })
      );
      writeGlobal();
      const t = await tiers();
      expect(t[2].label).toBe('Cloud policy');
      expect(t[2].status).toBe('active');
      expect(t[2].note).toContain('credentials found');
      expect(t[4].note ?? '').not.toContain('ignored');
    });
  });
});

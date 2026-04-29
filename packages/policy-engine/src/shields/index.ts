// Builtin shield registry + pure validators.
//
// The 11 JSON files in builtin/ are the canonical source. We import them
// statically so the engine ships them as code: no fs.readdir at runtime,
// works the same in CJS/ESM bundles, and the host repo doesn't need to
// know where the JSONs live on disk.

import safeRegex from 'safe-regex2';
import type { SmartRule } from '../types';

import aws from './builtin/aws.json';
import bashSafe from './builtin/bash-safe.json';
import docker from './builtin/docker.json';
import filesystem from './builtin/filesystem.json';
import github from './builtin/github.json';
import k8s from './builtin/k8s.json';
import mcpToolGating from './builtin/mcp-tool-gating.json';
import mongodb from './builtin/mongodb.json';
import postgres from './builtin/postgres.json';
import projectJail from './builtin/project-jail.json';
import redis from './builtin/redis.json';

export interface ShieldDefinition {
  name: string;
  description: string;
  aliases: string[];
  smartRules: SmartRule[];
  dangerousWords: string[];
}

export type ShieldVerdict = 'allow' | 'review' | 'block';
// overrides: { shieldName: { fullRuleName: verdict } }
export type ShieldOverrides = Record<string, Record<string, ShieldVerdict>>;

export function isShieldVerdict(v: unknown): v is ShieldVerdict {
  return v === 'allow' || v === 'review' || v === 'block';
}

/**
 * Validates a shield definition shape. Returns the shield on success or an
 * error string describing the missing/wrong field. Pure: no logging, the
 * caller decides how to surface validation failures.
 */
export function validateShieldDefinition(
  raw: unknown
): { ok: ShieldDefinition } | { error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { error: 'Shield file is not an object' };
  }
  const r = raw as Record<string, unknown>;
  if (typeof r.name !== 'string' || !r.name) return { error: "Shield file missing 'name'" };
  if (typeof r.description !== 'string') return { error: "Shield file missing 'description'" };
  if (!Array.isArray(r.aliases)) return { error: "Shield file missing 'aliases' array" };
  if (!Array.isArray(r.smartRules)) return { error: "Shield file missing 'smartRules' array" };
  if (!Array.isArray(r.dangerousWords))
    return { error: "Shield file missing 'dangerousWords' array" };
  return { ok: r as unknown as ShieldDefinition };
}

/**
 * Validates a raw overrides object read from disk. Returns the cleaned
 * overrides plus a list of warnings about dropped entries (so the host can
 * decide how/whether to log them). Tampered/invalid verdicts are silently
 * filtered to keep arbitrary strings out of the policy engine.
 */
export function validateOverrides(raw: unknown): {
  overrides: ShieldOverrides;
  warnings: string[];
} {
  const warnings: string[] = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { overrides: {}, warnings };
  const result: ShieldOverrides = {};
  for (const [shieldName, rules] of Object.entries(raw as Record<string, unknown>)) {
    if (!rules || typeof rules !== 'object' || Array.isArray(rules)) continue;
    const validRules: Record<string, ShieldVerdict> = {};
    for (const [ruleName, verdict] of Object.entries(rules as Record<string, unknown>)) {
      if (isShieldVerdict(verdict)) {
        validRules[ruleName] = verdict;
      } else {
        warnings.push(
          `shields.json contains invalid verdict "${String(verdict)}" for ${shieldName}/${ruleName} — entry ignored. File may be corrupted or tampered with.`
        );
      }
    }
    if (Object.keys(validRules).length > 0) result[shieldName] = validRules;
  }
  return { overrides: result, warnings };
}

/**
 * The 11 shields shipped with node9. User shields installed at
 * ~/.node9/shields/*.json are merged on top of these by the host.
 */
export const BUILTIN_SHIELDS: Record<string, ShieldDefinition> = {
  [(aws as ShieldDefinition).name]: aws as ShieldDefinition,
  [(bashSafe as ShieldDefinition).name]: bashSafe as ShieldDefinition,
  [(docker as ShieldDefinition).name]: docker as ShieldDefinition,
  [(filesystem as ShieldDefinition).name]: filesystem as ShieldDefinition,
  [(github as ShieldDefinition).name]: github as ShieldDefinition,
  [(k8s as ShieldDefinition).name]: k8s as ShieldDefinition,
  [(mcpToolGating as ShieldDefinition).name]: mcpToolGating as ShieldDefinition,
  [(mongodb as ShieldDefinition).name]: mongodb as ShieldDefinition,
  [(postgres as ShieldDefinition).name]: postgres as ShieldDefinition,
  [(projectJail as ShieldDefinition).name]: projectJail as ShieldDefinition,
  [(redis as ShieldDefinition).name]: redis as ShieldDefinition,
};

// ── Builtin shield regex safety check (runs at module load) ──────────────
// Smart-rule conditions inside shield JSONs use `matches` / `notMatches`
// operators whose `value` is a regex compiled by getCompiledRegex at
// evaluation time. That path already runs safe-regex2 — but the failure
// is silent (returns null → fail-closed). We want shipped-shield bad
// patterns to fail LOUD at import, same standard as the DLP guard in
// dlp/index.ts. Catches a vulnerable pattern landing in a future
// shield-JSON edit before any customer hits it.
function assertBuiltinShieldRegexesAreSafe(): void {
  for (const shield of Object.values(BUILTIN_SHIELDS)) {
    for (const rule of shield.smartRules) {
      const conditions = rule.conditions ?? [];
      for (const cond of conditions) {
        if (cond.op !== 'matches' && cond.op !== 'notMatches') continue;
        const pattern = cond.value;
        if (!pattern) continue;
        if (!safeRegex(pattern)) {
          throw new Error(
            `[node9 engine] Shield '${shield.name}' rule '${rule.name ?? rule.tool}' has unsafe regex: ${pattern}`
          );
        }
      }
    }
  }
}
assertBuiltinShieldRegexesAreSafe();

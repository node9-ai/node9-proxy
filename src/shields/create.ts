// src/shields/create.ts
// Shared apply path for `node9 shield create` (CLI) and `node9_shield_create`
// (MCP, later). Both call createShield() so the guards + audit live in one
// place. The atomic write / validation already exist (installShield); this layer
// adds the create-specific guards (built-in collision, overwrite, no-rules,
// MCP allow-reject) and the optional enable + audit.

import fs from 'fs';
import path from 'path';
import {
  BUILTIN_SHIELDS,
  validateShieldDefinition,
  type ShieldDefinition,
} from '@node9/policy-engine';
import {
  installShield,
  readActiveShields,
  writeActiveShields,
  USER_SHIELDS_DIR_PATH,
} from '../shields';
import { appendConfigAudit } from '../audit';

export interface CreateShieldOpts {
  enable?: boolean;
  overwrite?: boolean;
  /** When true, this came from the MCP server (an agent) — allow-verdict rules
   *  are rejected so an agent can never author a rule that weakens node9. */
  viaMcp?: boolean;
}

export type CreateShieldResult =
  | { ok: true; path: string; enabled: boolean; ruleCount: number }
  | { ok: false; error: string };

// Built-in shield names AND their aliases. A user shield with one of these names
// would SHADOW the built-in (the loader merges {...BUILTIN_SHIELDS, ...user}), so
// `create` must refuse it — unlike `install`, whose names are curated.
function builtinNames(): Set<string> {
  const names = new Set<string>();
  for (const def of Object.values(BUILTIN_SHIELDS)) {
    names.add(def.name.toLowerCase());
    for (const a of def.aliases ?? []) names.add(a.toLowerCase());
  }
  return names;
}

/**
 * Validate + write a new user shield, with the create-specific guards. Pure of
 * its own logic; the only I/O is delegated to installShield / writeActiveShields
 * / appendConfigAudit. Returns a discriminated result (never throws for an
 * expected guard failure — the caller renders the message).
 */
export function createShield(
  def: ShieldDefinition,
  opts: CreateShieldOpts = {}
): CreateShieldResult {
  const name = def.name;

  // 1. Must not shadow a built-in shield (or one of its aliases).
  if (builtinNames().has(name.toLowerCase())) {
    return {
      ok: false,
      error: `"${name}" is a built-in shield — choose a different name (a user shield with this name would shadow the built-in).`,
    };
  }

  // 2. Don't silently clobber an existing user shield.
  const filePath = path.join(USER_SHIELDS_DIR_PATH, `${name}.json`);
  if (!opts.overwrite && fs.existsSync(filePath)) {
    return {
      ok: false,
      error: `Shield "${name}" already exists at ${filePath}. Pass --overwrite to replace it.`,
    };
  }

  // 3. A shield with nothing to enforce is a mistake, not a no-op.
  if (def.smartRules.length === 0) {
    return {
      ok: false,
      error: 'Shield has no rules — add at least one --block/--review tool or path.',
    };
  }

  // 4. An agent must never author an allow-verdict rule (mirrors handleRuleAdd).
  if (opts.viaMcp && def.smartRules.some((r) => r.verdict === 'allow')) {
    return {
      ok: false,
      error:
        'allow-verdict rules are not permitted over MCP (they would weaken node9). Use the CLI.',
    };
  }

  // 5. Pre-validate for a clean "shield create" error (installShield re-validates
  //    but emits a marketplace-flavored message we don't want users to see).
  const v = validateShieldDefinition(def);
  if ('error' in v) {
    return { ok: false, error: v.error };
  }

  // 6. Atomic write (installShield re-checks name traversal + name match).
  installShield(name, def);

  // 7. Optional enable — write the active-list directly (a fresh shield is not in
  //    the in-memory SHIELDS registry this process, so we must NOT route through
  //    getShield/resolveShieldName). Dedup like the `enable` command.
  let enabled = false;
  if (opts.enable) {
    const active = readActiveShields();
    if (!active.includes(name)) writeActiveShields([...active, name]);
    enabled = true;
  }

  // 8. Audit (covers both CLI and MCP — both go through here).
  appendConfigAudit({
    event: 'shield-create',
    shield: name,
    via: opts.viaMcp ? 'mcp' : 'cli',
    enabled,
  });

  return { ok: true, path: filePath, enabled, ruleCount: def.smartRules.length };
}

// The five protection levels (node9Firewall#385 item 5, the "How strict"
// switch on the Protection page). `settings.mode` names the level.
//
// A level is a set of DEFAULTS: for every check nobody stated, it picks the
// value. A value a person or the workspace stated still wins, and a level
// never picks a value the check does not allow (`configurableValues`). The
// table below lists only what a level changes; every other check keeps its
// catalog default. Agreed with the founder 2026-10-25
// (docs: node9-levels-handoff.md, section 3).

import type { Verdict } from './catalog';

export const LEVELS = ['audit', 'soft', 'standard', 'strict', 'block-all'] as const;
export type Level = (typeof LEVELS)[number];

/** Every value `settings.mode` accepts: the five levels plus `observe`, the
 *  older name of Audit that the dashboard still stores. */
export const MODE_VALUES = ['observe', ...LEVELS] as const;
export type ModeValue = (typeof MODE_VALUES)[number];

export function isModeValue(v: unknown): v is ModeValue {
  return typeof v === 'string' && (MODE_VALUES as readonly string[]).includes(v);
}

/** The level a mode names. `observe` is Audit; anything unknown or unset is
 *  Standard, the default of every install. */
export function levelOf(mode: string | undefined): Level {
  if (mode === 'observe') return 'audit';
  return (LEVELS as readonly string[]).includes(mode ?? '') ? (mode as Level) : 'standard';
}

/** Audit: nothing is stopped; every check records what it would have done. */
export function isRecordOnly(mode: string | undefined): boolean {
  return levelOf(mode) === 'audit';
}

/** Strict and Block all ask about every inline code call, not only the
 *  dangerous ones the inline judge finds. */
export function reviewsEveryInline(mode: string | undefined): boolean {
  const level = levelOf(mode);
  return level === 'strict' || level === 'block-all';
}

/** Block all: ask before any call no check recognised (the catch-all,
 *  `commands.unknown`), plus the binary-provenance escalations that came with
 *  it. This is what `strict` meant before the levels. */
export function isBlockAll(mode: string | undefined): boolean {
  return levelOf(mode) === 'block-all';
}

const SOFT: Readonly<Record<string, Verdict>> = {
  'commands.inline-exec': 'log',
  'commands.eval-dynamic': 'log',
  'commands.rm': 'log',
  'commands.chmod': 'log',
  'commands.sudo': 'log',
  'commands.git-destructive': 'log',
  'commands.sql-ddl': 'log',
  'commands.sql-no-where': 'log',
  'commands.temp-binary': 'log',
  'commands.disk-destroy': 'log',
  'commands.dangerous-word': 'log',
  'files.system-dirs': 'log',
  'files.shell-startup': 'log',
  'files.password-hashes': 'log',
  'data.pipe-chain': 'log',
  'behavior.untrusted-content': 'log',
};

const STRICT: Readonly<Record<string, Verdict>> = {
  'commands.sql-ddl': 'block',
  'commands.disk-destroy': 'block',
  'commands.node9-disarm': 'block',
  'files.system-dirs': 'block',
  'files.shell-startup': 'block',
  'files.password-hashes': 'block',
  'data.secrets-weak': 'block',
  'data.pipe-chain': 'block',
  'network.unknown-host': 'review',
  'network.internal-addresses': 'block',
  'behavior.prompt-injection': 'log',
  'loading.skill-tamper': 'block',
};

const LEVEL_CHECKS: Readonly<Record<Level, Readonly<Record<string, Verdict>>>> = {
  audit: {},
  soft: SOFT,
  standard: {},
  strict: STRICT,
  'block-all': STRICT,
};

/** The value a level gives a check nobody stated, or undefined when the
 *  level keeps the catalog default. */
export function levelCheckValue(mode: string | undefined, id: string): Verdict | undefined {
  return LEVEL_CHECKS[levelOf(mode)][id];
}

/** Every check a level changes, with its value. */
export function levelChecks(mode: string | undefined): Readonly<Record<string, Verdict>> {
  return LEVEL_CHECKS[levelOf(mode)];
}

/** The package registry signals (`loading.malicious-package` tuning), which
 *  allow only review or off. Soft turns both off; the others keep review. */
export function levelPackageSignals(
  mode: string | undefined
): { newPackage: 'review' | 'off'; installScript: 'review' | 'off' } | undefined {
  return levelOf(mode) === 'soft' ? { newPackage: 'off', installScript: 'off' } : undefined;
}

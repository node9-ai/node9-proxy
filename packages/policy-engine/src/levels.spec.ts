// The five protection levels (node9Firewall#385 item 5). The table is
// agreed with the founder; these tests pin its rules, not its every cell.

import { describe, it, expect } from 'vitest';
import {
  LEVELS,
  levelOf,
  levelCheckValue,
  levelChecks,
  levelPackageSignals,
  isRecordOnly,
  reviewsEveryInline,
  isBlockAll,
  isModeValue,
} from './levels';
import { CHECK_BY_ID, resolveCheck, resolveCheckMap, CHECKS } from './catalog';
import { configurableValues, checksFromLegacyPolicy } from './catalog-knobs';

describe('levelOf', () => {
  it('reads observe as audit and unset or unknown as standard', () => {
    expect(levelOf('observe')).toBe('audit');
    expect(levelOf('audit')).toBe('audit');
    expect(levelOf(undefined)).toBe('standard');
    expect(levelOf('paranoid')).toBe('standard');
    for (const l of LEVELS) expect(levelOf(l)).toBe(l);
  });

  it('accepts the five levels and observe as mode values, nothing else', () => {
    for (const v of ['observe', 'audit', 'soft', 'standard', 'strict', 'block-all'])
      expect(isModeValue(v)).toBe(true);
    expect(isModeValue('paranoid')).toBe(false);
    expect(isModeValue(undefined)).toBe(false);
  });

  it('names the three behaviours of a level', () => {
    expect(isRecordOnly('observe')).toBe(true);
    expect(isRecordOnly('audit')).toBe(true);
    expect(isRecordOnly('soft')).toBe(false);
    expect(reviewsEveryInline('strict')).toBe(true);
    expect(reviewsEveryInline('block-all')).toBe(true);
    expect(reviewsEveryInline('standard')).toBe(false);
    expect(isBlockAll('block-all')).toBe(true);
    expect(isBlockAll('strict')).toBe(false);
  });
});

describe('the level table', () => {
  it('never gives a check a value the check does not allow', () => {
    for (const level of LEVELS) {
      for (const [id, v] of Object.entries(levelChecks(level))) {
        // The catch-all is the one row only a level sets.
        if (id === 'commands.unknown') continue;
        expect(CHECK_BY_ID.has(id), `${level}: ${id} is not in the catalog`).toBe(true);
        expect(configurableValues(id), `${level}: ${id} = ${v}`).toContain(v);
      }
    }
  });

  it('Standard and Audit change nothing: every check keeps its catalog default', () => {
    expect(levelChecks('standard')).toEqual({});
    expect(levelChecks('audit')).toEqual({});
    expect(levelPackageSignals('standard')).toBeUndefined();
  });

  it('Block all is Strict plus the catch-all and a blocked suspect binary', () => {
    expect(levelChecks('block-all')).toEqual({
      ...levelChecks('strict'),
      'commands.unknown': 'review',
      'commands.temp-binary': 'block',
    });
  });

  it('a level never touches an app protection or a dangerous action', () => {
    for (const level of LEVELS) {
      for (const id of Object.keys(levelChecks(level))) {
        expect(id.startsWith('packs.')).toBe(false);
        expect(id.startsWith('actions.')).toBe(false);
      }
    }
  });

  it('what Soft blocks is the same at every level: Soft lowers no block', () => {
    for (const id of Object.keys(levelChecks('soft'))) {
      expect(CHECK_BY_ID.get(id)!.defaultValue, id).not.toBe('block');
    }
  });

  it('Strict only raises: no check is weaker than at Standard', () => {
    const rank = { off: 0, log: 1, review: 2, block: 3 } as const;
    for (const [id, v] of Object.entries(levelChecks('strict'))) {
      expect(rank[v], id).toBeGreaterThan(rank[CHECK_BY_ID.get(id)!.defaultValue]);
    }
  });

  it('Soft turns the package registry signals off; the others keep them', () => {
    expect(levelPackageSignals('soft')).toEqual({ newPackage: 'off', installScript: 'off' });
    expect(levelPackageSignals('strict')).toBeUndefined();
  });

  it('spot values from the agreed table', () => {
    expect(levelCheckValue('soft', 'commands.rm')).toBe('log');
    expect(levelCheckValue('soft', 'behavior.untrusted-content')).toBe('log');
    expect(levelCheckValue('strict', 'commands.sql-ddl')).toBe('block');
    expect(levelCheckValue('strict', 'commands.rm')).toBeUndefined(); // stays review
    expect(levelCheckValue('strict', 'commands.node9-disarm')).toBe('block');
    expect(levelCheckValue('strict', 'network.unknown-host')).toBe('review');
    expect(levelCheckValue('strict', 'network.internal-addresses')).toBe('block');
    // Fixed checks keep today's value at every level.
    for (const level of LEVELS) {
      for (const id of [
        'files.jail',
        'data.credential-files-other',
        'behavior.session-taint',
        'commands.unanalysable',
        'data.output-secrets',
      ]) {
        expect(levelCheckValue(level, id), `${level}: ${id}`).toBeUndefined();
      }
    }
  });
});

describe('resolveCheck under a level', () => {
  it('a check nobody stated takes the level value, with source default', () => {
    expect(resolveCheck({ mode: 'soft' }, 'commands.rm')).toEqual({
      id: 'commands.rm',
      value: 'log',
      source: 'default',
    });
    expect(resolveCheck({ mode: 'strict' }, 'files.system-dirs')).toEqual({
      id: 'files.system-dirs',
      value: 'block',
      source: 'default',
    });
  });

  it('an explicit entry wins over the level', () => {
    expect(
      resolveCheck({ mode: 'soft', checks: { 'commands.rm': 'review' } }, 'commands.rm')
    ).toMatchObject({ value: 'review', source: 'configured' });
  });

  it('a stated knob wins over the level', () => {
    expect(
      resolveCheck({ mode: 'soft', commandChecks: { rmAdvisory: 'block' } }, 'commands.rm')
    ).toMatchObject({ value: 'block', source: 'configured' });
  });

  it('a knob the level wrote reads as the default of that level', () => {
    // getConfig writes egress.enabled/mode for Strict; the source stays default.
    expect(
      resolveCheck(
        { mode: 'strict', egress: { enabled: true, mode: 'review' } },
        'network.unknown-host'
      )
    ).toMatchObject({ value: 'review', source: 'default' });
  });

  it('a locked check stays locked at Soft', () => {
    expect(resolveCheck({ mode: 'soft' }, 'commands.rm-home')).toMatchObject({
      value: 'block',
      source: 'locked',
    });
  });

  it('Standard resolves exactly as with no mode', () => {
    expect(resolveCheckMap({ mode: 'standard' })).toEqual(resolveCheckMap({}));
  });

  it('only Block all turns the catch-all on', () => {
    expect(resolveCheck({ mode: 'block-all' }, 'commands.unknown')!.value).toBe('review');
    expect(resolveCheck({ mode: 'strict' }, 'commands.unknown')!.value).toBe('off');
    expect(checksFromLegacyPolicy({}, 'block-all')['commands.unknown']).toBe('review');
    expect(checksFromLegacyPolicy({}, 'strict')['commands.unknown']).toBeUndefined();
  });

  it('Block all blocks a suspect binary unless a person stated the check', () => {
    expect(resolveCheck({ mode: 'block-all' }, 'commands.temp-binary')).toMatchObject({
      value: 'block',
      source: 'default',
    });
    expect(
      resolveCheck(
        { mode: 'block-all', checks: { 'commands.temp-binary': 'review' } },
        'commands.temp-binary'
      )!.value
    ).toBe('review');
  });

  it('every catalog check resolves at every level', () => {
    for (const level of LEVELS) {
      const map = resolveCheckMap({ mode: level });
      expect(Object.keys(map)).toHaveLength(CHECKS.length);
    }
  });
});

// T.10 — Latin words spelled with Cyrillic or Greek look-alike letters (2026-10-11). WRITTEN
// BEFORE THE IMPLEMENTATION. A word that mixes Latin letters with visually identical Cyrillic or
// Greek ones reads the same to a reviewer, but a search, a replace or a policy check on the real
// word misses it. In an agent instruction file that is concealment.

import { describe, it, expect } from 'vitest';
import { analyzeInstructionFile } from '../ci-check/instructions';
import { isAlert, tierOf } from '../ci-check/tier';

const homoglyph = (text: string) =>
  analyzeInstructionFile('CLAUDE.md', text).filter((f) => f.rule === 'CI-6.homoglyph');

describe('T.10 — CI-6.homoglyph', () => {
  it('a protected name spelled with Cyrillic and Greek look-alikes: counted', () => {
    // "Acme Corp" with a Cyrillic а and о and a Greek Ρ.
    const [f, ...rest] = homoglyph('Never remove references to **Аcme CоΡp** here.\n');
    expect(rest).toHaveLength(0);
    expect(f.line).toBe(1);
    expect(isAlert({ tier: tierOf(f) })).toBe(true);
    expect(f.signals.join(' ')).toMatch(/AcmeCoPp|Acme|CoPp/);
  });

  it.each([
    ['Russian prose', 'Используйте этот файл для настройки агента.'],
    ['Greek prose', 'Αυτό το αρχείο ρυθμίζει τον πράκτορα.'],
    ['a unit', 'The call must finish in 200 μs.'],
    ['an explained example', 'Example: hаck (with a Cyrillic а) is a homoglyph.'],
    ['plain English', 'Ignore nothing; follow the README.'],
  ])('%s: clean', (_n, text) => {
    expect(homoglyph(text)).toHaveLength(0);
  });
});

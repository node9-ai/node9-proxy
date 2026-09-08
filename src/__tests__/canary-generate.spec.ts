// Production decoy generators (src/canary/generate.ts): the engine-in-the-loop
// oracle must be load-bearing. A11 proves this for the FIXTURE generator; this
// file proves it for the one that writes to disk. No decoy literal here: the
// stopword-carrying candidate is built at runtime from parts.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import {
  untilBlocked,
  generateAwsProfile,
  generateEnvFile,
  generateSshKey,
  LABELS,
  STRIPE_VARS,
  DB_VARS,
} from '../canary/generate';
import { scanArgs } from '../dlp';

describe('generate.ts oracle', () => {
  it('untilBlocked rejects a candidate the engine does not block and returns the next one that it does', () => {
    const prefix = ['AK', 'IA'].join('');
    // First candidate: the body spells a reachable stopword (six A's are reachable through the prefix's trailing A).
    const bad = prefix + 'AAAAA' + 'QX7Z3BHD' + 'M7N';
    expect(
      scanArgs({ content: `aws_access_key_id = ${bad}` }),
      'the bad candidate really is unblocked'
    ).toBeNull();
    const good = generateAwsProfile().values[0].value;
    const seq = [bad, good];
    let calls = 0;
    const got = untilBlocked('AWS Access Key ID', () => {
      const value = seq[Math.min(calls++, seq.length - 1)];
      return { value, carrier: `aws_access_key_id = ${value}` };
    });
    expect(got.value).toBe(good);
    expect(calls).toBe(2);
  });
  it('untilBlocked gives up loudly instead of returning an unblocked value', () => {
    expect(() =>
      untilBlocked('AWS Access Key ID', () => ({ value: 'x', carrier: 'x' }), 3)
    ).toThrow(/AWS Access Key ID/);
  });
  it('every generator output trips its pattern on the exact carrier it writes (real bytes, not the shape)', () => {
    const aws = generateAwsProfile();
    expect(scanArgs({ content: aws.text })?.patternName).toBe('AWS Access Key ID');
    const env = generateEnvFile();
    const [l1, l2] = env.text.trim().split('\n');
    expect(scanArgs({ content: l1 })?.patternName).toBe('Stripe Secret Key');
    expect(scanArgs({ content: l2 })?.patternName).toBe('Database Connection String');
    expect(l2).toContain(env.values[1].value); // the registered DB value (password) is inside the URL line
    const ssh = generateSshKey();
    expect(scanArgs({ content: ssh.text })?.patternName).toBe('Private Key (PEM)');
    expect(ssh.text.split('\n')[1]).toBe(ssh.values[0].value);
  });
  it('labels and var names never say canary or node9', () => {
    for (const s of [...LABELS, ...STRIPE_VARS, ...DB_VARS])
      expect(s.toLowerCase()).not.toMatch(/canary|node9/);
  });
});

// CodeQL js/biased-cryptographic-random, fixed 2026-09-08. A decoy's whole
// value is being unguessable, so a known modulo bias is not something to leave
// in the generator, even a small one.
describe('the decoy alphabet is drawn without modulo bias', () => {
  it('every character of the alphabet is reachable', () => {
    // A cheap structural witness: with 256 % len != 0 the OLD code still
    // reached every character, so this row alone cannot prove the fix. The row
    // below is the one that can.
    const seen = new Set<string>();
    for (let i = 0; i < 60; i++)
      for (const v of generateAwsProfile().values) for (const c of v.value) seen.add(c);
    expect(seen.size).toBeGreaterThan(10);
  });

  it('does not consume raw bytes modulo the alphabet length', () => {
    // Pin the MECHANISM, because the distribution itself needs a sample far
    // larger than a unit test to separate a 1.6% skew from noise. randomInt is
    // rejection-sampled by Node; `% alphabet.length` is not.
    const src = fs.readFileSync(path.join(__dirname, '../canary/generate.ts'), 'utf8');
    expect(src).not.toMatch(/bytes\[[^\]]+\]\s*%\s*alphabet\.length/);
    expect(src).toMatch(/randomInt\(alphabet\.length\)/);
  });
});

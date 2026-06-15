// Unit tests for the posture checks + scoring.
//
// Covers: egress verdict logic, score mapping, and the secrets check against
// a planted fake secret in an isolated temp HOME — including the invariant
// that the secret VALUE is never surfaced in a finding.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { evaluateEgressConfig } from '../egress';
import { scorePosture } from '../score';
import { checkSecrets } from '../secrets';
import type { Finding } from '../types';

// A fake token assembled at runtime — matches the DLP "GitHub Token" pattern
// once joined, but no secret-shaped literal appears in this source file.
const FAKE_TOKEN = ['ghp', '_', 'A1b2C3d4E5f6', 'G7h8I9j0K1l2', 'M3n4O5p6Q7r8'].join('');

describe('evaluateEgressConfig', () => {
  it('flags HIGH when egress is disabled', () => {
    const f = evaluateEgressConfig({ enabled: false, mode: 'off' });
    expect(f?.severity).toBe('high');
    expect(f?.category).toBe('Egress');
  });

  it('flags HIGH when enabled but mode is off', () => {
    const f = evaluateEgressConfig({ enabled: true, mode: 'off' });
    expect(f?.severity).toBe('high');
  });

  it('flags MEDIUM in review mode (logged, not blocked)', () => {
    const f = evaluateEgressConfig({ enabled: true, mode: 'review' });
    expect(f?.severity).toBe('medium');
  });

  it('passes (null) when locked to block', () => {
    const f = evaluateEgressConfig({ enabled: true, mode: 'block' });
    expect(f).toBeNull();
  });
});

describe('scorePosture', () => {
  const mk = (severity: Finding['severity']): Finding => ({
    category: 'X',
    severity,
    title: 't',
    detail: [],
  });

  it('a clean run (no findings) scores 100/good', () => {
    expect(scorePosture([], 3)).toEqual({ score: 100, tier: 'good' });
  });

  it('any critical finding lands in the critical tier', () => {
    const { tier } = scorePosture([mk('critical')], 3);
    expect(tier).toBe('critical');
  });

  it('a single high finding lands at-risk (not critical)', () => {
    const { tier } = scorePosture([mk('high')], 3);
    expect(tier).toBe('at-risk');
  });

  it('advisory findings do not deduct', () => {
    expect(scorePosture([mk('advisory')], 3)).toEqual({ score: 100, tier: 'good' });
  });
});

describe('checkSecrets', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'posture-secrets-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('flags a plaintext secret in a .env file as critical', () => {
    fs.writeFileSync(path.join(home, '.env'), `GITHUB_TOKEN=${FAKE_TOKEN}\n`);
    const findings = checkSecrets({ home, cwd: home });
    const crit = findings.find((f) => f.severity === 'critical');
    expect(crit).toBeDefined();
    expect(crit?.category).toBe('Secrets');
  });

  it('never leaks the secret value into the finding', () => {
    fs.writeFileSync(path.join(home, '.env'), `GITHUB_TOKEN=${FAKE_TOKEN}\n`);
    const findings = checkSecrets({ home, cwd: home });
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(FAKE_TOKEN);
  });

  it('flags credential material (~/.ssh/id_rsa) as high', () => {
    fs.mkdirSync(path.join(home, '.ssh'));
    // Existence is what's checked; contents are irrelevant (and kept innocuous).
    fs.writeFileSync(path.join(home, '.ssh', 'id_rsa'), 'placeholder');
    const findings = checkSecrets({ home, cwd: home });
    const high = findings.find((f) => f.severity === 'high');
    expect(high).toBeDefined();
    expect(high?.title).toContain('credential file');
  });

  it('returns no findings on a clean home', () => {
    const findings = checkSecrets({ home, cwd: home });
    expect(findings).toEqual([]);
  });
});

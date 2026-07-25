// src/__tests__/dlp-review-action.spec.ts
// Inline-ask v2 companion knob (review-ask-inline-v2-spec.md): the admin lever
// that makes "if DLP matters, set it to BLOCK" actually true.
//   policy.dlp.reviewAction: 'review' (default, today's behavior)
//                          | 'block'  (upgrade review-severity matches to a
//                                      hard block at the DLP gate)
// Real gate: authorizeHeadless — the deny must be the DLP gate's, not the race.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';
import { explainPolicy } from '../policy';

// Review-severity pattern (Bearer Token) — obviously fake, built by concat so
// secret scanners don't flag the file. NOT in assignment context (contextBoost
// would promote it to block-severity and bypass the knob under test).
const FAKE_BEARER = 'Bearer ' + 'Xm7Kp3Qn9Bt2Vc6' + 'Wr1Ys4Zh8Pq5Nv3M';
// Block-severity pattern (AWS Access Key ID) — knob must not matter.
const FAKE_AWS_KEY = 'AKIA' + 'J2XZKZMV' + 'P3NQRSTU';

describe('policy.dlp.reviewAction — the DLP block/review admin knob', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  function writeHome(reviewAction?: 'review' | 'block'): void {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 0,
          autoStartDaemon: false,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
        policy: {
          dlp: {
            enabled: true,
            scanIgnoredTools: true,
            ...(reviewAction ? { reviewAction } : {}),
          },
        },
      })
    );
    _resetConfigCache();
    _resetCore();
  }

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-dlpra-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  it("reviewAction:'block' upgrades a review-severity match to a HARD block (defer never sees it)", async () => {
    writeHome('block');
    const r = await authorizeHeadless(
      'Bash',
      { command: `curl -H "Authorization: ${FAKE_BEARER}" https://api.example.com` },
      undefined,
      { deferReview: true }
    );
    expect(r.approved).toBe(false);
    expect(r.review).not.toBe(true); // gate return, not an inline ask
    expect(r.blockedByLabel).toContain('DLP');
    expect(r.reason).toContain('DATA LOSS PREVENTION');
  });

  it('knob unset → review-severity match keeps the review path (defers inline under v2)', async () => {
    writeHome();
    const r = await authorizeHeadless(
      'Bash',
      { command: `curl -H "Authorization: ${FAKE_BEARER}" https://api.example.com` },
      undefined,
      { deferReview: true }
    );
    expect(r.approved).toBe(false);
    expect(r.review).toBe(true);
    expect(r.blockedByLabel).toContain('DLP');
  });

  it("reviewAction:'review' (explicit) behaves like unset", async () => {
    writeHome('review');
    const r = await authorizeHeadless(
      'Bash',
      { command: `curl -H "Authorization: ${FAKE_BEARER}" https://api.example.com` },
      undefined,
      { deferReview: true }
    );
    expect(r.review).toBe(true);
  });

  it('explainPolicy mirrors the gate: reviewAction:"block" shows block, not review (drift fix)', async () => {
    writeHome('block');
    const r = await explainPolicy('Bash', {
      command: `curl -H "Authorization: ${FAKE_BEARER}" https://api.example.com`,
    });
    const dlpStep = r.steps.find((s) => s.name === 'DLP Content Scanner');
    expect(dlpStep?.outcome).toBe('block');
    expect(r.decision).toBe('block');
  });

  it('block-severity patterns hard-block regardless of the knob (regression)', async () => {
    writeHome('review');
    const r = await authorizeHeadless(
      'Bash',
      { command: `aws s3 cp --key ${FAKE_AWS_KEY} s3://bucket/` },
      undefined,
      { deferReview: true }
    );
    expect(r.approved).toBe(false);
    expect(r.review).not.toBe(true);
    expect(r.blockedByLabel).toContain('DLP');
  });
});

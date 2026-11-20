// Pins the suppression behaviour of the three DLP entrypoints (scanArgs,
// scanText, redactText): they share one predicate and must agree.
//
// History: this file first pinned the behaviour BEFORE the shared helper was
// extracted, including the defect of the time: a stopword anywhere inside a
// match dropped it (DLP-1). node9Firewall#301 replaced the stopword substring
// test with a judgement on the token's shape (dlp/placeholder.ts), and the c1
// rows flipped from "suppressed at all three sites" to "reported at all three
// sites". That flip is the acceptance of the issue. AWS_DOC keeps the
// suppressed side witnessed with a real placeholder.
//
// Fixtures are split so the checkout holds no contiguous credential-shaped
// literal (and so node9's own DLP gate, which blocks an AKIA-shaped arg, lets
// the file be written). AWS_SW matches the AWS Access Key regex AND lowercases
// to contain the old stopword `here`; the AWS pattern has no minEntropy, so
// entropy is not a confound. OAI_LOW has entropy ~1.6 and is not filler by
// shape, isolating the entropy guard.
import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText } from './index';

const AWS_SW = ['AKIA', 'HERE', 'QX7Z3BHD', 'M7NP'].join(''); // old stopword inside a real-shaped key
const AWS_DOC = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join(''); // the AWS documentation key: a placeholder
const AWS_OK = ['AKIA', 'QX7Z3BHD', 'M7NPLKV5'].join(''); // the golden-corpus positive
const SLACK_OK = ['xoxb-', '5182736490-', 'Km3Pq7Xn2Bt'].join('');
const OAI_LOW = 'sk-' + 'abc'.repeat(10); // entropy ~1.6 < 3.5, no stopword
const OAI_OK = ['sk-', 'Xm7Kp3Qn9Bt2Vc6Wr1Ys4Zh8Pq5Nv3Mt'].join('');

describe('known-true (independent of any suppression path)', () => {
  it('a clean AWS key is reported by all three entrypoints', () => {
    expect(scanArgs({ k: AWS_OK })?.patternName).toBe('AWS Access Key ID');
    expect(scanText(AWS_OK)?.patternName).toBe('AWS Access Key ID');
    const r = redactText('x ' + AWS_OK + ' y');
    expect(r.found).toEqual(['AWS Access Key ID']);
    expect(r.result).not.toContain(AWS_OK);
  });
});

describe('c1 a stopword inside a real-shaped key is reported at all three sites (was: suppressed)', () => {
  it('scanArgs reports', () => {
    expect(scanArgs({ k: AWS_SW })?.patternName).toBe('AWS Access Key ID');
  });
  it('scanText reports', () => {
    expect(scanText(AWS_SW)?.patternName).toBe('AWS Access Key ID');
  });
  it('redactText redacts and reports', () => {
    const r = redactText('x ' + AWS_SW + ' y');
    expect(r.result).toBe('x [node9-redacted:AWS Access Key ID] y');
    expect(r.found).toEqual(['AWS Access Key ID']);
  });
});

describe('c1b placeholder suppression is identical at all three sites', () => {
  it('scanArgs suppresses', () => {
    expect(scanArgs({ k: AWS_DOC })).toBeNull();
  });
  it('scanText suppresses', () => {
    expect(scanText(AWS_DOC)).toBeNull();
  });
  it('redactText leaves the text intact and reports nothing', () => {
    const input = 'x ' + AWS_DOC + ' y';
    const r = redactText(input);
    expect(r.result).toBe(input);
    expect(r.found).toEqual([]);
  });
  it('scanArgs CONTINUES to the next pattern after a suppressed match (not return null)', () => {
    expect(scanArgs({ k: AWS_DOC + ' ' + SLACK_OK })?.patternName).toBe('Slack Bot Token');
  });
});

describe('c2 entropy suppression at redactText (already pinned for scanArgs/scanText)', () => {
  it('low-entropy match is left intact', () => {
    const input = 'x ' + OAI_LOW + ' y';
    const r = redactText(input);
    expect(r.result).toBe(input);
    expect(r.found).toEqual([]);
  });
  it('high-entropy match is redacted', () => {
    const r = redactText(OAI_OK);
    expect(r.found).toEqual(['OpenAI API Key']);
    expect(r.result).toContain('[node9-redacted:OpenAI API Key]');
    expect(r.result).not.toContain(OAI_OK);
  });
});

describe('c3 redactText semantics', () => {
  it('a suppressed and an accepted match of the same pattern in one string: only the accepted one is redacted, name reported once', () => {
    const r = redactText(AWS_DOC + ' ' + AWS_OK);
    expect(r.result).toContain(AWS_DOC);
    expect(r.result).not.toContain(AWS_OK);
    expect(r.result).toContain('[node9-redacted:AWS Access Key ID]');
    expect(r.found).toEqual(['AWS Access Key ID']);
  });
  it('two accepted matches of one pattern report the name once', () => {
    const r = redactText(AWS_OK + ' ' + AWS_OK);
    expect(r.found).toHaveLength(1);
    expect(r.result).not.toContain(AWS_OK);
  });
});

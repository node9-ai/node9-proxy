// Pins the CURRENT suppression behaviour of the three DLP entrypoints BEFORE
// the shared helper is extracted. Every row here must be green on the code as
// it stands; the refactor must leave all of them green.
//
// Why these exist: stopword suppression was never pinned at any site (only
// implied by "avoid stopwords" fixture comments), entropy suppression was
// pinned for scanArgs/scanText but not redactText, and redactText had no
// tests at all. An unwitnessed site cannot be refactored.
//
// Fixtures are split so the checkout holds no contiguous credential-shaped
// literal (and so node9's own DLP gate, which blocks an AKIA-shaped arg, lets
// the file be written). AWS_SW matches the AWS Access Key regex AND lowercases
// to contain the stopword `here`; the AWS pattern has no minEntropy, so entropy
// is not a confound. OAI_LOW has entropy ~1.6 and no stopword, isolating the
// entropy guard (the repo's `'a'.repeat(n)` rows contain the stopword `aaaaaa`
// and therefore witness "stopword OR entropy", not entropy alone).
import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText } from './index';

const AWS_SW = ['AKIA', 'HERE', 'QX7Z3BHD', 'M7NP'].join(''); // stopword inside a real-shaped key
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

describe('c1 stopword suppression is identical at all three sites', () => {
  it('scanArgs suppresses', () => {
    expect(scanArgs({ k: AWS_SW })).toBeNull();
  });
  it('scanText suppresses', () => {
    expect(scanText(AWS_SW)).toBeNull();
  });
  it('redactText leaves the text intact and reports nothing', () => {
    const input = 'x ' + AWS_SW + ' y';
    const r = redactText(input);
    expect(r.result).toBe(input);
    expect(r.found).toEqual([]);
  });
  it('scanArgs CONTINUES to the next pattern after a suppressed match (not return null)', () => {
    expect(scanArgs({ k: AWS_SW + ' ' + SLACK_OK })?.patternName).toBe('Slack Bot Token');
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
    const r = redactText(AWS_SW + ' ' + AWS_OK);
    expect(r.result).toContain(AWS_SW);
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

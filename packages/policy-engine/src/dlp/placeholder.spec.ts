// The placeholder judgement (node9Firewall#301, DLP-1). Before the fix the
// three raw entrypoints dropped any match that CONTAINED a stopword (`here`,
// `your`, `example`), so a real token or password that merely carried one was
// allowed through. The corpus in placeholder.fixtures.ts was written first;
// every row runs through scanArgs, scanText and redactText.
import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText } from './index';
import { scanArgumentSecrets } from './arguments';
import { isPlaceholder } from './placeholder';
import { PLACEHOLDER_CORPUS, AWS, AWS_DOC, AWS_REAL, BEARER, DB } from './placeholder.fixtures';

const j = (...parts: string[]): string => parts.join('');

describe('corpus: reported rows are reported at all three entrypoints', () => {
  for (const row of PLACEHOLDER_CORPUS.filter((r) => r.report !== null)) {
    it(`${row.id} (${row.why})`, () => {
      // The call shape of the hook: the text inside a Bash command.
      expect(scanArgs({ command: `echo ${row.text}` })?.patternName).toBe(row.report);
      expect(scanText(`out: ${row.text}`)?.patternName).toBe(row.report);
      const r = redactText(`out: ${row.text} end`);
      expect(r.found).toContain(row.report);
      expect(r.result).toContain(`[node9-redacted:${row.report}]`);
    });
  }
});

describe('corpus: placeholder rows stay quiet at all three entrypoints', () => {
  for (const row of PLACEHOLDER_CORPUS.filter((r) => r.report === null)) {
    it(`${row.id} (${row.why})`, () => {
      expect(scanArgs({ command: `echo ${row.text}` })).toBeNull();
      expect(scanText(`out: ${row.text}`)).toBeNull();
      const input = `out: ${row.text} end`;
      const r = redactText(input);
      expect(r.found).toEqual([]);
      expect(r.result).toBe(input);
    });
  }
});

describe('pairs that differ only in an incidental stopword', () => {
  // The control and the positive are the same length and alphabet; only the
  // four letters in the middle change.
  const pairs: Array<[string, string, string]> = [
    [AWS, j('AKIA', 'QX7Z', 'WXYZ', '3BHDM7NP'), j('AKIA', 'QX7Z', 'HERE', '3BHDM7NP')],
    [
      BEARER,
      j('Bearer ', 'Qx7Lm2Vb9', 'wxyz', 'Tz4Kp3Wn8Rd5Hc6'),
      j('Bearer ', 'Qx7Lm2Vb9', 'your', 'Tz4Kp3Wn8Rd5Hc6'),
    ],
    [
      DB,
      j('postgres://admin:', 'Qx7Lm2', 'wxyz', 'Vb9', '@db.internal/prod'),
      j('postgres://admin:', 'Qx7Lm2', 'fake', 'Vb9', '@db.internal/prod'),
    ],
  ];
  for (const [name, control, positive] of pairs) {
    it(`${name}: control and positive get the same verdict`, () => {
      for (const text of [control, positive]) {
        expect(scanArgs({ k: text })?.patternName, text.slice(0, 12)).toBe(name);
        expect(scanText(text)?.patternName).toBe(name);
        expect(redactText(text).found).toEqual([name]);
      }
    });
  }
});

describe('where the secret sits', () => {
  const positive = j('AKIA', 'HERE', 'QX7Z3BHD', 'M7NP');

  it('two levels down in an object', () => {
    expect(scanArgs({ a: { b: { key: positive } } })?.patternName).toBe(AWS);
  });

  it('inside a stringified JSON field', () => {
    expect(scanArgs({ body: JSON.stringify({ env: { AWS_KEY: positive } }) })?.patternName).toBe(
      AWS
    );
  });

  it('a placeholder and a real key in one text: only the real one is redacted', () => {
    const r = redactText(`${AWS_DOC} then ${AWS_REAL}`);
    expect(r.result).toContain(AWS_DOC);
    expect(r.result).not.toContain(AWS_REAL);
    expect(r.found).toEqual([AWS]);
  });

  it('redactText replaces the whole match, the writer-chosen part included', () => {
    const text = j(
      'cloudinary://',
      '123456789012345',
      ':',
      'Qx7Lm2Vb9Tz4Kp3Wn8Rd5Hc6Yf1',
      '@sample'
    );
    expect(redactText(text).result).toBe('[node9-redacted:Cloudinary URL]');
  });
});

describe('the entropy floor reads the secret, not the words around it', () => {
  it('a Bearer token of five repeated digits is filler; the scheme word no longer lifts it', () => {
    // Token entropy 2.3; with `Bearer ` in front the whole match measured 3.1
    // and passed the 3.0 floor before the fix.
    expect(scanText(j('Bearer ', '01234'.repeat(4), '01'))).toBeNull();
  });
  it('a varied Bearer token is reported', () => {
    expect(scanText(j('Bearer ', 'Qx7Lm2Vb9Tz4Kp3Wn8Rd5'))?.patternName).toBe(BEARER);
  });
});

describe('the argument gate (context patterns) uses the same judgement', () => {
  const VALUE = j('Ghq', 'ylh3N', 'here', 'Fbs1jC', '26VoQ9');

  it('an assigned value with a stopword inside is still a finding', () => {
    expect(scanArgumentSecrets({ content: `api_key = "${VALUE}"` })?.patternName).toBe(
      'Assigned Secret'
    );
  });
  it('a placeholder value is not', () => {
    expect(scanArgumentSecrets({ content: 'api_key = "your_api_key_here_1"' })).toBeNull();
    expect(scanArgumentSecrets({ content: 'api_key = "<your-api-key-0001>"' })).toBeNull();
  });
  it('a SQL account password with a stopword inside is still a finding', () => {
    const sql = j("CREATE USER app IDENTIFIED BY '", 'Qx7Lm2', 'here', 'Vb9', "'");
    expect(scanArgumentSecrets({ command: `mysql -e "${sql}"` })?.patternName).toBe(
      'SQL Account Password'
    );
  });
});

describe('isPlaceholder: the four rules', () => {
  const yes: Array<[string, string]> = [
    ['${DB_PASSWORD}', 'template variable'],
    ['{{ secrets.token }}', 'template variable'],
    ['%{hiera_key}', 'template variable'],
    ['<your-token>', 'angle slot'],
    ['x'.repeat(20), 'one character'],
    [j('Qx7Lm2', '0'.repeat(8), 'Vb9'), 'a run of eight'],
    [j('sk_live_', 'x'.repeat(24)), 'filler after a prefix'],
    ['sk-your-key-here', 'your/here stand as words'],
    ['my.fake.value', 'fake stands as a word'],
    [j('AKIA', 'IOSFODNN7', 'EXAMPLE'), 'ends in a doc word'],
    [j('wJalrXUtnFEMI/K7MDENG/bPxRfiCY', 'EXAMPLE', 'KEY'), 'ends in EXAMPLEKEY'],
    ['changeme123', 'starts with a doc word'],
    ['FAKEPASSWORDXY', 'starts with a doc word, upper case'],
    ['YOUR_KEY_HERE', 'vocabulary'],
    ['yourKeyHere', 'vocabulary, camel case'],
    ['InsertTokenHere', 'vocabulary, pascal case'],
    ['password', 'one vocabulary word'],
    ['mypassword', 'vocabulary words joined'],
    ['test1234', 'vocabulary and digits'],
    ['secret_key_123', 'vocabulary and digits'],
  ];
  for (const [value, why] of yes) {
    it(`placeholder: ${why} (${value.slice(0, 16)})`, () => {
      expect(isPlaceholder(value)).toBe(true);
    });
  }

  const no: Array<[string, string]> = [
    ['', 'empty'],
    [j('AKIA', 'HERE', 'QX7Z3BHD', 'M7NP'), 'here inside a run of letters'],
    ['atmosphere', 'here inside a word'],
    ['Qx7Lm2hereVb9', 'a case boundary is not a separator'],
    [j('sk_test_', 'Qx7Lm2Vb9Tz4Kp3Wn8Rd5Hc6'), 'test is a real prefix word'],
    [j('secret_', 'Qx7Lm2Vb9Tz4Kp3Wn8Rd5Hc6Yf1Qx7Lm2Vb9Tz4Kp3W'), 'vendor prefix then real body'],
    [j('key-', '1'.repeat(4), '2'.repeat(4), '3'.repeat(4), '4567890123456789'), 'digits dominate'],
    ['Qx7Lm2Vb9Tz4', 'generated'],
    [j('Qx7Lm2', '0'.repeat(6), 'Vb9Tz4Kp3'), 'six zeros inside a real token'],
    ['Qx7Lm2exampleVb9Tz4', 'a doc word in the middle'],
    ['theme-park-7Qx2Lm9Vb', 'words that are not vocabulary'],
  ];
  for (const [value, why] of no) {
    it(`not a placeholder: ${why} (${value.slice(0, 16)})`, () => {
      expect(isPlaceholder(value)).toBe(false);
    });
  }
});

describe('cost', () => {
  it('a 200 KB token is judged in linear time', () => {
    // Upper-case letters with no lower-case one: the shape a naive case split
    // walks quadratically. The hook must never wait on a placeholder check.
    const long = 'QXZBHDMNPLKV'.repeat(17_000);
    const started = process.cpuUsage();
    expect(isPlaceholder(long)).toBe(false);
    expect(scanText(j('Bearer ', long))?.patternName).toBe(BEARER);
    const spent = process.cpuUsage(started);
    expect((spent.user + spent.system) / 1000).toBeLessThan(500);
  });
});

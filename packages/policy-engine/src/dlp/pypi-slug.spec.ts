// A URL slug is not a token (node9Firewall#374). The PyPI pattern matched any
// `pypi-` followed by 50 letters, digits, dashes or underscores, so a news
// article URL was redacted as a `PyPI Upload Token` and the session flagged.
// Two changes: the pattern is anchored on the macaroon prefix every PyPI token
// starts with, and a match made only of lower-case words joined by separators
// is a phrase for every vendor pattern.
//
// Canaries are built by construction; no real token in the repository.
import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText } from './index';
import { isPhrase } from './placeholder';

const j = (...parts: string[]): string => parts.join('');
const PYPI = 'PyPI Upload Token';

// Token-shaped canaries: the real macaroon prefixes, then a generated body.
const BODY = j('Qx7Lm2Vb9Tz4Kp3W', 'n8Rd5Hc6Yf1Gs0Jb', 'e2Ua9Mi4Xo7Pl3Kt', 'r6Zw1Nq8Dv5');
const TOKEN_PYPI = j('pypi-', 'AgEIcHlwaS5vcmc', BODY);
const TOKEN_TEST_PYPI = j('pypi-', 'AgENdGVzdC5weXBpLm9yZw', BODY);

// The URL from the issue, and other slugs of the same shape.
const SLUGS = [
  j(
    'https://www.bleepingcomputer.example/news/security/popular-litellm-',
    'pypi-package-backdoored-to-steal-credentials-auth-tokens/'
  ),
  j('https://blog.example/2026/', 'pypi-trusted-publishing-explained-for-maintainers-and-teams'),
  j('docs/', 'pypi-upload-guide-for-first-time-package-authors-and-contributors', '.md'),
  j('feature/', 'pypi-release-workflow-with-attestations-and-provenance-checks'),
  j('pypi-', 'mirror_cache_refresh_job_for_internal_packages_and_wheels'),
  // Mixed case and digits, still not a macaroon.
  j('https://x.example/', 'pypi-Package-Index-Mirror-2026-Q3-Rollout-Plan-And-Checklist-v2'),
];

describe('PyPI: a slug is not a token', () => {
  it.each(SLUGS)('quiet at all three entrypoints: %s', (text) => {
    expect(scanArgs({ url: text })).toBeNull();
    expect(scanText(`see ${text} for details`)).toBeNull();
    const input = `see ${text} for details`;
    const r = redactText(input);
    expect(r.found).toEqual([]);
    expect(r.result).toBe(input);
  });
});

describe('PyPI: a token-shaped canary still matches', () => {
  it.each([
    ['pypi.org', TOKEN_PYPI],
    ['test.pypi.org', TOKEN_TEST_PYPI],
  ])('%s', (_name, token) => {
    expect(scanArgs({ command: `twine upload -p ${token} dist/*` })?.patternName).toBe(PYPI);
    expect(scanText(`password = ${token}`)?.patternName).toBe(PYPI);
    const r = redactText(`TWINE_PASSWORD=${token}`);
    expect(r.found).toContain(PYPI);
    expect(r.result).not.toContain(token);
  });

  it('a token inside a URL-looking line is still found', () => {
    expect(scanText(`https://upload.example/legacy/?t=${TOKEN_PYPI}`)?.patternName).toBe(PYPI);
  });
});

describe('the same rule for the other prefix-plus-run patterns', () => {
  it.each([
    ['OpenAI prefix', j('sk-', 'learn-how-to-rotate-api-keys-safely')],
    ['Slack prefix', j('xoxb-', 'migration-notes-for-the-new-bot-scopes')],
    ['GitLab prefix', j('glpat-', 'rotation-policy-docs')],
  ])('a phrase after a vendor prefix is quiet: %s', (_name, text) => {
    expect(scanText(`https://docs.example/${text}/`)).toBeNull();
    expect(redactText(`https://docs.example/${text}/`).found).toEqual([]);
  });

  it.each([
    ['OpenAI', j('sk-', 'Xm7Kp3Qn9Bt2Vc6Wr1Ys4Zh8Pq5Nv3Mt'), 'OpenAI API Key'],
    ['Slack', j('xoxb-', '5182736490-', 'Km3Pq7Xn2Bt'), 'Slack Bot Token'],
    // Lower case with digits: generated, not a phrase.
    ['OpenAI, lower case and digits', j('sk-', 'k3m9-x7q2-v8n4-b1z6-w5t0'), 'OpenAI API Key'],
  ])('a generated body after the same prefix is reported: %s', (_name, text, pattern) => {
    expect(scanText(text)?.patternName).toBe(pattern);
  });
});

describe('isPhrase', () => {
  it.each(['package-backdoored-to-steal-credentials', 'my_internal_tool_name', 'docs.guide.intro'])(
    'a phrase: %s',
    (s) => expect(isPhrase(s)).toBe(true)
  );

  it.each([
    ['two words', 'hello-world'],
    ['a digit', 'release-notes-2026'],
    ['a capital', 'Release-notes-draft'],
    ['one run', 'abcdefghijklmnop'],
    ['generated', 'k3m9-x7q2-v8n4'],
    ['a long run of letters after two short parts', `dp.pt.${'qxzbhdmnplkv'.repeat(4)}`],
    ['empty', ''],
  ])('not a phrase: %s', (_name, s) => expect(isPhrase(s)).toBe(false));
});

describe('a password a person chose is not judged as a phrase', () => {
  it('a passphrase in a connection string is still reported', () => {
    const url = j('postgres://app:', 'correct-horse-battery-staple', '@db.internal:5432/app');
    expect(scanText(url)?.patternName).toBe('Database Connection String');
  });
});

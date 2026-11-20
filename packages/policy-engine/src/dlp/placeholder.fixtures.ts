// packages/policy-engine/src/dlp/placeholder.fixtures.ts
// The placeholder corpus (node9Firewall#301, DLP-1). Written BEFORE the
// predicate; placeholder.spec.ts derives every row from it and runs each one
// through the three raw entrypoints (scanArgs, scanText, redactText).
//
// A row is a real SHAPE, never a real credential. Every token is built by
// construction so the checkout holds no contiguous credential-shaped literal.
//
// `report` is the pattern that must be reported, or null when the text is a
// placeholder and must stay quiet. `was` records what the build before the fix
// did, so the flipped rows are visible as the acceptance of the issue.

export interface PlaceholderRow {
  id: string;
  text: string;
  report: string | null;
  /** The verdict of the build before the fix: 'missed', 'reported' or 'quiet'. */
  was: 'missed' | 'reported' | 'quiet';
  why: string;
}

const j = (...parts: string[]): string => parts.join('');

// A 12-character generated password, and bodies with no word inside.
const PW = j('Qx7', 'Lm2', 'Vb9', 'Tz4');
const BODY27 = j('Qx7Lm2Vb9Tz4', 'Kp3Wn8Rd5Hc6', 'Yf1');

export const AWS = 'AWS Access Key ID';
export const DB = 'Database Connection String';
export const BEARER = 'Bearer Token';

/** A real-shaped AWS key, no word inside: the known-true control. */
export const AWS_REAL = j('AKIA', 'QX7Z3BHD', 'M7NPLKV5');
/** AWS's documentation key: ends in the word EXAMPLE. */
export const AWS_DOC = j('AKIA', 'IOSFODNN7', 'EXAMPLE');

export const PLACEHOLDER_CORPUS: PlaceholderRow[] = [
  // ── Positives: a stopword INSIDE real material is not a placeholder ───────
  {
    id: 'aws-here-inside',
    text: j('AKIA', 'HERE', 'QX7Z3BHD', 'M7NP'),
    report: AWS,
    was: 'missed',
    why: 'the inventory row: `here` in the middle of a key',
  },
  {
    id: 'aws-your-inside',
    text: j('AKIA', 'QX7Z', 'YOUR', '3BHDM7NP'),
    report: AWS,
    was: 'missed',
    why: '`your` in the middle of a key',
  },
  {
    id: 'stripe-here-inside',
    text: j('sk_', 'live_', 'Qx7Lm2Vb9', 'here', 'Kp3Wn8Rd5Hc'),
    report: 'Stripe Secret Key',
    was: 'missed',
    why: 'lower-case word between a digit and a capital: a case boundary is not a separator',
  },
  {
    id: 'slack-fake-inside',
    text: j('xoxb-', '5182736490-', 'Km3Pq7', 'fake', 'Xn2Bt'),
    report: 'Slack Bot Token',
    was: 'missed',
    why: '`fake` inside the last part of a token that has separators',
  },
  {
    id: 'openai-dummy-inside',
    text: j('sk-', 'Xm7Kp3Qn9Bt2', 'dummy', 'Vc6Wr1Ys4Zh8Pq5'),
    report: 'OpenAI API Key',
    was: 'missed',
    why: '`dummy` inside the body',
  },
  {
    id: 'openai-example-inside',
    text: j('sk-', 'Xm7Kp3Qn9', 'example', 'Bt2Vc6Wr1Ys4'),
    report: 'OpenAI API Key',
    was: 'missed',
    why: '`example` in the middle, not at either end',
  },
  {
    id: 'gcp-sample-inside',
    text: j('AIza', 'Sy7Kp3Qn9Bt2', 'sample', 'Vc6Wr1Ys4Zh8Pq5Nv'),
    report: 'GCP API Key',
    was: 'missed',
    why: '`sample` inside the body',
  },
  {
    id: 'bearer-here-inside',
    text: j('Bearer ', 'Qx7Lm2Vb9', 'here', 'Tz4Kp3Wn8Rd5Hc6'),
    report: BEARER,
    was: 'missed',
    why: 'a JWT payload or an opaque token can carry a word',
  },
  {
    id: 'cloudinary-cloud-named-sample',
    text: j('cloudinary://', '123456789012345', ':', BODY27, '@sample-cloud'),
    report: 'Cloudinary URL',
    was: 'missed',
    why: 'the cloud name is chosen by the writer; only the API secret is judged',
  },
  {
    id: 'cloudinary-cloud-named-your',
    text: j('cloudinary://', '123456789012345', ':', BODY27, '@your-team'),
    report: 'Cloudinary URL',
    was: 'missed',
    why: 'same, with `your`',
  },
  {
    id: 'npm-token-here-inside',
    text: j('//registry.npmjs.org/:_authToken=', 'Qx7Lm2Vb9', 'here', 'Tz4Kp3Wn8Rd5'),
    report: 'NPM Auth Token',
    was: 'missed',
    why: '`here` inside the token value',
  },
  {
    id: 'conn-password-here-inside',
    text: j('postgres://admin:', 'Qx7Lm2', 'here', 'Vb9', '@db.internal/prod'),
    report: DB,
    was: 'missed',
    why: 'a real password can contain a word',
  },
  {
    id: 'conn-password-your-inside',
    text: j('postgres://admin:', 'Qx7', 'your', 'Lm2Vb9', '@db.internal/prod'),
    report: DB,
    was: 'missed',
    why: 'same, with `your`',
  },
  {
    id: 'conn-host-atmosphere',
    text: j('postgres://admin:', PW, '@atmosphere.internal/prod'),
    report: DB,
    was: 'reported',
    why: 'the writer chooses the host (closed by fw#372 A6, pinned here)',
  },
  {
    id: 'conn-host-example',
    text: j('postgres://admin:', PW, '@example.evil-host.net/prod'),
    report: DB,
    was: 'reported',
    why: 'same, `example` as a host label',
  },
  {
    id: 'conn-user-your-app',
    text: j('postgres://your_app:', PW, '@db.internal/prod'),
    report: DB,
    was: 'reported',
    why: 'the writer chooses the user name too',
  },
  {
    id: 'placeholder-then-real',
    text: j(AWS_DOC, ' ', AWS_REAL),
    report: AWS,
    was: 'reported',
    why: 'a placeholder next to a real key does not hide the real one',
  },

  // ── Controls: placeholders stay quiet ──────────────────────────────────────
  {
    id: 'aws-doc-key',
    text: AWS_DOC,
    report: null,
    was: 'quiet',
    why: 'the AWS documentation key ends in EXAMPLE',
  },
  {
    id: 'aws-x-run',
    text: j('AKIA', 'X'.repeat(16)),
    report: null,
    was: 'quiet',
    why: 'one character fills the body',
  },
  {
    id: 'openai-your-key-here',
    text: j('sk-', 'your-openai-api-key-here'),
    report: null,
    was: 'quiet',
    why: '`your` and `here` stand as words between separators',
  },
  {
    id: 'openai-a-run',
    text: j('sk-', 'a'.repeat(24)),
    report: null,
    was: 'quiet',
    why: 'filler',
  },
  {
    id: 'openai-masked-tail',
    text: j('sk-', 'Qx7Lm2', 'x'.repeat(20)),
    report: null,
    was: 'quiet',
    why: 'a masked value: a run of one character',
  },
  {
    id: 'openai-fake-key-for-testing',
    text: j('sk-', 'fake-key-for-testing-1234567890'),
    report: null,
    was: 'quiet',
    why: '`fake` stands as a word; the rest need not be vocabulary',
  },
  {
    id: 'slack-your-token',
    text: j('xoxb-', 'your-slack-bot-token-here'),
    report: null,
    was: 'quiet',
    why: 'vendor words around `your` do not make it real',
  },
  {
    id: 'stripe-x-run',
    text: j('sk_', 'test_', 'x'.repeat(24)),
    report: null,
    was: 'quiet',
    why: 'filler after a real prefix',
  },
  {
    id: 'bearer-your-token-here',
    text: j('Bearer ', 'YOUR_ACCESS_TOKEN_HERE'),
    report: null,
    was: 'quiet',
    why: 'built from placeholder vocabulary',
  },
  {
    id: 'bearer-camel-placeholder',
    text: j('Bearer ', 'yourAccessTokenGoesHere'),
    report: null,
    was: 'quiet',
    why: 'camel case splits into words; `your` ... `here` is the documentation form',
  },
  {
    id: 'bearer-x-run',
    text: j('Bearer ', 'x'.repeat(20)),
    report: null,
    was: 'quiet',
    why: 'filler',
  },
  {
    id: 'bearer-changeme',
    text: j('Bearer ', 'changeme'.repeat(3)),
    report: null,
    was: 'quiet',
    why: 'starts (and ends) with a doc word',
  },
  {
    id: 'conn-template-dollar',
    text: j('postgres://user:', '${DB_PASSWORD}', '@db.internal/app'),
    report: null,
    was: 'quiet',
    why: 'a template variable is not a value',
  },
  {
    id: 'conn-template-angle',
    text: j('redis://:', '<your-password>', '@cache.internal:6379'),
    report: null,
    was: 'quiet',
    why: 'an angle-bracket slot',
  },
  {
    id: 'conn-your-password',
    text: j('postgres://user:', 'your_password', '@localhost/db'),
    report: null,
    was: 'quiet',
    why: 'built from placeholder vocabulary',
  },
  {
    id: 'conn-password-is-password',
    text: j('export DATABASE_URL=postgres://user:', 'password', '@localhost/db'),
    report: null,
    was: 'reported',
    why: 'a README line: the password IS the word `password` (a false block before the fix)',
  },
  {
    id: 'conn-password-starts-with-doc-word',
    text: j('postgres://dbadmin:', 'example', 'pass123', '@db.internal:5432/app'),
    report: null,
    was: 'quiet',
    why: 'a fixture password opens with a doc word (seen in real transcripts)',
  },
  {
    id: 'conn-password-changeme',
    text: j('mysql://root:', 'changeme', '@127.0.0.1:3306/app'),
    report: null,
    was: 'quiet',
    why: 'a doc word',
  },
  {
    id: 'npm-token-placeholder',
    text: j('//registry.npmjs.org/:_authToken=', 'YOUR_NPM_TOKEN_GOES_HERE'),
    report: null,
    was: 'quiet',
    why: '`your` and `here` stand as words',
  },
];

import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText } from './index';
import { inspectArgumentSecrets, scanArgumentSecrets } from './arguments';

// Credential shapes the argument gate missed on the public split of a
// benchmark of labelled credential lines: an HTTP Basic value, the secret of
// an OTP constructor, JSON escaped inside a string literal, and names outside
// the first keyword list. Every value is synthetic and assembled at runtime,
// so no secret-shaped literal lives in the source.

const gate = (args: unknown) => scanArgumentSecrets(args);
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

const PASSWORD = ['q7Rk', '2xVm', '9pLw', '4tZb'].join(''); // 16, letters and digits
const GENERATED = ['Ghq', 'ylh3N', 'Fbs1jC', '_26Vo', 'Q9'].join('');
const BASE32 = ['KQZC', 'W4NX', 'RDTV', '6MJP'].join(''); // 16, base32 alphabet
// Lower case, digits and dashes: a generated token that the joined-words rule
// would misread once its digits are stripped.
const DASHED = ['k7d2q9x4', 'm8w1z6p3', '-44v9t7d2', '-7kvu3x95'].join('');

describe('HTTP Basic Credential', () => {
  it('reviews a Basic value that decodes to user:generated-password', () => {
    for (const text of [
      `Authorization: Basic ${b64(`svc-deploy:${PASSWORD}`)}`,
      `      - Basic ${b64(`ops:${PASSWORD}-${PASSWORD.slice(0, 6)}`)}`,
      `      - Basic ${b64(`fat:${DASHED}`)}`,
      `curl -H 'authorization: basic ${b64(`ci:${PASSWORD}`)}' https://api.example.test`,
    ]) {
      const m = gate({ content: text });
      expect(m?.patternName, text).toBe('HTTP Basic Credential');
      expect(m?.severity).toBe('review');
      expect(m?.redactedSample).not.toContain(b64(`ci:${PASSWORD}`).slice(4, -4));
    }
  });

  it('leaves prose, documentation pairs and values that are not user:password alone', () => {
    for (const text of [
      'Basic authentication is configured in the settings page',
      `Authorization: Basic ${b64('user:password')}`,
      `Authorization: Basic ${b64('admin:changeme')}`,
      `Authorization: Basic ${b64('user:pass1234')}`,
      `Authorization: Basic ${b64('test:test')}`,
      `Authorization: Basic ${b64(`no-colon-${PASSWORD}`)}`,
      `Authorization: Basic ${b64('svc:abcdefghij')}`,
      'Authorization: Basic ${BASIC_AUTH}',
      'Basic Configuration',
    ]) {
      expect(gate({ content: text }), text).toBeNull();
    }
  });

  it('a decoded value with a control character is not a credential', () => {
    const v = Buffer.from(`svc:${PASSWORD}\u0001`, 'utf8').toString('base64');
    expect(gate({ content: `Basic ${v}` })).toBeNull();
  });
});

// node9Firewall#385: behind an Authorization header a person's password counts.
describe('HTTP Basic Credential in an Authorization header', () => {
  const WORDS = ['mor', 'ning', 'glory', 'river'].join(''); // letters only
  const SHORT = ['k3', 'v9', 'xq'].join(''); // six characters

  it('reviews a header whose value decodes to a user and a human password', () => {
    for (const text of [
      `Authorization: Basic ${b64(`deploy:${WORDS}`)}`,
      `curl -H "Authorization: Basic ${b64(`ci:${SHORT}`)}" https://api.example.test`,
      `{"headers": {"Authorization": "Basic ${b64(`jenkins:${WORDS}7`)}"}}`,
      `headers = {'authorization': 'Basic ${b64(`bot:${WORDS}`)}'}`,
    ]) {
      const m = gate({ content: text });
      expect(m?.patternName, text).toBe('HTTP Basic Credential');
      expect(m?.severity).toBe('review');
    }
  });

  it('still leaves documentation pairs alone', () => {
    for (const text of [
      `Authorization: Basic ${b64('user:password')}`,
      `Authorization: Basic ${b64('admin:admin123')}`,
      `Authorization: Basic ${b64('alice:alice')}`,
      `Authorization: Basic ${b64('svc:qwerty99')}`,
      `Authorization: Basic ${b64('svc:aaaaaaaa')}`,
      `Authorization: Basic ${b64('svc:12345678')}`,
      `Authorization: Basic ${b64('svc:abc')}`,
      `Authorization: Basic ${b64(`svc:your${WORDS}`)}`,
    ]) {
      expect(gate({ content: text }), text).toBeNull();
    }
  });

  it('a bare Basic value keeps the generated-password rule', () => {
    expect(gate({ content: `      - Basic ${b64(`deploy:${WORDS}`)}` })).toBeNull();
  });
});

// node9Firewall#385: a Dropbox app secret has no prefix; its name says what it is.
describe('Dropbox App Secret', () => {
  const SECRET = ['k7d2q', '9x4m8', 'w1z6p'].join(''); // 15, lower case and digits

  it('blocks the secret under its own names', () => {
    for (const text of [
      `DROPBOX_APP_SECRET=${SECRET}`,
      `dropbox_secret: "${SECRET}"`,
      `"app_secret": "${SECRET}"`,
      `dropboxClientSecret = '${SECRET}'`,
      `APP_SECRET=${SECRET}`,
      `{"dropbox": {"app_key": "x", "appSecret": "${SECRET}"}}`,
    ]) {
      const m = gate({ content: text });
      expect(m?.patternName, text).toBe('Dropbox App Secret');
      expect(m?.severity).toBe('block');
      expect(m?.redactedSample).not.toContain(SECRET.slice(3, -3));
    }
  });

  it('leaves other lengths, upper case, words and placeholders alone', () => {
    for (const text of [
      `app_secret = "${SECRET}abc"`, // 18
      `app_secret = "${SECRET.toUpperCase()}"`,
      'app_secret = "abcdefghijklmno"',
      'app_secret = "xxxxxxxxxxxxxxx"',
      'app_secret = "dropboxsecretxy"',
      `dropbox_app_key = "${SECRET}"`,
    ]) {
      const m = gate({ content: text });
      expect(m?.patternName, text).not.toBe('Dropbox App Secret');
    }
  });
});

describe('OTP Secret', () => {
  it('reviews the secret of an OTP constructor in Ruby, Python and JavaScript', () => {
    for (const text of [
      `otp = ROTP::TOTP.new('${BASE32}')`,
      `let(:totp) { ROTP::TOTP.new '${BASE32}' }`,
      `otp = ROTP::HOTP.new("${BASE32}", digits: 8)`,
      `totp = pyotp.TOTP("${BASE32}${BASE32}")`,
      `const totp = new TOTP('${BASE32}')`,
    ]) {
      const m = gate({ content: text });
      expect(m?.patternName, text).toBe('OTP Secret');
      expect(m?.severity).toBe('review');
    }
  });

  it('leaves references, tutorial secrets, runs and non-base32 values alone', () => {
    const tutorial = ['JBSW', 'Y3DP', 'EHPK', '3PXP'].join('');
    for (const text of [
      'totp = pyotp.TOTP(user.otp_secret)',
      'ROTP::TOTP.new(secret, issuer: "Acme")',
      `totp = pyotp.TOTP('${tutorial}')`,
      "TOTP('AAAAAAAAAAAAAAAA')",
      "TOTP('ABCDEFGHIJKLMNOP')",
      "TOTP('not-base32-at-all!')",
      'const code = totp.generate(); // 6 digits like 123456',
    ]) {
      expect(gate({ content: text }), text).toBeNull();
    }
  });

  it('the tutorial secret is not a credential in the otpauth form either', () => {
    const tutorial = ['JBSW', 'Y3DP', 'EHPK', '3PXP'].join('');
    expect(gate({ url: `otpauth://totp/Acme:alice?secret=${tutorial}&issuer=Acme` })).toBeNull();
    expect(gate({ url: `otpauth://totp/Acme:alice?secret=${BASE32}&issuer=Acme` })).not.toBeNull();
  });
});

describe('Assigned Secret: JSON escaped inside a string literal', () => {
  it('reviews an escaped "name":"value" pair', () => {
    const text = `final String body = "{ \\"access_token\\":\\"${GENERATED}\\", \\"expires_in\\": 3600 }";`;
    expect(gate({ content: text })?.patternName).toBe('Assigned Secret');
  });

  it('leaves an escaped pair with a placeholder or a reference alone', () => {
    expect(
      gate({ content: 'String b = "{ \\"access_token\\":\\"your_token_here\\" }";' })
    ).toBeNull();
    expect(gate({ content: 'String b = "{ \\"access_token\\":\\"${TOKEN}\\" }";' })).toBeNull();
  });
});

describe('Assigned Secret: wider name vocabulary', () => {
  it('reviews consumer and app keys, signing, encryption and master keys, a jsapi ticket, a *_PASS', () => {
    for (const text of [
      `CONSUMER_KEY=${GENERATED}`,
      `config.consumer_key = '${GENERATED}'`,
      `oauth: { consumer_key: '${GENERATED}' }`,
      `APP_KEY=${GENERATED}`,
      `signingKey: "${GENERATED}"`,
      `ENCRYPTION_KEY=${GENERATED}`,
      `master_key = "${GENERATED}"`,
      `jsapi_ticket = '${GENERATED}'`,
      `DEPLOY_PASS=${GENERATED}`,
      `"pass": "${GENERATED}"`,
    ]) {
      expect(gate({ content: text })?.patternName, text).toBe('Assigned Secret');
    }
  });

  it('pass inside another word, short values, derivatives and code stay allowed', () => {
    for (const text of [
      `bypass: ${GENERATED}`,
      `compass_version: ${GENERATED}`,
      `passthrough = "${GENERATED}"`,
      'DEPLOY_PASS=wqkrtzma',
      `encryptionKeyFingerprint: "${GENERATED}"`,
      `"signingKeyThumbprint": "${GENERATED}"`,
      "ENCRYPTION_KEY='+secrets.token_hex(16)",
      'APP_KEY=base64:${APP_KEY}',
      `master_key_id = "${GENERATED}"`,
    ]) {
      expect(gate({ content: text }), text).toBeNull();
    }
  });

  it('dbpassword is still a password (the start-of-part rule is for pass alone)', () => {
    expect(gate({ content: `dbpassword=${GENERATED}` })?.patternName).toBe('Assigned Secret');
  });

  it('a word containing pass does not hide the keyword after it (review finding)', () => {
    for (const text of [
      `PASSPORT_CLIENT_SECRET=${GENERATED}`,
      `PASSPORT_PRIVATE_KEY=${GENERATED}`,
      `passport_token: '${GENERATED}'`,
      `bypass_token=${GENERATED}`,
      `COMPASS_API_KEY=${GENERATED}`,
    ]) {
      expect(gate({ content: text })?.patternName, text).toBe('Assigned Secret');
    }
  });
});

describe('the new shapes are gate-only and stay linear', () => {
  it('raw scanners, output redaction and response text do not use them', () => {
    const text = `Authorization: Basic ${b64(`svc:${PASSWORD}`)}\notp = ROTP::TOTP.new('${BASE32}')`;
    expect(scanText(text)).toBeNull();
    expect(scanArgs({ prompt: text })).toBeNull();
    expect(redactText(text).found).toEqual([]);
  });

  it('is found through nested fields', () => {
    const r = inspectArgumentSecrets({ a: [{ b: `ROTP::TOTP.new('${BASE32}')` }] });
    expect(r.match?.patternName).toBe('OTP Secret');
    expect(r.coverage).toBe('complete');
  });

  it('long runs of the new keywords finish quickly', () => {
    for (const word of ['Basic ', 'TOTP(', 'pass=', 'consumer_key', '\\"token\\":\\"']) {
      const text = word.repeat(Math.ceil(200_000 / word.length));
      const start = performance.now();
      gate({ content: text });
      expect(performance.now() - start, word).toBeLessThan(500);
    }
  });
});

describe('shapes from the CredData review (fw#372 B4, node9Firewall#385)', () => {
  // All synthetic. The cipher key and the Laravel key are random bytes
  // base64-encoded at test time, so no key-shaped literal lives in the source.
  const aes128 = Buffer.from(Array.from({ length: 16 }, (_, i) => (i * 37 + 11) % 251)).toString(
    'base64'
  );
  const aes256 = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 53 + 7) % 241)).toString(
    'base64'
  );
  const MIXED12 = ['x7', 'Kq', '2m', 'Zp', '9r', 'Tw'].join(''); // letters and digits, 12 long
  const GRAFANA = Buffer.from(
    '{"k":"' + ['Zm1', 'Qa9', 'kL3', 'pR7', 'vB2', 'nX8'].join('') + '","n":"ci","id":1}'
  ).toString('base64');

  it('a 16-byte base64 literal under a key name is a cipher key; a public key or a word is not', () => {
    expect(gate({ content: `cipherKey = "${aes128}"` })?.patternName).toBe('Cipher Key Literal');
    expect(
      gate({ content: `private static final String ENC_KEY = "${aes128}";` })?.patternName
    ).toBe('Cipher Key Literal');
    expect(gate({ content: `publicKey = "${aes128}"` })).toBeNull();
    expect(gate({ content: `cipherKey = "${'a'.repeat(22)}=="` })).toBeNull();
    expect(gate({ content: `testKey = "${aes128}"` })).toBeNull();
    for (const name of ['cacheKey', 'idempotencyKey', 'requestKey', 'monkey']) {
      expect(gate({ content: `${name} = "${aes128}"` }), name).toBeNull();
    }
    expect(gate({ content: `rememberMeCipherKey = "${aes128}"` })?.patternName).toBe(
      'Cipher Key Literal'
    );
  });

  it('Laravel APP_KEY, a Mailgun key, a kubeadm token and a SQL account password are reviews', () => {
    expect(gate({ content: `APP_KEY=base64:${aes256}` })?.patternName).toBe('Laravel App Key');
    expect(gate({ content: 'APP_KEY=base64:' + 'A'.repeat(43) + '=' })).toBeNull();
    expect(gate({ content: `MAILGUN_KEY=key-${'3f9a'.repeat(8)}` })?.patternName).toBe(
      'Mailgun API Key'
    );
    expect(
      gate({ content: 'kubeadm join 10.0.0.1:6443 --token abcdef.0123456789abcdef' })?.patternName
    ).toBe('Kubeadm Bootstrap Token');
    expect(gate({ content: 'the file abcdef.0123456789abcdef is a cache entry' })).toBeNull();
    expect(
      gate({ content: `CREATE USER 'app'@'%' IDENTIFIED BY '${MIXED12}!'` })?.patternName
    ).toBe('SQL Account Password');
    expect(gate({ content: `CREATE ROLE app WITH PASSWORD '${MIXED12}'` })?.patternName).toBe(
      'SQL Account Password'
    );
    expect(gate({ content: "CREATE USER 'app'@'%' IDENTIFIED BY 'changeme'" })).toBeNull();
    expect(gate({ content: "CREATE USER 'app'@'%' IDENTIFIED BY 'password'" })).toBeNull();
    expect(gate({ content: "IDENTIFIED BY '${DB_PASSWORD}'" })).toBeNull();
  });

  it('a Grafana API key blocks, in arguments and in text', () => {
    expect(gate({ content: `Authorization: Bearer ${GRAFANA}` })?.patternName).toBe(
      'Grafana API Key'
    );
    expect(scanText(`GF_KEY=${GRAFANA}`)?.patternName).toBe('Grafana API Key');
    const notGrafana = Buffer.from('{"k":"short","n":"x"}').toString('base64');
    expect(scanText(`x=${notGrafana}`)).toBeNull();
  });

  it('a PGP private key block and a DSA or encrypted PEM header block', () => {
    for (const header of [
      '-----BEGIN PGP PRIVATE KEY BLOCK-----',
      '-----BEGIN DSA PRIVATE KEY-----',
      '-----BEGIN ENCRYPTED PRIVATE KEY-----',
    ]) {
      expect(scanText(header + '\nabc\n')?.patternName, header).toBe('Private Key (PEM)');
    }
    expect(scanText('-----BEGIN PGP PUBLIC KEY BLOCK-----')).toBeNull();
  });

  it('Assigned Secret: aes/cipher/subscription key names, a backtick, a pipe, an escaped slash, and the mixed-value floor', () => {
    for (const text of [
      `AES_KEY=${GENERATED}`,
      `cipher_key: '${GENERATED}'`,
      `subscriptionKey = "${GENERATED}"`,
      '`password`: "' + GENERATED + '"',
      `password = "${GENERATED}|${MIXED12}"`,
      `"token":"ab12\\/${GENERATED}"`,
      // Letters and digits at 3.0 bits per character: a 12-character token of
      // the shape many services issue, which the 3.5 floor rejected.
      `secret = "${MIXED12}"`,
    ]) {
      expect(gate({ content: text })?.patternName, text).toBe('Assigned Secret');
    }
    expect(gate({ content: `PUBLIC_KEY=${GENERATED}` })).toBeNull();
    expect(gate({ content: 'secret = "abcdefghijkl"' })).toBeNull(); // letters only keep the 3.5 floor
  });
});

describe('the output scan reads decoded views (fw#372 B7)', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n';
  it('a PEM header encoded in base64 or hex in tool output is a finding', () => {
    expect(scanText('blob: ' + Buffer.from(pem).toString('base64'))?.patternName).toBe(
      'Private Key (PEM)'
    );
    expect(scanText('hex: ' + Buffer.from(pem).toString('hex'))?.patternName).toBe(
      'Private Key (PEM)'
    );
    expect(scanText('blob: ' + Buffer.from(pem).toString('base64'))?.redactedSample).toBe(
      '[encoded secret]'
    );
  });
  it('ordinary encoded text is not', () => {
    expect(
      scanText(
        'blob: ' + Buffer.from('hello world, this is a plain paragraph of text').toString('base64')
      )
    ).toBeNull();
    expect(scanText('sha256: ' + 'ab'.repeat(32))).toBeNull();
  });
});

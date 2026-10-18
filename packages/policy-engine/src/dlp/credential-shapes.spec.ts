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
      `dbPass: '${GENERATED}'`,
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

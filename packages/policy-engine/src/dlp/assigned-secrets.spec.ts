import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText } from './index';
import { inspectArgumentSecrets, scanArgumentSecrets } from './arguments';

// The bounded argument gate: the only entry point that uses the context patterns.
const gate = (args: unknown) => scanArgumentSecrets(args);

// Name-based patterns from node9Firewall#348: a credential in a URL query
// value and a secret assigned to a telling name. Every value below is
// synthetic and assembled at runtime so no secret-shaped literal lives in
// the source.

const GENERATED = ['Ghq', 'ylh3N', 'Fbs1jC', '_26Vo', 'Q9'].join(''); // 19 chars, letters and digits
const HEX32 = ['62a3e889', '50d5d314', 'd4c71f32', '9d7b31dc'].join('');
const OTP = ['VWAAV3ZC', 'UNSK2OBA'].join(''); // base32, 16 chars
const OTP_LONG = ['QJAMKITDWZ', 'PDTY4MZIYU', '2PHAKGSJVYNW'].join('');

describe('Credential in URL Query', () => {
  it('reviews a generated value under a secret-naming query key', () => {
    const m = gate({ url: `https://api.example.test/v1/users?q=1&apiKey=${HEX32}` });
    expect(m?.patternName).toBe('Credential in URL Query');
    expect(m?.severity).toBe('review');
    expect(m?.redactedSample).not.toContain(HEX32.slice(4, -4));
  });

  it('reviews the secret of an otpauth URI, letters-only base32 included', () => {
    for (const secret of [OTP, OTP_LONG, 'GYKNEFFDCUPMVEZB']) {
      const m = gate({
        content: `expect(uri).to eq 'otpauth://totp/Big%20Corp:alice%40bigco.test?secret=${secret}&issuer=Big%20Corp'`,
      });
      expect(m?.patternName, secret).toBe('Credential in URL Query');
    }
  });

  it('finds the value in a query fragment without a scheme', () => {
    expect(gate({ content: `@"&secret=${OTP_LONG}";` })?.patternName).toBe(
      'Credential in URL Query'
    );
  });

  it('leaves fixtures, placeholders, slugs and short values alone', () => {
    const benign = [
      'GET /user/{name}?token=ftoken123&id=1',
      'https://api.example.test/repos?state=open&page=2&per_page=30&sort=updated',
      'https://example.test/login?username=admin&password=958017',
      'https://example.test/cb?access_token=${ACCESS_TOKEN}&state=xyz',
      'https://example.test/cb?token=your_token_here',
      'https://example.test/search?q=how+to+fix+error&key=placeholder',
      'https://example.test/api?secret=client-secret-value',
      'https://example.test/x?signature=sha256',
    ];
    for (const text of benign) expect(gate({ url: text }), text).toBeNull();
  });

  it('is a gate-only pattern: raw scanners, output redaction and response text do not use it', () => {
    const text = `https://api.example.test/v1?apiKey=${HEX32}`;
    expect(redactText(text).found).toEqual([]);
    expect(scanText(text)).toBeNull();
    expect(scanArgs({ prompt: text })).toBeNull();
  });
});

describe('Assigned Secret', () => {
  it('reviews a generated value assigned to a secret-naming variable', () => {
    const lines = [
      `JWT_SECRET=${GENERATED}`,
      `export SURGE_TOKEN=${HEX32}`,
      `  password: ${GENERATED}`,
      `"api_key": "${GENERATED}",`,
      `$config['client_secret'] = '${GENERATED}';`,
      `MYSQL_ROOT_PASSWORD=${['gdki', '1450', '01Xq', 'Zt7'].join('')}`,
      `aws_secret_access_key: ${['QDPLGJUZ', 'AINK4HVY', 'ZEBH7UHQ', 'QEVANQ1T', 'SA2TTAHT'].join('')}`,
      `'passphrase' => '${GENERATED}'`,
    ];
    for (const line of lines) {
      const m = gate({ content: line });
      expect(m?.patternName, line).toBe('Assigned Secret');
      expect(m?.severity, line).toBe('review');
    }
  });

  it('leaves references, identifiers, words, placeholders and short values alone', () => {
    const benign = [
      'self.password = friendly_token',
      'const token = process.env.GITHUB_TOKEN',
      "password = os.environ['DB_PASSWORD']",
      'c.Providers.Google.ClientSecret = c.ClientSecretLegacy',
      'newPassword: registerPasswordValidation',
      'traefik-forward-auth-secret: base64-something-random',
      'password: changeme-please-now',
      'API_KEY=your_api_key_here',
      'token = "${TOKEN}"',
      'PASSWORD=hunter2',
      'password: correcthorsebatterystaple',
      'JENKINS_PASS=dzdvnffv',
      '"password": "djabprxYdjpbbac",',
      'DATABASE_URL=postgres://user@host.test/db',
      'token_type=bearer&expires_in=3600',
      'secret: null',
      '# password: set in the vault, never here',
      'const secret = "0123456789abcdefghijklmnopqrstuv"',
      '"id_token":"id_123456789"',
      '$ MYSQL_USER=root MYSQL_PASSWORD= FILTER=integration npm test',
      `![overview](https://cdn.example.test/s/541p0kbq3pwone6/status.png?dl=1&token_hash=${GENERATED})`,
      `const FAKE_TOKEN = '${GENERATED}'`,
      `mockSecret: '${GENERATED}'`,
      `password_length: ${GENERATED}`,
      "login, password = 'someone@example.test', 'mlbbmimevm'",
    ];
    for (const text of benign) expect(gate({ content: text }), text).toBeNull();
  });

  it('does not reverse a checksum decision on a vendor-shaped look-alike', () => {
    // A GitHub token shape with a failing CRC32 is allowed on purpose.
    const lookalike = 'ghp_' + 'A'.repeat(30) + 'bcdef1';
    expect(gate({ content: `export GITHUB_TOKEN=${lookalike}` })).toBeNull();
    expect(gate({ url: `https://log.example.test/?token=${lookalike}` })).toBeNull();
  });

  it('yields to a block-severity match in the same text', () => {
    const key = ['AKIA', 'QX7Z3BHD', 'M7NPLKV5'].join('');
    const m = gate({ content: `AWS_ACCESS_KEY_ID=${key}\nJWT_SECRET=${GENERATED}` });
    expect(m?.severity).toBe('block');
    expect(m?.patternName).toBe('AWS Access Key ID');
  });

  it('is found through the bounded argument inspection and in nested fields', () => {
    const r = inspectArgumentSecrets({ a: { b: [`SESSION_SECRET=${GENERATED}`] } });
    expect(r.match?.patternName).toBe('Assigned Secret');
    expect(r.coverage).toBe('complete');
  });

  it('is a gate-only pattern: raw scanners, output redaction and response text do not use it', () => {
    const text = `password: ${GENERATED}`;
    expect(redactText(text).result).toBe(text);
    expect(scanText(text)).toBeNull();
    expect(scanArgs({ prompt: text })).toBeNull();
  });

  it('stays linear on long runs of a keyword', () => {
    for (const word of ['pwd', 'token', 'api_key', 'secret', 'password=']) {
      const text = word.repeat(Math.ceil(200_000 / word.length));
      const start = performance.now();
      gate({ content: text });
      expect(performance.now() - start, word).toBeLessThan(500);
    }
  });

  it('reviews a Go short variable declaration', () => {
    expect(gate({ content: `apiKey := "${GENERATED}"` })?.patternName).toBe('Assigned Secret');
  });

  it('leaves paths, ARNs, property references and longer words alone', () => {
    const benign = [
      'why does export PWD=/home/someone/project/packages break',
      '"pwd": "/Users/alice/dev/my-app2/src"',
      'cd ./build && TOKEN_FILE=~/secrets/token2.txt run',
      'aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/billing/stripe-api-Xy9Z1a',
      'tokenizer: "sentence-transformers/all-MiniLM-L6-v2"',
      'TOKENIZER=bert-base-uncased-v2x',
      'secretOrKey: jwtConstants.secretKey2024',
      'passwords: Xk9fQ2mZ7pLw4RtB8vN',
    ];
    for (const text of benign) expect(gate({ content: text }), text).toBeNull();
  });
});

describe('Database Connection String with a driver suffix', () => {
  it('blocks a SQLAlchemy-style scheme with an inline password', () => {
    const pw = ['idqg', 'Rt7', 'x'].join('');
    for (const scheme of ['mysql+pymysql', 'postgresql+psycopg2', 'mariadb+mariadbconnector']) {
      const m = gate({ content: `DATABASE_URI = '${scheme}://root:${pw}@db.test/app'` });
      expect(m?.patternName, scheme).toBe('Database Connection String');
      expect(m?.severity, scheme).toBe('block');
      expect(scanArgs({ content: `${scheme}://root:${pw}@db.test/app` })?.patternName).toBe(
        'Database Connection String'
      );
    }
  });

  it('still ignores a user-only URL and an http basic-auth URL', () => {
    expect(gate({ content: 'mysql+pymysql://root@db.test/app' })).toBeNull();
    expect(gate({ content: 'http://user:pass1234@peer1.test:8080/eureka/' })).toBeNull();
  });
});

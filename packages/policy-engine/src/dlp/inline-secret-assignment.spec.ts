import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText } from './index';
import { inspectArgumentSecrets, scanArgumentSecrets } from './arguments';

// CPU time of this test process, in ms (see assigned-secrets.spec.ts).
const cpuNow = (): number => {
  const u = process.cpuUsage();
  return (u.user + u.system) / 1000;
};

// The bounded argument gate, with the Bash tool's input shape.
const gate = (command: string) => scanArgumentSecrets({ command });

// node9Firewall#451: a known secret variable assigned a literal in a shell
// command. Every value is synthetic and assembled at runtime. The AWS value
// is the one AWS's own documentation uses as its example secret access key:
// it carries the stopword `example`, which is exactly why the shape-based
// Assigned Secret pattern let it through.
const AWS_EXAMPLE_SECRET = ['wJalrXUtnFEMI/', 'K7MDENG/bPxRfiCY', 'EXAMPLEKEY'].join('');
const GENERATED = ['Ghq', 'ylh3N', 'Fbs1jC', '_26Vo', 'Q9'].join(''); // 19, letters and digits
const DB_PASSWORD = ['Vq8', 'mT2', 'xp9', 'Lk'].join('');

describe('Inline Secret Assignment', () => {
  it('reviews the AWS example secret in the inline, export and env forms', () => {
    for (const command of [
      `AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET} aws s3 ls`,
      `export AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET} && aws s3 ls`,
      `env AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET} aws s3 ls`,
      `cd infra; AWS_SECRET_ACCESS_KEY="${AWS_EXAMPLE_SECRET}" terraform plan`,
    ]) {
      const m = gate(command);
      expect(m?.patternName, command).toBe('Inline Secret Assignment');
      expect(m?.severity, command).toBe('review');
      // The sample keeps the name and the last four characters only.
      expect(m?.redactedSample, command).not.toContain(AWS_EXAMPLE_SECRET.slice(0, 20));
    }
  });

  it('the name decides for a well-known variable: any literal, whatever its shape', () => {
    // Values the shape-based Assigned Secret leaves alone (short, a word,
    // letters only), so the finding can only come from the name.
    for (const command of [
      'GITHUB_TOKEN=abc gh api user',
      "GH_TOKEN='kq7' gh pr list",
      'NPM_TOKEN="abc123" npm publish',
      'AWS_SESSION_TOKEN=shortvalue aws sts get-caller-identity',
      'OPENAI_API_KEY=notarealkeybutliteral python app.py',
      'ANTHROPIC_API_KEY=some-words-joined node agent.js',
      "GITHUB_TOKEN='p$ss1' gh api user", // single quotes: `$` is a literal
      'docker run -e GITHUB_TOKEN=abc123 img', // an argument, the same handoff
    ]) {
      const m = gate(command);
      expect(m?.patternName, command).toBe('Inline Secret Assignment');
      expect(m?.severity, command).toBe('review');
    }
    // A generated value under the same names is still a finding, by either name.
    for (const command of [
      `GH_TOKEN='${GENERATED}' gh pr list`,
      `AWS_SESSION_TOKEN=${GENERATED}${GENERATED} aws sts get-caller-identity`,
      `ANTHROPIC_API_KEY=${GENERATED} node agent.js`,
    ]) {
      expect(gate(command)?.severity, command).toBe('review');
    }
  });

  it('a short value never shows whole in the sample', () => {
    expect(gate('GITHUB_TOKEN=abc gh api user')?.redactedSample).toBe('GITH****');
    expect(gate('GITHUB_TOKEN=1234567 gh api user')?.redactedSample).toBe('GITH****');
    const long = gate(`AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET} aws s3 ls`)?.redactedSample;
    expect(long).toMatch(/^AWS_\*+EKEY$/);
  });

  it('a suffix name needs a value that is not a word, not a dev default, 8 or longer', () => {
    for (const command of [
      `MY_SERVICE_PASSWORD=${DB_PASSWORD} docker compose up`,
      `DEPLOY_SECRET=${GENERATED} ./deploy.sh`,
      `CI_API_KEY="${GENERATED}" ./release.sh`,
      `SLACK_BOT_TOKEN=${GENERATED} npm start`,
    ]) {
      expect(gate(command)?.severity, command).toBe('review');
    }
    for (const command of [
      'MYSQL_ROOT_PASSWORD=root123 docker compose up',
      'POSTGRES_PASSWORD=postgres docker run postgres',
      'DB_PASSWORD=my-secret-pw docker compose up',
      'APP_SECRET=development npm run dev',
      `TEST_TOKEN=${GENERATED} npm test`,
      `FAKE_API_KEY=${GENERATED} npm test`,
      `PUBLIC_TOKEN=${GENERATED} npm run build`,
    ]) {
      expect(gate(command), command).toBeNull();
    }
  });

  it('a DATABASE_URL is a finding only when the URL carries a password', () => {
    expect(gate(`DATABASE_URL=postgres://app:${DB_PASSWORD}@db.test/app npm test`)?.severity).toBe(
      'block' // the connection-string pattern itself, as before
    );
    for (const command of [
      'DATABASE_URL=postgres://localhost/app npm test',
      'DATABASE_URL=postgres://app@db.test/app npm test',
      'DATABASE_URL=sqlite::memory: npm test',
      'DATABASE_URL=file:./dev.db npx prisma migrate dev',
      'DATABASE_URL=postgres://app:changeme@db.test/app npm test',
    ]) {
      expect(gate(command), command).toBeNull();
    }
  });

  it('leaves a reference, an empty value and a placeholder alone', () => {
    for (const command of [
      'AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY aws s3 ls',
      'AWS_SECRET_ACCESS_KEY=${AWS_SECRET} aws s3 ls',
      'AWS_SECRET_ACCESS_KEY="${AWS_SECRET:-}" aws s3 ls',
      'AWS_SECRET_ACCESS_KEY=$(cat ~/.aws/secret) aws s3 ls',
      'AWS_SECRET_ACCESS_KEY="$(aws configure get aws_secret_access_key)" aws s3 ls',
      'AWS_SECRET_ACCESS_KEY=`cat secret` aws s3 ls',
      'AWS_SECRET_ACCESS_KEY= aws s3 ls',
      'AWS_SECRET_ACCESS_KEY="" aws s3 ls',
      "AWS_SECRET_ACCESS_KEY='' aws s3 ls",
      'GITHUB_TOKEN=<your-token> gh api user',
      'GITHUB_TOKEN="<token>" gh api user',
      'GITHUB_TOKEN=[REDACTED] gh api user',
      'GITHUB_TOKEN=xxx gh api user',
      'GITHUB_TOKEN=xxxxxxxxxxxxxxxxxxxx gh api user',
      'GITHUB_TOKEN=changeme gh api user',
      'GITHUB_TOKEN=your_token_here gh api user',
      'GITHUB_TOKEN=replace-me gh api user',
      'GITHUB_TOKEN=REDACTED gh api user',
      'GITHUB_TOKEN=dummy123 gh api user',
      'GITHUB_TOKEN=dummy-token-for-tests npm test',
      'GITHUB_TOKEN=not-a-real-token gh api user',
      'GITHUB_TOKEN=fake_key_1 gh api user',
      'GITHUB_TOKEN=12345678 gh api user',
      'MY_APP_PASSWORD=12345678 ./run.sh',
      'MY_APP_PASSWORD=abcdefghijkl ./run.sh',
      'NPM_TOKEN=none npm ci',
      'OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx python app.py',
    ]) {
      expect(gate(command), command).toBeNull();
    }
  });

  it('does not read a mention, a lower-case name or a file-path variable as an assignment', () => {
    for (const command of [
      'echo $GITHUB_TOKEN',
      'grep -r GITHUB_TOKEN= .',
      'git log --grep=GITHUB_TOKEN=foo',
      `github_token=${GENERATED} ./x.sh`, // Assigned Secret territory, not an env var
      'GITHUB_TOKEN_FILE=/run/secrets/token ./x.sh',
      'MYSQL_USER=root MYSQL_PASSWORD= FILTER=integration npm test',
      'export PATH=/usr/local/bin:$PATH',
      `curl 'https://api.example.test/?MY_TOKEN=${GENERATED}'`,
    ]) {
      const m = gate(command);
      expect(m?.patternName ?? null, command).not.toBe('Inline Secret Assignment');
    }
  });

  it('does not reverse a checksum decision on a vendor-shaped look-alike', () => {
    const lookalike = 'ghp_' + 'A'.repeat(30) + 'bcdef1';
    expect(gate(`GITHUB_TOKEN=${lookalike} gh api user`)).toBeNull();
  });

  it('yields to a block-severity match in the same command', () => {
    const key = ['AKIA', 'QX7Z3BHD', 'M7NPLKV5'].join('');
    const m = gate(
      `AWS_ACCESS_KEY_ID=${key} AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET} aws s3 ls`
    );
    expect(m?.severity).toBe('block');
    expect(m?.patternName).toBe('AWS Access Key ID');
  });

  it('is found through the bounded inspection, with complete coverage', () => {
    const r = inspectArgumentSecrets({
      tool_name: 'Bash',
      tool_input: { command: `AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET} aws s3 ls` },
    });
    expect(r.match?.patternName).toBe('Inline Secret Assignment');
    expect(r.coverage).toBe('complete');
  });

  it('is a gate-only pattern: raw scanners, output redaction and response text do not use it', () => {
    const text = `AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET} aws s3 ls`;
    expect(redactText(text).result).toBe(text);
    expect(scanText(text)).toBeNull();
    expect(scanArgs({ prompt: text })).toBeNull();
  });

  it('stays linear on long runs of a keyword', () => {
    for (const word of ['_TOKEN=', 'A_SECRET', 'GITHUB_TOKEN', '_PASSWORD=x ']) {
      const text = word.repeat(Math.ceil(200_000 / word.length));
      const start = cpuNow();
      gate(text);
      expect(cpuNow() - start, word).toBeLessThan(500);
    }
  });
});

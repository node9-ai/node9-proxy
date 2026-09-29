import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import { pathToFileURL } from 'url';
import fs from 'fs';
import os from 'os';
import path from 'path';
const root = path.resolve(__dirname, '../..');
let home: string;
let credentials: string;
let config: string;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-disconnect-'));
  fs.mkdirSync(path.join(home, '.node9'));
  credentials = path.join(home, '.node9/credentials.json');
  config = path.join(home, '.node9/config.json');
  fs.writeFileSync(
    credentials,
    JSON.stringify({
      default: { apiKey: 'attempt', apiUrl: 'http://127.0.0.1:9/api/v1/intercept' },
      other: { apiKey: 'keep' },
    })
  );
  fs.writeFileSync(
    config,
    JSON.stringify({ settings: { approvers: { cloud: true, terminal: true } }, custom: 42 })
  );
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});
function run(apiKey = '', implicitProfile = false) {
  const script = path.join(home, 'disconnect.mts');
  fs.writeFileSync(
    script,
    // A file URL, not a path: the ESM loader reads a Windows "D:\..." as a URL scheme.
    `import { disconnectMachine } from ${JSON.stringify(pathToFileURL(path.join(root, 'src/cli/commands/logout.ts')).href)};
try { console.log(JSON.stringify(await disconnectMachine({ ${implicitProfile ? '' : "profile: 'default',"} resetCloudApprover: true }))); }
catch (error) { console.error(error.message); process.exitCode = 1; }`
  );
  const result = spawnSync(
    process.execPath,
    [path.join(root, 'node_modules/tsx/dist/cli.mjs'), script],
    {
      cwd: home,
      env: {
        PATH: path.dirname(process.execPath),
        HOME: home,
        USERPROFILE: home,
        NODE9_TESTING: '1',
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_API_KEY: apiKey,
        NODE9_PROFILE: '',
      },
      encoding: 'utf8',
      timeout: 15000,
    }
  );
  expect(result.error).toBeUndefined();
  return result;
}
describe('setup disconnect recovery', () => {
  it('uses the default profile when NODE9_PROFILE is empty', () => {
    const result = run('', true);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(fs.readFileSync(credentials, 'utf8'))).toEqual({ other: { apiKey: 'keep' } });
  });
  it('preserves other profiles and resets only the cloud approver when revocation fails', async () => {
    const result = run();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ outcome: 'unreachable', localRemoved: true });
    expect(JSON.parse(fs.readFileSync(credentials, 'utf8'))).toEqual({ other: { apiKey: 'keep' } });
    expect(JSON.parse(fs.readFileSync(config, 'utf8'))).toEqual({
      settings: { approvers: { cloud: false, terminal: true } },
      custom: 42,
    });
  });
  it('refuses a local transition while an environment credential remains active', async () => {
    const before = fs.readFileSync(credentials, 'utf8');
    const result = run('env-key');
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('NODE9_API_KEY');
    expect(fs.readFileSync(credentials, 'utf8')).toBe(before);
  });
  it('validates malformed config before revoking or removing credentials', async () => {
    fs.writeFileSync(config, '{broken');
    const before = fs.readFileSync(credentials, 'utf8');
    const result = run();
    expect(result.status).toBe(1);
    // Fail for the right reason: a broken import also exits 1.
    expect(result.stderr).toContain('config.json is not valid JSON');
    expect(fs.readFileSync(credentials, 'utf8')).toBe(before);
  });
});

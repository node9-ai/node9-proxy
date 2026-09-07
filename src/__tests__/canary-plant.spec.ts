// Canary adapter corpus, canary-corpus.md section D: the REAL CLI
// (dist/cli.js canary ...) against a tmp HOME. Build in the same command as
// the run; a green row against yesterday's dist is not a result. No decoy
// value appears in this file: values are read back from the tmp registry.
import { describe, it, expect, beforeEach, afterEach, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import { scanArgs } from '../dlp';
import { ROW_COUNTS } from '../../packages/policy-engine/src/dlp/canary.fixtures';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');
const win = process.platform === 'win32';
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');
type Kind = 'aws-profile' | 'env-file' | 'ssh-key';
const KINDS: Kind[] = ['aws-profile', 'env-file', 'ssh-key'];
const PRIMARY: Record<Kind, (h: string) => string> = {
  'aws-profile': (h) => path.join(h, '.aws', 'credentials'),
  'env-file': (h) => path.join(h, '.env.bak'),
  'ssh-key': (h) => path.join(h, '.ssh', 'id_rsa_backup'),
};
const FALLBACK: Record<Kind, (h: string) => string> = {
  'aws-profile': (h) => path.join(h, '.aws', 'credentials.bak'),
  'env-file': (h) => path.join(h, '.env.local.bak'),
  'ssh-key': (h) => path.join(h, '.ssh', 'id_rsa.old'),
};
const PATTERN: Record<Kind, string[]> = {
  'aws-profile': ['AWS Access Key ID'],
  'env-file': ['Stripe Secret Key', 'Database Connection String'],
  'ssh-key': ['Private Key (PEM)'],
};

function run(home: string, args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 90000,
    cwd: os.tmpdir(),
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
const plantJson = (home: string, kind?: Kind) => {
  const r = run(home, ['canary', 'plant', ...(kind ? ['--kind', kind] : ['--all']), '--json']);
  expect(r.status, r.stderr).toBe(0);
  return {
    r,
    out: JSON.parse(r.stdout) as {
      results: Array<{
        kind: Kind;
        action: string;
        path: string;
        createdDir: boolean;
        reason?: string;
        recordIds: string[];
      }>;
    },
  };
};
const removeJson = (home: string, kind: Kind) => {
  const r = run(home, ['canary', 'remove', '--kind', kind, '--json']);
  return {
    r,
    out: JSON.parse(r.stdout) as {
      results: Array<{
        kind: Kind;
        action: string;
        path?: string;
        reason?: string;
        dirRemoved?: boolean;
      }>;
    },
  };
};
type Rec = {
  id: string;
  kind: Kind;
  field: string;
  path: string;
  value: string;
  valueHash: string;
  retiredAt?: string;
  label: string;
  fileHash: string;
  createdDir: boolean;
};
const records = (home: string): Rec[] => {
  const p = path.join(home, '.node9', 'canaries.json');
  return fs.existsSync(p)
    ? (JSON.parse(fs.readFileSync(p, 'utf-8')) as { records: Rec[] }).records
    : [];
};
const live = (home: string, kind: Kind) =>
  records(home).filter((r) => r.kind === kind && !r.retiredAt);
/** sha256 of every regular file under HOME with its mtimeMs, for "nothing else changed" rows. */
function treeMap(root: string, skip: string[] = []): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (skip.includes(p)) continue;
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) out.set(p, sha(fs.readFileSync(p)) + ':' + fs.statSync(p).mtimeMs);
    }
  };
  walk(root);
  return out;
}
const jailPaths = (home: string) => {
  const p = path.join(home, '.node9', 'jail-paths.json');
  return fs.existsSync(p)
    ? (
        JSON.parse(fs.readFileSync(p, 'utf-8')) as {
          paths: Array<{ path: string; verdict: string }>;
        }
      ).paths
    : [];
};

let home: string;
beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`build first: ${CLI}`);
});
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-canary-plant-'));
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

describe.each(KINDS)('D. shared rows: %s', (kind) => {
  it('D1 primary and parent absent: created, dir created, createdDir true, json names the path and no value', () => {
    const { r, out } = plantJson(home, kind);
    const res = out.results[0];
    expect(res.action).toBe('created');
    expect(res.path).toBe(PRIMARY[kind](home));
    expect(res.createdDir).toBe(kind !== 'env-file'); // env primary is directly in HOME, which exists
    expect(fs.existsSync(res.path)).toBe(true);
    for (const rec of live(home, kind)) expect(r.stdout).not.toContain(rec.value);
  });
  it('D2 parent exists, primary absent: created, createdDir false', () => {
    fs.mkdirSync(path.dirname(PRIMARY[kind](home)), { recursive: true });
    expect(plantJson(home, kind).out.results[0].createdDir).toBe(false);
  });
  it('D3 primary present: primary byte-identical, fallback created, record path is the fallback', () => {
    const p = PRIMARY[kind](home);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, 'user content\n');
    const before = sha(fs.readFileSync(p));
    const res = plantJson(home, kind).out.results[0];
    expect(res.action).toBe('created');
    expect(res.path).toBe(FALLBACK[kind](home));
    expect(sha(fs.readFileSync(p))).toBe(before);
    expect(live(home, kind)[0].path).toBe(FALLBACK[kind](home));
  });
  it('D4 both present: nothing written anywhere, skipped with reason, registry unchanged, exit 0', () => {
    for (const f of [PRIMARY[kind](home), FALLBACK[kind](home)]) {
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, 'x\n');
    }
    const before = treeMap(home);
    const { r, out } = plantJson(home, kind);
    expect(out.results[0].action).toBe('skipped');
    expect(out.results[0].reason).toMatch(/exist/);
    expect(r.stdout).toContain(kind);
    expect(treeMap(home)).toEqual(before);
    expect(records(home)).toEqual([]);
  });
  it('D5 plant twice: same bytes, same record ids, no duplicates', () => {
    const a = plantJson(home, kind).out.results[0];
    const bytes = sha(fs.readFileSync(a.path));
    const b = plantJson(home, kind).out.results[0];
    expect(b.action).toBe('exists');
    expect(b.recordIds).toEqual(a.recordIds);
    expect(sha(fs.readFileSync(a.path))).toBe(bytes);
    expect(
      live(home, kind)
        .map((x) => x.id)
        .sort()
    ).toEqual([...a.recordIds].sort());
  });
  it('D6 remove: created file gone, nothing else changed, records retired not deleted', () => {
    const a = plantJson(home, kind).out.results[0];
    const before = treeMap(home, [
      a.path,
      path.join(home, '.node9', 'canaries.json'),
      path.join(home, '.node9', 'jail-paths.json'),
      path.join(home, '.node9', 'shields', 'user-jail.json'),
      path.join(home, '.node9', 'shields.json'),
    ]);
    const { r, out } = removeJson(home, kind);
    expect(r.status).toBe(0);
    expect(out.results[0].action).toBe('removed');
    expect(fs.existsSync(a.path)).toBe(false);
    expect(
      treeMap(home, [
        path.join(home, '.node9', 'canaries.json'),
        path.join(home, '.node9', 'jail-paths.json'),
        path.join(home, '.node9', 'shields', 'user-jail.json'),
        path.join(home, '.node9', 'shields.json'),
      ])
    ).toEqual(before);
    const recs = records(home).filter((x) => x.kind === kind);
    expect(recs.length).toBeGreaterThan(0);
    for (const x of recs) expect(x.retiredAt).toBeTruthy();
  });
  it('D7 file changed: remove refuses (non-zero), file untouched, records still live', () => {
    const a = plantJson(home, kind).out.results[0];
    fs.appendFileSync(a.path, 'x');
    const h = sha(fs.readFileSync(a.path));
    const { r, out } = removeJson(home, kind);
    expect(r.status).not.toBe(0);
    expect(out.results[0].action).toBe('refused');
    expect(out.results[0].reason).toContain(a.path);
    expect(sha(fs.readFileSync(a.path))).toBe(h);
    expect(live(home, kind).length).toBeGreaterThan(0);
  });
  it('D11 file deleted by the user, then remove: retired, exit 0, already-gone', () => {
    const a = plantJson(home, kind).out.results[0];
    fs.rmSync(a.path);
    const { r, out } = removeJson(home, kind);
    expect(r.status).toBe(0);
    expect(out.results[0].action).toBe('already-gone');
    expect(live(home, kind)).toEqual([]);
  });
  it('D12 file deleted, status says missing', () => {
    const a = plantJson(home, kind).out.results[0];
    fs.rmSync(a.path);
    const r = run(home, ['canary', 'status', '--json']);
    const sites = (JSON.parse(r.stdout) as { sites: Array<{ kind: Kind; state: string }> }).sites;
    expect(sites.find((s) => s.kind === kind)?.state).toBe('missing');
  });
  it.skipIf(win)('D13 created file mode 0600', () => {
    const a = plantJson(home, kind).out.results[0];
    expect(fs.statSync(a.path).mode & 0o777).toBe(0o600);
  });
  it('D14 plant path jail-registered as block and the user-jail shield materialised', () => {
    const a = plantJson(home, kind).out.results[0];
    expect(jailPaths(home)).toContainEqual({ path: a.path, verdict: 'block' });
    expect(fs.existsSync(path.join(home, '.node9', 'shields', 'user-jail.json'))).toBe(true);
  });
  it('D15 the REAL file bytes trip the named regex pattern(s) at block', () => {
    const a = plantJson(home, kind).out.results[0];
    const text = fs.readFileSync(a.path, 'utf-8');
    if (kind === 'env-file') {
      const [l1, l2] = text.trim().split('\n');
      expect(scanArgs({ content: l1 })?.patternName).toBe('Stripe Secret Key');
      expect(scanArgs({ content: l2 })?.patternName).toBe('Database Connection String');
    } else {
      const m = scanArgs({ content: text });
      expect(m?.severity).toBe('block');
      expect(PATTERN[kind]).toContain(m?.patternName);
    }
  });
  it('D16 plant and register agree: each value is in the file, hash is sha256(value)', () => {
    const a = plantJson(home, kind).out.results[0];
    const text = fs.readFileSync(a.path, 'utf-8');
    const recs = live(home, kind);
    expect(recs.length).toBeGreaterThan(0);
    for (const rec of recs) {
      expect(text).toContain(rec.value);
      expect(rec.valueHash).toBe(sha(rec.value));
      expect(rec.fileHash).toBe(sha(text));
    }
  });
  it('D17 label never says canary or node9', () => {
    plantJson(home, kind);
    for (const rec of live(home, kind)) expect(rec.label.toLowerCase()).not.toMatch(/canary|node9/);
  });
});

describe('D. shared rows, cross-kind', () => {
  it('D8 createdDir true: remove deletes the empty parent', () => {
    const a = plantJson(home, 'aws-profile').out.results[0];
    expect(a.createdDir).toBe(true);
    const { out } = removeJson(home, 'aws-profile');
    expect(out.results[0].dirRemoved).toBe(true);
    expect(fs.existsSync(path.dirname(a.path))).toBe(false);
  });
  it('D9 createdDir true but a sibling appeared: file removed, dir kept', () => {
    const a = plantJson(home, 'aws-profile').out.results[0];
    fs.writeFileSync(path.join(path.dirname(a.path), 'config'), 'x');
    const { out } = removeJson(home, 'aws-profile');
    expect(out.results[0].action).toBe('removed');
    expect(out.results[0].dirRemoved).toBe(false);
    expect(fs.existsSync(path.dirname(a.path))).toBe(true);
  });
  it('D10 createdDir false: dir kept', () => {
    fs.mkdirSync(path.join(home, '.ssh'), { recursive: true });
    const a = plantJson(home, 'ssh-key').out.results[0];
    expect(a.createdDir).toBe(false);
    removeJson(home, 'ssh-key');
    expect(fs.existsSync(path.join(home, '.ssh'))).toBe(true);
  });
  it('D18 --all with one site in the both-present state: two planted, one skipped, exit 0', () => {
    for (const f of [PRIMARY['env-file'](home), FALLBACK['env-file'](home)])
      fs.writeFileSync(f, 'x\n');
    const { out } = plantJson(home);
    const by = Object.fromEntries(out.results.map((r) => [r.kind, r.action]));
    expect(by).toEqual({ 'aws-profile': 'created', 'env-file': 'skipped', 'ssh-key': 'created' });
    expect(records(home).filter((r) => !r.retiredAt)).toHaveLength(3);
  });
  it("D19 posture after plant: no Secrets finding attributes a planted path as the user's credential", () => {
    const { out } = plantJson(home);
    const planted = out.results.map((r) => r.path);
    const r = run(home, ['posture', '--json']);
    // posture sets exit code 2 when the tier is critical (cli/commands/posture.ts),
    // which an empty tmp HOME always is; the document on stdout is still complete.
    expect([0, 2], r.stderr).toContain(r.status);
    const res = JSON.parse(r.stdout) as {
      findings: Array<{ category: string; severity: string; title: string; detail: string[] }>;
    };
    const secrets = res.findings.filter((f) => f.category === 'Secrets');
    for (const f of secrets) {
      if (/decoy/i.test(f.title)) continue; // the informational row is allowed to name them
      for (const d of f.detail)
        for (const p of planted) expect(d).not.toContain(p.replace(home, '~'));
    }
    expect(secrets.some((f) => /decoy/i.test(f.title))).toBe(true);
  });
  it('A12 via the CLI: a full plant registers five records', () => {
    plantJson(home);
    expect(records(home).filter((r) => !r.retiredAt)).toHaveLength(5);
  });
});

describe('D-a. aws-profile only', () => {
  const parseIni = (text: string) => {
    const sections: Record<string, Record<string, string>> = {};
    let cur = '';
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith(';')) continue;
      const s = /^\[(.+)\]$/.exec(line);
      if (s) {
        cur = s[1];
        sections[cur] = {};
        continue;
      }
      const kv = /^([^=]+?)\s*=\s*(.*)$/.exec(line);
      if (!kv) throw new Error('bad ini line');
      sections[cur][kv[1]] = kv[2];
    }
    return sections;
  };
  it('D-a1 strict INI: one section named by the label, exactly the two keys, trailing newline', () => {
    plantJson(home, 'aws-profile');
    const text = fs.readFileSync(PRIMARY['aws-profile'](home), 'utf-8');
    expect(text.endsWith('\n')).toBe(true);
    const ini = parseIni(text);
    const names = Object.keys(ini);
    expect(names).toHaveLength(1);
    expect(names[0]).toBe(live(home, 'aws-profile')[0].label);
    expect(Object.keys(ini[names[0]]).sort()).toEqual([
      'aws_access_key_id',
      'aws_secret_access_key',
    ]);
  });
  const hasAws = spawnSync('aws', ['--version'], { encoding: 'utf-8' }).status === 0;
  it.skipIf(!hasAws)(
    'D-a2 aws CLI resolves the label as a shared-credentials-file profile (SKIPPED when aws is absent)',
    () => {
      plantJson(home, 'aws-profile');
      const label = live(home, 'aws-profile')[0].label;
      const r = spawnSync('aws', ['configure', 'list', '--profile', label], {
        encoding: 'utf-8',
        env: { ...process.env, HOME: home, USERPROFILE: home },
      });
      expect(r.status).toBe(0);
      expect(r.stdout).toMatch(/shared-credentials-file/);
    }
  );
  it('D-a3 ~/.aws/config exists, credentials absent: the FALLBACK is used (H20)', () => {
    fs.mkdirSync(path.join(home, '.aws'), { recursive: true });
    fs.writeFileSync(path.join(home, '.aws', 'config'), '[default]\nregion = us-east-1\n');
    const res = plantJson(home, 'aws-profile').out.results[0];
    expect(res.path).toBe(FALLBACK['aws-profile'](home));
    expect(fs.existsSync(PRIMARY['aws-profile'](home))).toBe(false);
  });
  it('D-a4 the label is never default', () => {
    plantJson(home, 'aws-profile');
    expect(live(home, 'aws-profile')[0].label).not.toBe('default');
  });
});

describe('D-e. env-file only', () => {
  const parseDotenv = (text: string) => {
    const out: Record<string, string> = {};
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
      if (!m) throw new Error('bad dotenv line');
      out[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
    return out;
  };
  it('D-e1 exactly two assignments with names from the list; values equal the Stripe key and the DB URL', () => {
    plantJson(home, 'env-file');
    const env = parseDotenv(fs.readFileSync(PRIMARY['env-file'](home), 'utf-8'));
    const keys = Object.keys(env);
    expect(keys).toHaveLength(2);
    expect(keys.some((k) => ['STRIPE_SECRET_KEY', 'STRIPE_API_KEY'].includes(k))).toBe(true);
    expect(keys.some((k) => ['DATABASE_URL', 'PG_URL'].includes(k))).toBe(true);
    const recs = live(home, 'env-file');
    const stripe = recs.find((r) => r.field.startsWith('STRIPE'))!;
    expect(env[stripe.field]).toBe(stripe.value);
  });
  it('D-e2 the DB URL parses; its password is the registered value; host is from the list', () => {
    plantJson(home, 'env-file');
    const env = Object.values(parseDotenvSafe(fs.readFileSync(PRIMARY['env-file'](home), 'utf-8')));
    const urlText = env.find((v) => v.includes('://'))!;
    const u = new URL(urlText);
    const db = live(home, 'env-file').find((r) => !r.field.startsWith('STRIPE'))!;
    expect(u.password).toBe(db.value);
    expect(['db-internal', 'pg-primary.internal', 'postgres.svc.cluster.local']).toContain(
      u.hostname
    );
  });
  function parseDotenvSafe(text: string) {
    return parseDotenv(text);
  }
  it('D-e3 a project .env in cwd is never touched', () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-canary-cwd-'));
    const proj = path.join(cwd, '.env');
    fs.writeFileSync(proj, 'A=1\n');
    const before = sha(fs.readFileSync(proj));
    const r = spawnSync(
      process.execPath,
      [CLI, 'canary', 'plant', '--kind', 'env-file', '--json'],
      {
        encoding: 'utf-8',
        cwd,
        env: {
          ...process.env,
          HOME: home,
          USERPROFILE: home,
          NODE9_TESTING: '1',
          NODE9_NO_AUTO_DAEMON: '1',
        },
      }
    );
    expect(r.status).toBe(0);
    expect(sha(fs.readFileSync(proj))).toBe(before);
    fs.rmSync(cwd, { recursive: true, force: true });
  });
  it('D-e4 ~/.env exists: untouched; primary is ~/.env.bak, unrelated to it', () => {
    const dot = path.join(home, '.env');
    fs.writeFileSync(dot, 'REAL=1\n');
    const before = sha(fs.readFileSync(dot));
    const res = plantJson(home, 'env-file').out.results[0];
    expect(res.path).toBe(PRIMARY['env-file'](home));
    expect(sha(fs.readFileSync(dot))).toBe(before);
  });
});

describe('D-s. ssh-key only', () => {
  it('D-s1 structure: header, 64-char base64 body lines, one short line, footer; body decodes', () => {
    plantJson(home, 'ssh-key');
    const lines = fs.readFileSync(PRIMARY['ssh-key'](home), 'utf-8').trimEnd().split('\n');
    expect(lines[0]).toMatch(/^-----BEGIN .*PRIVATE KEY-----$/);
    expect(lines[lines.length - 1]).toMatch(/^-----END .*PRIVATE KEY-----$/);
    const body = lines.slice(1, -1);
    for (const l of body.slice(0, -1)) expect(l).toMatch(/^[A-Za-z0-9+/]{64}$/);
    expect(body[body.length - 1].length).toBeLessThan(64);
    expect(() => Buffer.from(body.join(''), 'base64')).not.toThrow();
  });
  const hasSsh = spawnSync('ssh', ['-V'], { encoding: 'utf-8' }).status === 0;
  it.skipIf(!hasSsh)(
    'D-s2 ssh does not list the planted path as an identity (SKIPPED when ssh is absent)',
    () => {
      plantJson(home, 'ssh-key');
      const r = spawnSync('ssh', ['-G', 'localhost'], {
        encoding: 'utf-8',
        env: { ...process.env, HOME: home },
      });
      expect(r.stdout).not.toContain('id_rsa_backup');
      const kg = spawnSync('ssh-keygen', ['-l', '-f', PRIMARY['ssh-key'](home)], {
        encoding: 'utf-8',
      });
      if (kg.status !== null) expect(kg.status).not.toBe(0);
    }
  );
  it.skipIf(win)('D-s3 ~/.ssh absent: created 0700, createdDir true', () => {
    const res = plantJson(home, 'ssh-key').out.results[0];
    expect(res.createdDir).toBe(true);
    expect(fs.statSync(path.join(home, '.ssh')).mode & 0o777).toBe(0o700);
  });
  it('D-s4 ~/.ssh/config untouched', () => {
    fs.mkdirSync(path.join(home, '.ssh'), { recursive: true });
    const cfg = path.join(home, '.ssh', 'config');
    fs.writeFileSync(cfg, 'Host x\n');
    const before = sha(fs.readFileSync(cfg));
    plantJson(home, 'ssh-key');
    expect(sha(fs.readFileSync(cfg))).toBe(before);
  });
  it('D-s5 registered value is the first body line, 64 chars', () => {
    plantJson(home, 'ssh-key');
    const lines = fs.readFileSync(PRIMARY['ssh-key'](home), 'utf-8').split('\n');
    const rec = live(home, 'ssh-key')[0];
    expect(rec.value).toBe(lines[1]);
    expect(rec.value).toHaveLength(64);
  });
  it('D-s6 full text trips Private Key (PEM) at block', () => {
    plantJson(home, 'ssh-key');
    const m = scanArgs({ content: fs.readFileSync(PRIMARY['ssh-key'](home), 'utf-8') });
    expect(m?.patternName).toBe('Private Key (PEM)');
    expect(m?.severity).toBe('block');
  });
  it('D-s7 body only, no header: null (pinned honestly, H6)', () => {
    plantJson(home, 'ssh-key');
    const lines = fs.readFileSync(PRIMARY['ssh-key'](home), 'utf-8').trimEnd().split('\n');
    expect(scanArgs({ content: lines.slice(1, -1).join('\n') })).toBeNull();
  });
  it('row counts', () => {
    expect(ROW_COUNTS.D).toBe(34);
  });
});

// node9Firewall#376 item 6, phase 4, check B: the domains a skill names, and
// whether DNS says they exist.
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { hostCachePath, lookupDomains, type NsQuery } from '../host-lookup';
import { registrableDomain, skillHosts } from '../skill-hosts';
import { collectAddonsWithLookups, type AddonSkill } from '../collect';

const domains = (text: string) => skillHosts([text]).map((h) => h.domain);

describe('registrableDomain', () => {
  it('is never longer than the name someone could register', () => {
    expect(registrableDomain('api.eu.vendor-cloud.com')).toBe('vendor-cloud.com');
    expect(registrableDomain('docs.vendor-shop.co.uk')).toBe('vendor-shop.co.uk');
    expect(registrableDomain('acme-team.github.io')).toBe('acme-team.github.io');
    expect(registrableDomain('VENDOR-CLOUD.COM.')).toBe('vendor-cloud.com');
  });

  it('is null for what nobody can register: addresses, private names, bare suffixes', () => {
    for (const h of [
      '10.0.0.5',
      '127.0.0.1',
      'localhost',
      'db',
      'db.internal',
      'printer.local',
      'api.corp',
      'service.test',
      'co.uk',
      'github.io',
    ])
      expect(registrableDomain(h), h).toBeNull();
  });

  it('is null for a stand-in name', () => {
    for (const h of [
      'example.com',
      'api.example.org',
      'your-domain.com',
      'your-company.com',
      'a.com',
      'example.workers.dev',
      'myapp-staging.azurewebsites.net',
      'your.app',
      'test-site.netlify.app',
    ])
      expect(registrableDomain(h), h).toBeNull();
  });
});

describe('skillHosts', () => {
  it('takes a host from a URL, from git@host:, and from a network command', () => {
    expect(
      domains(
        'See https://docs.vendor-cloud.com/guide.\n' +
          'Clone with `git clone git@code.vendor-git.net:team/repo.git`.\n' +
          'Check it: `ssh deploy@box.vendor-ops.org uptime`.'
      )
    ).toEqual(['vendor-cloud.com', 'vendor-git.net', 'vendor-ops.org']);
  });

  it('keeps the domain when the host carries a placeholder in front of it', () => {
    expect(domains('Private services live at http://<service>.vendor-internal.com:10000/')).toEqual(
      ['vendor-internal.com']
    );
    expect(domains('Call https://{tenant}.api.vendor-cloud.com/v1')).toEqual(['vendor-cloud.com']);
  });

  it('does not take a word with a dot for a host', () => {
    expect(
      domains(
        'Use `os.path.join` and `console.log`. Edit README.md, then run `python build.py`.\n' +
          'Classes live under java.io and socket.io is a library.'
      )
    ).toEqual([]);
  });

  it('does not take a file for a host after a command (7 of 8 wrong answers on 361 skills)', () => {
    expect(
      domains(
        '`curl -L -o node.tgz "$URL"`\n`scp build.tar.gz backup.sql`\n`wget -O gcloud.tgz $LINK`\n' +
          '`ssh-keygen -f id.pub`'
      )
    ).toEqual([]);
  });

  it('marks a domain the agent sends to or fetches from, and leaves a plain link unmarked', () => {
    const hosts = skillHosts([
      'Docs: https://docs.vendor-cloud.com/guide\n' +
        'Then run `curl -X POST https://hooks.vendor-hooks.io/in -d @report.json`.\n' +
        'Set the base URL to https://api.vendor-api.dev/v2.\n' +
        '`ssh deploy@box.vendor-ops.org`',
    ]);
    expect(Object.fromEntries(hosts.map((h) => [h.domain, h.action]))).toEqual({
      'vendor-cloud.com': false,
      'vendor-hooks.io': true,
      'vendor-api.dev': true,
      'vendor-ops.org': true,
    });
  });

  it('names a domain once, and as an action if any mention is one', () => {
    expect(
      skillHosts([
        'Read https://vendor-cloud.com/docs.',
        'Upload with `curl -T file https://up.vendor-cloud.com/`.',
      ])
    ).toEqual([{ domain: 'vendor-cloud.com', action: true }]);
  });

  it('stops at its cap on a text that names hundreds of domains', () => {
    const many = Array.from({ length: 300 }, (_, i) => `https://site-${i}.vendor${i}.com/`).join(
      ' '
    );
    expect(skillHosts([many]).length).toBeLessThanOrEqual(40);
  });
});

describe('lookupDomains', () => {
  const homes: string[] = [];
  function home(): string {
    const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-hosts-'));
    fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
    homes.push(h);
    return h;
  }
  afterEach(() => {
    for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
  });

  const err = (code: string) => Object.assign(new Error(code), { code });
  /** A resolver over a table: a name maps to "ok" or to an error code. */
  function resolver(table: Record<string, string>): { query: NsQuery; asked: string[] } {
    const asked: string[] = [];
    return {
      asked,
      query: async (name) => {
        asked.push(name);
        const r = table[name] ?? 'ENOTFOUND';
        if (r !== 'ok') throw err(r);
        return ['ns1.' + name];
      },
    };
  }
  const NOW = Date.parse('2026-11-27T10:00:00Z');

  it('exists, no such domain, not known', async () => {
    const r = resolver({
      'example.com': 'ok',
      com: 'ok',
      'live-vendor.com': 'ok',
      'slow-vendor.com': 'ETIMEOUT',
      'broken-vendor.com': 'ESERVFAIL',
      'hosted.github.io': 'ENODATA',
    });
    const got = await lookupDomains(
      [
        'live-vendor.com',
        'gone-vendor.com',
        'slow-vendor.com',
        'broken-vendor.com',
        'hosted.github.io',
      ],
      home(),
      { query: r.query, now: NOW }
    );
    expect(Object.fromEntries(got)).toEqual({
      'live-vendor.com': true,
      'gone-vendor.com': false,
      'slow-vendor.com': null,
      'broken-vendor.com': null,
      // The name exists; it only has no NS record of its own.
      'hosted.github.io': true,
    });
  });

  it('a name under a top-level domain that does not exist is not "unregistered"', async () => {
    const r = resolver({ 'example.com': 'ok' }); // `svc` and `monitoring` are not TLDs
    const got = await lookupDomains(['default.svc', 'prometheus.monitoring'], home(), {
      query: r.query,
      now: NOW,
    });
    expect([...got.values()]).toEqual([true, true]);
  });

  it('says nothing at all when the resolver does not answer for a domain that must exist', async () => {
    const dead = resolver({}); // everything NXDOMAIN, example.com included
    const got = await lookupDomains(['gone-vendor.com'], home(), { query: dead.query, now: NOW });
    expect(got.get('gone-vendor.com')).toBeNull();
    const down = resolver({ 'example.com': 'ETIMEOUT' });
    expect(
      (await lookupDomains(['gone-vendor.com'], home(), { query: down.query, now: NOW })).get(
        'gone-vendor.com'
      )
    ).toBeNull();
  });

  it('asks a domain once a day, and never caches "not known"', async () => {
    const h = home();
    const r = resolver({ 'example.com': 'ok', com: 'ok', 'slow-vendor.com': 'ETIMEOUT' });
    await lookupDomains(['gone-vendor.com', 'slow-vendor.com'], h, { query: r.query, now: NOW });
    const first = r.asked.length;
    // An hour later: the answered one comes from the file, the unknown one is asked again.
    const again = await lookupDomains(['gone-vendor.com', 'slow-vendor.com'], h, {
      query: r.query,
      now: NOW + 60 * 60 * 1000,
    });
    expect(again.get('gone-vendor.com')).toBe(false);
    expect(r.asked.slice(first)).not.toContain('gone-vendor.com');
    expect(r.asked.slice(first)).toContain('slow-vendor.com');
    // Nothing to ask: no query at all, not even the control.
    const before = r.asked.length;
    await lookupDomains(['gone-vendor.com'], h, { query: r.query, now: NOW + 2 * 60 * 60 * 1000 });
    expect(r.asked.length).toBe(before);
    // A day later it is asked again.
    await lookupDomains(['gone-vendor.com'], h, { query: r.query, now: NOW + 25 * 60 * 60 * 1000 });
    expect(r.asked.slice(before)).toContain('gone-vendor.com');
  });

  it('keeps its answers in a private file, and survives a broken one', async () => {
    const h = home();
    const r = resolver({ 'example.com': 'ok', com: 'ok' });
    await lookupDomains(['gone-vendor.com'], h, { query: r.query, now: NOW });
    expect(fs.statSync(hostCachePath(h)).mode & 0o077).toBe(0);
    fs.writeFileSync(hostCachePath(h), '{not json');
    const got = await lookupDomains(['gone-vendor.com'], h, { query: r.query, now: NOW });
    expect(got.get('gone-vendor.com')).toBe(false);
  });
});

describe('the add-ons report with the host check', () => {
  const homes: string[] = [];
  function home(): string {
    const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-hosts-report-'));
    fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
    homes.push(h);
    return h;
  }
  afterEach(() => {
    for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
  });
  function skill(h: string, name: string, body: string): void {
    const dir = path.join(h, '.claude', 'skills', name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'SKILL.md'), `---\nname: ${name}\n---\n${body}\n`);
  }
  /** A lookup that knows which domains are gone; everything else exists. */
  const lookup = (gone: string[], ok = true) => {
    const asked: string[][] = [];
    return {
      asked,
      fn: async (domains: string[]) => {
        asked.push(domains);
        return { ok, answers: new Map(domains.map((d) => [d, !gone.includes(d)])) };
      },
    };
  };
  const byName = (skills: AddonSkill[]) => Object.fromEntries(skills.map((s) => [s.name, s]));

  it('grades a gone domain high where the agent sends something there, low for a link', async () => {
    const h = home();
    skill(
      h,
      'deploy',
      'Private services answer at http://<service>.gone-vendor.com:10000/.\n' +
        'Post the report: `curl -X POST https://hooks.gone-hooks.io/in -d @report.json`'
    );
    skill(h, 'reader', 'Background reading: https://docs.gone-vendor.com/guide');
    skill(h, 'plain', 'See https://docs.live-vendor.com/ for details.');
    const l = lookup(['gone-vendor.com', 'gone-hooks.io']);
    const skills = byName((await collectAddonsWithLookups(h, {}, { lookup: l.fn })).skills);
    expect(skills.deploy.findings).toContainEqual({
      rule: 'skill.host-unregistered',
      severity: 'high',
    });
    expect(skills.deploy.unregisteredDomains?.sort()).toEqual(['gone-hooks.io', 'gone-vendor.com']);
    expect(skills.reader.findings).toContainEqual({
      rule: 'skill.host-unregistered',
      severity: 'low',
    });
    expect(skills.plain.findings).toEqual([]);
    expect(skills.plain.unregisteredDomains).toBeUndefined();
    // Every skill says the check ran, so no finding means nothing found.
    for (const s of Object.values(skills)) expect(s.checks).toEqual(['hosts']);
    // Each domain is asked once, as a registrable domain.
    expect(l.asked).toEqual([
      expect.arrayContaining(['gone-vendor.com', 'gone-hooks.io', 'live-vendor.com']),
    ]);
    expect(l.asked[0]).toHaveLength(3);
  });

  it('sends the finding but not the domain for a skill inside a project', async () => {
    const h = home();
    const project = path.join(h, 'work', 'repo');
    const dir = path.join(project, '.claude', 'skills', 'internal');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: internal\n---\nUpload with `curl -T out.bin https://up.gone-vendor.com/`\n'
    );
    // A session started in the project is what makes its skills reported.
    fs.writeFileSync(
      path.join(h, '.node9', 'audit.log'),
      JSON.stringify({ ts: new Date().toISOString(), tool: 'Bash', workingDir: project }) + '\n'
    );
    const report = await collectAddonsWithLookups(
      h,
      {},
      {
        lookup: lookup(['gone-vendor.com']).fn,
      }
    );
    const row = report.skills.find((s) => s.name === 'internal');
    expect(row?.scope).toBe('project');
    expect(row?.findings).toContainEqual({ rule: 'skill.host-unregistered', severity: 'high' });
    expect(row?.unregisteredDomains).toBeUndefined();
    expect(JSON.stringify(report)).not.toContain('gone-vendor.com');
  });

  it('marks nothing as checked when the resolver could not be trusted', async () => {
    const h = home();
    skill(h, 'reader', 'https://docs.gone-vendor.com/guide');
    const report = await collectAddonsWithLookups(
      h,
      {},
      {
        lookup: lookup(['gone-vendor.com'], false).fn,
      }
    );
    expect(report.skills[0].checks).toBeUndefined();
    expect(report.skills[0].findings).toEqual([]);
  });

  it('asks nothing when lookups are switched off, and survives a lookup that throws', async () => {
    const h = home();
    skill(h, 'reader', 'https://docs.gone-vendor.com/guide');
    const l = lookup(['gone-vendor.com']);
    const off = await collectAddonsWithLookups(h, {}, { lookup: l.fn, lookupsAllowed: false });
    expect(l.asked).toEqual([]);
    expect(off.skills[0].checks).toBeUndefined();
    const thrown = await collectAddonsWithLookups(
      h,
      {},
      {
        lookup: async () => {
          throw new Error('dns down');
        },
      }
    );
    expect(thrown.skills).toHaveLength(1);
    expect(thrown.skills[0].checks).toBeUndefined();
  });

  it("never puts a skill's text or a full URL on the wire", async () => {
    const h = home();
    skill(h, 'deploy', 'Token is in the URL: https://up.gone-vendor.com/in?key=hunter2secret');
    const report = await collectAddonsWithLookups(
      h,
      {},
      {
        lookup: lookup(['gone-vendor.com']).fn,
      }
    );
    const wire = JSON.stringify(report);
    expect(wire).toContain('gone-vendor.com');
    expect(wire).not.toContain('hunter2secret');
    expect(wire).not.toContain('up.gone-vendor.com');
  });
});

// The SSRF floor beyond shell commands.
//
// Measured gap: `curl http://<metadata>/` blocks, the same address through
// WebFetch or a browser tool does not, because the floor is called only inside
// the shell branch. Design and both adversarial corpora:
//   doc/roadmap/active/ssrf-nonshell-design.md
//   doc/roadmap/active/ssrf-nonshell-{attack,fp}-corpus.md
//
// Two laws this file exists to hold:
//   1. a value is judged by PARSING it as a URL and taking the host, never by
//      searching for a substring
//   2. only a tool on the closed list is judged at all, because there is no
//      placement that reaches WebFetch without also reaching Grep
import { describe, it, expect } from 'vitest';
import { ssrfDestinationFloor } from './destinations';

const META = '169.254.169.254';
const hit = (tool: string, args: unknown, opts = {}) => ssrfDestinationFloor(tool, args, opts);

describe('A. the closed list', () => {
  it('A1 WebFetch is judged', () => {
    expect(hit('WebFetch', { url: `http://${META}/latest/meta-data/` })?.tier).toBe('metadata');
  });

  it('A2 the browser tools are judged, including a value nested at depth 4', () => {
    expect(hit('navigate', { url: `http://${META}/` })?.tier).toBe('metadata');
    expect(hit('preview_start', { url: `http://${META}/` })?.tier).toBe('metadata');
    expect(
      hit('browser_batch', {
        actions: [
          { input: { url: 'https://ok.example.com' } },
          { input: { url: `http://${META}/` } },
        ],
      })?.tier
    ).toBe('metadata');
  });

  it('A3 an MCP server prefix does not hide a listed tool', () => {
    expect(hit('mcp__Claude_Browser__navigate', { url: `http://${META}/` })?.tier).toBe('metadata');
  });

  it('A4 a tool NOT on the list is not judged, whatever its arguments say', () => {
    // The founder call, 2026-09-08: a URL-shaped key on a tool whose network
    // semantics are undeclared is ignored. There is no placement that sees
    // WebFetch without also seeing these, so the list is what separates them.
    for (const tool of [
      'Grep',
      'Write',
      'Read',
      'Bash',
      'Agent',
      'Task',
      'mcp__unknown__do_thing',
    ]) {
      expect(
        hit(tool, { url: `http://${META}/`, pattern: META, content: `see http://${META}/` }),
        tool
      ).toBeNull();
    }
  });

  it("A5 an argument that is not on the tool's declared path is not judged", () => {
    expect(hit('WebFetch', { prompt: `explain http://${META}/latest/meta-data/` })).toBeNull();
  });
});

describe('B. a value becomes a host by PARSING, not by searching', () => {
  it('B1 the row that kills a substring check', () => {
    // Looks like the metadata address, resolves to example.com. Measured with
    // the real URL parser before this file was written.
    expect(hit('WebFetch', { url: `http://${META}%2f@example.com/` })).toBeNull();
  });

  it('B2 every spelling of the address still lands', () => {
    for (const u of [
      `http://${META}/x`,
      'http://2852039166/x',
      'http://[::ffff:169.254.169.254]/x',
      `http://${META.toUpperCase()}./x`,
      `http://user:pw@${META}/x`,
    ]) {
      expect(hit('WebFetch', { url: u })?.tier, u).toBe('metadata');
    }
  });

  it('B3 ordinary destinations pass', () => {
    for (const u of [
      'https://api.github.com/repos',
      'https://registry.npmjs.org/x',
      'http://example.com',
    ]) {
      expect(hit('WebFetch', { url: u }), u).toBeNull();
    }
  });

  it('B3b a non-http scheme reaching the same address is still a destination', () => {
    // Found by a surviving mutant: the first version restricted this to
    // http(s), which was arbitrary rather than safe.
    expect(hit('WebFetch', { url: `ssh://${META}/x` })?.tier).toBe('metadata');
    expect(hit('WebFetch', { url: `ftp://${META}/x` })?.tier).toBe('metadata');
  });

  it('B3c a scheme that carries no host is not a destination', () => {
    for (const u of [
      `data:text/html,${META}`,
      `javascript:fetch('${META}')`,
      `mailto:a@${META}`,
      'file:///etc/hosts',
      // The row a surviving mutant asked for: read the PATH instead of the
      // host and this blocks, though nothing is being reached.
      `javascript:${META}`,
    ]) {
      expect(hit('WebFetch', { url: u }), u).toBeNull();
    }
  });

  it('B4 a value that is not a URL at all is not a destination', () => {
    // The numeric-collision family: under inet_aton a price or a hash folds to
    // a protected address. None of these is a URL host, so this path never
    // meets the problem the shell path has to guard against.
    for (const v of ['239.99', '0.0', '0', '1678033921', 'not a url', '', 'metadata']) {
      expect(hit('WebFetch', { url: v }), v).toBeNull();
    }
  });
});

describe('C. the same tiers as the shell path', () => {
  it('C1 the strict tier is off by default and on when asked', () => {
    expect(hit('WebFetch', { url: 'http://127.0.0.1:3000/health' })).toBeNull();
    expect(hit('WebFetch', { url: 'http://0.0.0.0:3000/health' })).toBeNull();
    expect(
      hit('WebFetch', { url: 'http://127.0.0.1:3000/health' }, { ssrfStrict: true })?.tier
    ).toBe('private');
  });

  it('C2 an exemption applies to an overridable tier only', () => {
    const strict = { ssrfStrict: true };
    expect(hit('WebFetch', { url: 'http://100.64.0.1/x' }, strict)?.tier).toBe('cgnat');
    expect(
      hit('WebFetch', { url: 'http://100.64.0.1/x' }, { ...strict, ssrfAllow: ['100.64.0.1'] })
    ).toBeNull();
    expect(hit('WebFetch', { url: `http://${META}/x` }, { ssrfAllow: [META] })?.tier).toBe(
      'metadata'
    );
  });

  it('C3 the metadata endpoint inside CGNAT is still not exemptable', () => {
    expect(
      hit(
        'WebFetch',
        { url: 'http://100.100.100.200/latest/meta-data/' },
        { ssrfAllow: ['100.100.100.200'] }
      )?.tier
    ).toBe('metadata');
  });
});

describe('D. it can never crash a tool call', () => {
  it('D1 junk arguments return null rather than throwing', () => {
    for (const a of [
      null,
      undefined,
      'string',
      42,
      [],
      { url: null },
      { url: {} },
      { actions: 'no' },
      { actions: [null, 1] },
    ]) {
      expect(() => hit('WebFetch', a)).not.toThrow();
      expect(hit('WebFetch', a)).toBeNull();
    }
  });

  it('D2 a deeply nested cycle does not hang', () => {
    const a: Record<string, unknown> = { url: 'https://ok.example.com' };
    a.self = a;
    expect(() => hit('WebFetch', a)).not.toThrow();
  });
});

// The check has to run BEFORE the ignoredTools fast path. `webfetch`,
// `get_*`, `read_*` and `list_*` are all on that list, so a placement one
// block lower is dead code for exactly the tools that carry the gap. That is
// not hypothetical: the first wiring of this feature sat below it, and
// WebFetch still reached the metadata endpoint while `navigate` was blocked.
describe('E. placement', () => {
  it('E1 an IGNORED tool is still judged', async () => {
    const { evaluatePolicy } = await import('../policy');
    const config = {
      settings: { mode: 'standard' },
      policy: {
        ignoredTools: ['webfetch'],
        dlp: { enabled: false, scanIgnoredTools: false, reviewAction: 'review' },
        egress: { enabled: false, mode: 'off', allow: [], deny: [], allowPrivate: true },
        smartRules: [],
        dangerousWords: [],
        toolInspection: {},
        commandChecks: {},
        jailPaths: [],
        loopDetection: { enabled: false, threshold: 5, windowSeconds: 120 },
      },
    } as unknown as Parameters<typeof evaluatePolicy>[0];
    const r = await evaluatePolicy(
      config,
      'WebFetch',
      { url: 'http://169.254.169.254/latest/meta-data/' },
      { agent: 'agent' },
      {}
    );
    expect(r.decision, 'the ignored-tool fast path must not swallow this').toBe('block');
    expect(r.blockedByLabel).toMatch(/Protected Address/);
  });
});

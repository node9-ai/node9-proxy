// fw#318 P2 (design untrusted-content-proxy-p2-p5-code-design.md section 4,
// rows R1-R4): annotations reach the hook through the inventory and only add
// caution; agent-internal servers are read.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  toolRole,
  resolveToolAnnotations,
  _resetRolesCache,
  configuredRole,
  injectionOrigin,
} from '../exposure/roles';
import { updateServerDiscovery, readMcpToolsConfig } from '../daemon/mcp-tools';

const POLICY = {
  enabled: true,
  spotlight: true,
  afterExposure: 'ask-once' as const,
  orgDomains: [] as string[],
  roles: {} as Record<string, Record<string, 'source' | 'action' | 'read'>>,
  trustedRecipients: [] as string[],
};

let home: string;
let origHome: string | undefined;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-roles-'));
  origHome = process.env.HOME;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  _resetRolesCache();
});

afterEach(() => {
  if (origHome !== undefined) process.env.HOME = origHome;
  else delete process.env.HOME;
  fs.rmSync(home, { recursive: true, force: true });
  _resetRolesCache();
});

describe('R1: the inventory keeps annotations and updates them on a match', () => {
  it('stores the hints on discovery and refreshes them for the same names', () => {
    expect(
      updateServerDiscovery(
        'k1',
        [
          { name: 'get_message', annotations: { readOnlyHint: true, openWorldHint: true } },
          { name: 'archive_thread', description: 'x' },
        ],
        'gmail'
      )
    ).toBe('new');
    expect(readMcpToolsConfig().k1.tools[0].annotations).toEqual({
      readOnlyHint: true,
      openWorldHint: true,
    });
    expect(
      updateServerDiscovery(
        'k1',
        [
          { name: 'get_message', annotations: { readOnlyHint: true, openWorldHint: true } },
          { name: 'archive_thread', description: 'x', annotations: { destructiveHint: true } },
        ],
        'gmail'
      )
    ).toBe('match');
    expect(readMcpToolsConfig().k1.tools[1].annotations).toEqual({ destructiveHint: true });
    expect(readMcpToolsConfig().k1.status).toBe('pending');
  });
});

describe('R2: a declared destructiveHint makes the call destructive', () => {
  it('a harmless name with destructiveHint is destructive; without it, not', () => {
    updateServerDiscovery(
      'k1',
      [
        { name: 'archive_thread', annotations: { destructiveHint: true } },
        { name: 'label_thread' },
      ],
      'gmail'
    );
    expect(toolRole('mcp__gmail__archive_thread', POLICY)).toEqual({
      source: true,
      action: true,
      destructive: true,
    });
    expect(toolRole('mcp__gmail__label_thread', POLICY).destructive).toBe(false);
  });
});

describe('R3: relaxing hints never relax by themselves', () => {
  it('readOnlyHint keeps source and action; an explicit role removes them', () => {
    updateServerDiscovery(
      'k1',
      [{ name: 'list_labels', annotations: { readOnlyHint: true, openWorldHint: false } }],
      'gmail'
    );
    expect(toolRole('mcp__gmail__list_labels', POLICY)).toEqual({
      source: true,
      action: true,
      destructive: false,
    });
    const withRole = { ...POLICY, roles: { gmail: { list_labels: 'read' as const } } };
    expect(toolRole('mcp__gmail__list_labels', withRole)).toEqual({ source: false, action: false });
  });
});

describe('R4: name matching', () => {
  it('two records sharing a name resolve to unannotated; folded names match', () => {
    updateServerDiscovery('k1', [{ name: 't', annotations: { destructiveHint: true } }], 'gmail');
    updateServerDiscovery('k2', [{ name: 't', annotations: { destructiveHint: true } }], 'gmail');
    expect(resolveToolAnnotations('gmail', 't')).toBeNull();
    _resetRolesCache();
    updateServerDiscovery('k3', [{ name: 'q', annotations: { destructiveHint: true } }], 'my.crm');
    // Claude Code names the server `my_crm`.
    expect(resolveToolAnnotations('my_crm', 'q')).toEqual({ destructiveHint: true });
    expect(resolveToolAnnotations('other', 'q')).toBeNull();
  });
});

describe('second review 5: a long-lived process sees servers discovered later', () => {
  it('rereads the inventory when the file changes, without a cache reset', () => {
    expect(resolveToolAnnotations('crm', 'drop_table')).toBeNull();
    updateServerDiscovery(
      'k-late',
      [{ name: 'drop_table', annotations: { destructiveHint: true } }],
      'crm'
    );
    expect(resolveToolAnnotations('crm', 'drop_table')).toEqual({ destructiveHint: true });
  });
});

describe('agent-internal servers', () => {
  it("Claude Code's own session and view tools are read, not source or action", () => {
    expect(toolRole('mcp__ccd_session__mark_chapter', POLICY)).toEqual({
      source: false,
      action: false,
    });
    expect(toolRole('mcp__ccd_view__show_pane', POLICY)).toEqual({ source: false, action: false });
    expect(toolRole('mcp__visualize__show_widget', POLICY)).toEqual({
      source: false,
      action: false,
    });
    // The browser is not internal: its reads are sources.
    expect(toolRole('mcp__Claude_Browser__get_page_text', POLICY)).toEqual({
      source: true,
      action: false,
    });
  });
});

// Code review of the fw#318 fixes (finding 6): the gate (toolRole) and the
// injection scanner (injectionOrigin) read a configured role through one
// lookup, so they agree for every role and every spelling of the tool name.
describe('configuredRole: one lookup for the gate and the scanner', () => {
  const roles = { gmail: { fetch_page: 'read' as const, send: 'action' as const } };
  const policy = { ...POLICY, roles };

  it('finds the role as written and lower-cased, undefined otherwise', () => {
    expect(configuredRole({ server: 'gmail', bare: 'fetch_page' }, policy)).toBe('read');
    expect(configuredRole({ server: 'gmail', bare: 'Fetch_Page' }, policy)).toBe('read');
    expect(configuredRole({ server: 'gmail', bare: 'other' }, policy)).toBeUndefined();
    expect(configuredRole({ server: 'slack', bare: 'fetch_page' }, policy)).toBeUndefined();
  });

  it('a tool the gate reads as `read` is trusted by the scanner, in either case', () => {
    for (const name of ['mcp__gmail__fetch_page', 'mcp__gmail__Fetch_Page']) {
      expect(toolRole(name, policy)).toEqual({ source: false, action: false });
      expect(injectionOrigin(name, policy, false)).toEqual({ untrusted: false });
    }
  });

  it('any other role leaves the scanner to its own list', () => {
    expect(injectionOrigin('mcp__gmail__send', policy, false)).toEqual({});
    expect(injectionOrigin('mcp__gmail__other', policy, false)).toEqual({});
    expect(injectionOrigin('mcp__gmail__other', policy, true)).toEqual({ untrusted: true });
    expect(injectionOrigin('mcp__gmail__fetch_page', { ...policy, enabled: false }, false)).toEqual(
      {}
    );
  });
});

// Reports cleanup P1 (fw#421): the cheap inconsistencies between the report
// commands. One vocabulary for the mode, aligned blast columns, no "today ago",
// the three internal-address states over MCP, and node9's own key out of the
// credential list. Each case pins one rendered string, not a gate decision.
import { describe, it, expect, beforeEach } from 'vitest';
import React from 'react';
import { render } from 'ink-testing-library';
import { BlockedPanel } from '../cli/render/ink/panels/BlockedPanel';
import { checkEgress } from '../posture/egress';
import { internalAddressLine } from '../mcp-server/index';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { _resetConfigCache, getConfig } from '../config';
import { buildChecksReport, renderChecks } from '../cli/commands/checks';
import { wouldHaveVerb, type ScanSummary } from '../scan-summary';
import { checkCoverage } from '../posture/coverage';
import { labelColumnWidth } from '../cli/commands/blast';
import { relativeAgo } from '../cli/render/scan-derive';
import { describeInternalState, readInternalState } from '../cli/commands/egress';
import { homeCredentialFiles } from '../credential-files';

const home = () => os.homedir();
const writeJson = (rel: string, obj: unknown) => {
  const p = path.join(home(), rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj));
};

describe('item 1: the mode is named audit in every human text', () => {
  beforeEach(() => {
    writeJson('.node9/config.json', { settings: { mode: 'observe' } });
    _resetConfigCache();
  });

  it('checks prints audit for a config that says observe', () => {
    const text = renderChecks({ ...buildChecksReport(getConfig()), mode: 'observe' });
    expect(text).toContain('mode: audit');
    expect(text).not.toContain('observe');
  });

  it('scan says audit in the would-have-blocked verb', () => {
    const summary = { policy: { mode: 'observe', recordOnly: true } } as unknown as ScanSummary;
    expect(wouldHaveVerb(summary)).toBe('logged only (audit mode, nothing enforced)');
  });

  it('posture Coverage names audit mode when a wired agent is only watched', () => {
    writeJson('.claude/settings.json', {
      hooks: { PreToolUse: [{ matcher: '*', hooks: [{ command: 'node9 check' }] }] },
    });
    const findings = checkCoverage({ home: home(), cwd: home() });
    const f = findings.find((x) => x.category === 'Coverage');
    expect(f?.title).toContain('audit mode');
    expect(JSON.stringify(f)).not.toMatch(/observe mode/);
  });
});

describe('item 1 (review): the default scan view and posture egress say audit too', () => {
  beforeEach(() => {
    writeJson('.node9/config.json', { settings: { mode: 'observe' } });
    _resetConfigCache();
  });

  it('the Ink BLOCKED panel footer names audit mode', () => {
    const summary = {
      policy: { mode: 'observe', recordOnly: true },
      sections: [
        {
          id: 'default',
          label: 'Default Rules',
          subtitle: '',
          sourceType: 'default',
          blockedCount: 1,
          reviewCount: 0,
          rules: [{ name: 'block-rm-rf', verdict: 'block', reason: '', findings: [{}] }],
        },
      ],
    } as unknown as ScanSummary;
    const frame = render(React.createElement(BlockedPanel, { summary, width: 120 })).lastFrame();
    expect(frame).toContain('audit mode: these were logged');
    expect(frame).not.toContain('observe');
  });

  it('posture egress findings do not say observe mode', () => {
    writeJson('.node9/config.json', {
      settings: { mode: 'observe' },
      policy: { egress: { enabled: true, mode: 'block' } },
    });
    _resetConfigCache();
    const text = JSON.stringify(checkEgress({ home: home(), cwd: home() }));
    expect(text).not.toMatch(/observe mode/);
  });
});

describe('item 4 (review): internal addresses when egress is off', () => {
  it('egress off: the allowlist is not consulted, so listed reads as allowed', () => {
    expect(internalAddressLine({ enabled: false, ssrfStrict: false, allowPrivate: false })).toMatch(
      /^Internal addresses: allowed/
    );
    expect(internalAddressLine({ enabled: true, ssrfStrict: false, allowPrivate: false })).toMatch(
      /^Internal addresses: listed/
    );
    expect(internalAddressLine({ enabled: false, ssrfStrict: true })).toMatch(
      /^Internal addresses: blocked/
    );
  });
});

describe('item 2: the blast label column fits its longest label', () => {
  it('keeps 38 for short labels and widens for a long one', () => {
    expect(labelColumnWidth(['~/.ssh/id_rsa', '~/.npmrc'])).toBe(38);
    const long = '~/.config/gcloud/application_default_credentials.json';
    expect(labelColumnWidth(['~/.ssh/id_rsa', long])).toBe(long.length + 2);
  });
});

describe('item 3: relativeAgo never reads "today ago"', () => {
  const now = new Date('2026-10-31T12:00:00Z');
  const daysBack = (d: number) => new Date(now.getTime() - d * 86_400_000).toISOString();
  it('today, yesterday, N days ago, 90d+ ago', () => {
    expect(relativeAgo(daysBack(0), now)).toBe('today');
    expect(relativeAgo(daysBack(1), now)).toBe('yesterday');
    expect(relativeAgo(daysBack(5), now)).toBe('5d ago');
    expect(relativeAgo(daysBack(120), now)).toBe('90d+ ago');
    expect(relativeAgo('not a date', now)).toBe('?');
  });
});

describe('item 4: internal addresses have three states, with one description each', () => {
  it('describes allowed, listed and blocked the way the CLI does', () => {
    expect(readInternalState({ ssrfStrict: false, allowPrivate: false })).toBe('listed');
    expect(describeInternalState('listed')).toContain('allowlist');
    expect(describeInternalState('blocked')).toBe('blocked');
    expect(describeInternalState('allowed')).toContain('without listing');
  });
});

describe('item 9: node9 credentials are not a credential-file finding', () => {
  it('the shared list has no ~/.node9/credentials.json row', () => {
    const labels = homeCredentialFiles('/h').map((c) => c.label);
    expect(labels).not.toContain('~/.node9/credentials.json');
    expect(labels).toContain('~/.ssh/id_rsa');
  });
});

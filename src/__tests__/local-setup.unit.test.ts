import { describe, expect, it } from 'vitest';
import { buildChecklist, diffChoices, renderSummary, type LocalState } from '../cli/local-setup';
const fresh: LocalState = {
  fresh: true,
  managed: false,
  shields: 'off',
  dlp: 'on',
  egressEnabled: false,
  serviceInstalled: false,
  serviceEnabled: false,
  mode: 'standard',
};
describe('local setup choices', () => {
  it('recommends protection without turning on egress', () => {
    expect(
      buildChecklist(fresh)
        .filter((i) => i.checked)
        .map((i) => i.key)
    ).toEqual(['shields', 'dlp', 'service']);
  });
  it('applies preselected shields and service on fresh installs', () => {
    expect(diffChoices(fresh, ['shields', 'dlp', 'service'])).toEqual([
      { key: 'shields', from: 'off', to: true },
      { key: 'service', from: 'off', to: true },
    ]);
  });
  it('turns off shipped DLP defaults when explicitly unselected', () => {
    expect(diffChoices(fresh, [])).toContainEqual({ key: 'dlp', from: 'on', to: false });
  });
  it('preserves partial settings without rewriting them', () => {
    const state = { ...fresh, fresh: false, dlp: 'partial' as const, shields: 'partial' as const };
    expect(diffChoices(state, [])).toEqual([]);
    expect(diffChoices(state, [], { dlp: false })).toEqual([
      { key: 'dlp', from: 'partial', to: false },
    ]);
    expect(diffChoices(state, [], { shields: true })).toEqual([
      { key: 'shields', from: 'partial', to: true },
    ]);
  });
  it('makes no changes to unchanged existing rows', () => {
    expect(diffChoices({ ...fresh, fresh: false }, ['dlp'])).toEqual([]);
  });
  it('keeps workspace policy read-only while service remains a local choice', () => {
    expect(diffChoices({ ...fresh, managed: true }, ['egress', 'service'])).toEqual([
      { key: 'service', from: 'off', to: true },
    ]);
  });
  it('does not imply runtime protection from configuration', () => {
    const summary = renderSummary({
      agents: [],
      applied: [],
      state: fresh,
      serviceRunning: false,
      cloud: 'none',
    });
    expect(summary).toContain('No agents wired yet');
    expect(summary).toContain('not running');
    expect(summary).not.toContain('protecting');
    expect(summary).not.toContain('Undo everything');
  });
});

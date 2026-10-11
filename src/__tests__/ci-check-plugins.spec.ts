// T.3 — a plugin marketplace installed at run time without a pin (2026-10-11). WRITTEN BEFORE
// THE IMPLEMENTATION. claude-code-action's `plugin_marketplaces` + `plugins` fetch code and
// prompts (plugins can ship hooks) from another repository on every run, next to the token.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflowPlugins } from '../ci-check/workflows';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'plugins');
const run = (f: string) =>
  analyzeWorkflowPlugins(`.github/workflows/${f}`, fs.readFileSync(path.join(FX, f), 'utf8'));

describe('T.3 — CI-3.plugin-unpinned', () => {
  it('a third-party marketplace, unpinned: medium', () => {
    const [f, ...rest] = run('third-party-marketplace.yml');
    expect(rest).toHaveLength(0);
    expect(f.rule).toBe('CI-3.plugin-unpinned');
    expect(f.severity).toBe('medium');
    expect(f.signals.join(' ')).toMatch(/example-person\/some-plugins/);
  });

  it("the vendor's own marketplace: clean", () => {
    expect(run('vendor-marketplace.yml')).toHaveLength(0);
  });

  it('a marketplace pinned to a commit: clean', () => {
    expect(run('pinned-marketplace.yml')).toHaveLength(0);
  });

  it('the repository itself (`./.`) is not a third party', () => {
    const y = fs
      .readFileSync(path.join(FX, 'third-party-marketplace.yml'), 'utf8')
      .replace('https://github.com/example-person/some-plugins.git', './.');
    expect(analyzeWorkflowPlugins('.github/workflows/x.yml', y)).toHaveLength(0);
  });

  it('a marketplace of the same owner is not a third party', () => {
    const y = fs.readFileSync(path.join(FX, 'third-party-marketplace.yml'), 'utf8');
    expect(analyzeWorkflowPlugins('.github/workflows/x.yml', y, 'Example-Person')).toHaveLength(0);
    expect(analyzeWorkflowPlugins('.github/workflows/x.yml', y, 'someone-else')).toHaveLength(1);
  });
});

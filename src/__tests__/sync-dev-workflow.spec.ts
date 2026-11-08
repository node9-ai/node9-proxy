import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';

/**
 * The sync-dev workflow merges main back into dev so the next dev -> main PR
 * starts from the released version.
 *
 * Wiring assertions, as in release-signing.spec.ts: the only real exercise is
 * a release. They exist because the first version ran on `push` to main, which
 * fired on the dev -> main merge, while the release job was still running. The
 * version commits the release pushes afterwards carry `[skip ci]`, so no push
 * workflow ever saw them, and dev stayed one version behind main after every
 * release until someone fast-forwarded it by hand.
 */

const workflowsDir = join(__dirname, '..', '..', '.github', 'workflows');
const read = (file: string) => parse(readFileSync(join(workflowsDir, file), 'utf8'));

type Step = { name?: string; run?: string; with?: Record<string, unknown> };
const syncDev = read('sync-dev.yml') as {
  on: Record<string, { workflows?: string[]; types?: string[]; branches?: string[] } | null>;
  concurrency?: { group?: string; 'cancel-in-progress'?: boolean };
  jobs: { sync: { if?: string; steps: Step[] } };
};
const release = read('release.yml') as { name: string; on: { push?: { branches?: string[] } } };

describe('sync-dev workflow', () => {
  it('runs after the release workflow finishes, not on the push that starts it', () => {
    expect(syncDev.on.push, 'a push trigger races the release job').toBeUndefined();
    const after = syncDev.on.workflow_run;
    // Matched by the release workflow's `name:`, so a rename there must fail here.
    expect(after?.workflows).toEqual([release.name]);
    expect(after?.types).toEqual(['completed']);
    expect(after?.branches).toEqual(release.on.push?.branches);
  });

  it('does not read push-only event fields, which a workflow_run event lacks', () => {
    const text = readFileSync(join(workflowsDir, 'sync-dev.yml'), 'utf8');
    expect(text).not.toMatch(/github\.event\.head_commit/);
    expect(syncDev.jobs.sync.if ?? '').not.toMatch(/head_commit/);
  });

  it('merges origin/main into dev, one run at a time', () => {
    const merge = syncDev.jobs.sync.steps.find((s) => s.name === 'Merge main into dev');
    expect(merge?.run).toMatch(/git merge origin\/main/);
    expect(merge?.run).toMatch(/git push origin dev/);
    expect(syncDev.concurrency?.group).toBeTruthy();
    expect(syncDev.concurrency?.['cancel-in-progress']).toBe(false);
  });
});

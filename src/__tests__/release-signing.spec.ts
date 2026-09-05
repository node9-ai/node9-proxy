import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';

/**
 * The release workflow signs the artifacts it attaches to each GitHub release.
 *
 * These are ordering and wiring assertions rather than behaviour tests, because
 * the only way to exercise the real thing is to cut a release. They exist
 * because the first version of the signing steps was silently dead: the
 * detection step read `git tag --points-at HEAD` from the end of the job, but
 * the engine-sync step commits on top and moves HEAD off the tagged commit, so
 * detection would have answered "no release" on every run, forever, without
 * failing anything.
 */

type Step = {
  name?: string;
  id?: string;
  uses?: string;
  if?: string;
  with?: Record<string, unknown>;
};

const workflow = parse(
  readFileSync(join(__dirname, '..', '..', '.github', 'workflows', 'release.yml'), 'utf8')
) as { jobs: { release: { permissions: Record<string, string>; steps: Step[] } } };

const steps = workflow.jobs.release.steps;
const indexOf = (name: string) => steps.findIndex((s) => s.name === name);

describe('release workflow signing', () => {
  it('detects the release before any step that can move HEAD', () => {
    const release = indexOf('Release');
    const detect = indexOf('Detect whether this run cut a release');
    const engineSync = indexOf('Sync @node9/policy-engine version to @node9/proxy');

    expect(release).toBeGreaterThanOrEqual(0);
    expect(detect).toBeGreaterThanOrEqual(0);
    expect(engineSync).toBeGreaterThanOrEqual(0);

    // The whole point: detection sits between semantic-release and the first
    // step that adds a commit. Moving it after engine-sync makes signing dead.
    expect(detect).toBeGreaterThan(release);
    expect(detect).toBeLessThan(engineSync);
  });

  it('signs the same dist files that are attached to the release', () => {
    const attest = steps.find((s) => s.id === 'attest');
    // Pinned by commit SHA, not by tag: a tag can be moved onto other code.
    expect(attest?.uses).toMatch(/^actions\/attest-build-provenance@[0-9a-f]{40}$/);

    const subjects = String(attest?.with?.['subject-path'] ?? '')
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);

    // package.json's semantic-release config is the one that actually loads,
    // and it attaches these globs to the GitHub release. The signature has to
    // cover exactly what people download.
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'));
    const github = (pkg.release.plugins as unknown[]).find(
      (p): p is [string, { assets: string[] }] =>
        Array.isArray(p) && p[0] === '@semantic-release/github'
    );

    expect(subjects.sort()).toEqual([...github![1].assets].sort());
  });

  it('guards both signing steps on the detection result', () => {
    for (const name of [
      'Sign the release artifacts',
      'Attach the signature to the GitHub release',
    ]) {
      expect(steps[indexOf(name)]?.if).toBe("steps.released.outputs.released == 'true'");
    }
  });

  it('grants the permission the signing step needs', () => {
    expect(workflow.jobs.release.permissions.attestations).toBe('write');
    expect(workflow.jobs.release.permissions['id-token']).toBe('write');
  });
});

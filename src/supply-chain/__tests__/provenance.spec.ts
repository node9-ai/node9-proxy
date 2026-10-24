// Reading the source repository out of registry provenance, and picking the
// release before this one (node9Firewall#385). Synthetic records only.
import { describe, it, expect } from 'vitest';
import { normalizeRepo, npmRepoOf, pypiRepoOf, previousRelease } from '../provenance';

const slsa = (predicate: object, predicateType = 'https://slsa.dev/provenance/v1') => ({
  attestations: [
    {
      predicateType,
      bundle: {
        dsseEnvelope: { payload: Buffer.from(JSON.stringify({ predicate })).toString('base64') },
      },
    },
  ],
});

describe('normalizeRepo', () => {
  it.each([
    ['https://github.com/Acme/Tool', 'github.com/acme/tool'],
    ['https://github.com/acme/tool.git', 'github.com/acme/tool'],
    ['git+https://github.com/acme/tool@refs/heads/main', 'github.com/acme/tool'],
    ['acme/tool', 'github.com/acme/tool'],
  ])('%s -> %s', (raw, want) => {
    expect(normalizeRepo(raw)).toBe(want);
  });
  it('a short name on GitLab keeps its host', () => {
    expect(normalizeRepo('group/tool', 'gitlab.com')).toBe('gitlab.com/group/tool');
  });
  it('a value that is not a repository is null', () => {
    expect(normalizeRepo('tool')).toBeNull();
  });
});

describe('npmRepoOf', () => {
  it('reads SLSA v1 (workflow.repository)', () => {
    const doc = slsa({
      buildDefinition: {
        externalParameters: { workflow: { repository: 'https://github.com/acme/tool' } },
      },
    });
    expect(npmRepoOf(doc)).toBe('github.com/acme/tool');
  });
  it('reads SLSA v0.2 (invocation.configSource.uri)', () => {
    const doc = slsa(
      { invocation: { configSource: { uri: 'git+https://github.com/acme/tool@refs/heads/main' } } },
      'https://slsa.dev/provenance/v0.2'
    );
    expect(npmRepoOf(doc)).toBe('github.com/acme/tool');
  });
  it('a publish attestation alone, or an unreadable payload, names no repository', () => {
    expect(
      npmRepoOf({ attestations: [{ predicateType: 'https://github.com/npm/attestation/x' }] })
    ).toBeNull();
    expect(
      npmRepoOf({
        attestations: [
          {
            predicateType: 'https://slsa.dev/provenance/v1',
            bundle: { dsseEnvelope: { payload: '!!' } },
          },
        ],
      })
    ).toBeNull();
    expect(npmRepoOf(null)).toBeNull();
  });
});

describe('pypiRepoOf', () => {
  it('reads the Trusted Publisher repository', () => {
    const doc = { attestation_bundles: [{ publisher: { kind: 'GitHub', repository: 'Acme/py' } }] };
    expect(pypiRepoOf(doc)).toBe('github.com/acme/py');
  });
  it('a Google publisher is named by its service account', () => {
    const doc = {
      attestation_bundles: [{ publisher: { kind: 'Google', email: 'Release@Example.test' } }],
    };
    expect(pypiRepoOf(doc)).toBe('google:release@example.test');
  });
  it('a GitLab publisher', () => {
    const doc = { attestation_bundles: [{ publisher: { kind: 'GitLab', repository: 'g/py' } }] };
    expect(pypiRepoOf(doc)).toBe('gitlab.com/g/py');
  });
});

describe('previousRelease', () => {
  it('npm: the highest final version below, prereleases skipped', () => {
    expect(previousRelease('npm', ['1.0.0', '1.2.0-beta.1', '1.1.0', '1.2.0'], '1.2.0')).toBe(
      '1.1.0'
    );
    expect(previousRelease('npm', ['1.0.0'], '1.0.0')).toBeNull();
    expect(previousRelease('npm', ['1.0.0'], 'not-a-version')).toBeUndefined();
  });
  it('PyPI: numeric order, pre-releases skipped', () => {
    expect(previousRelease('PyPI', ['3.9', '3.10', '3.11rc1', '3.11'], '3.11')).toBe('3.10');
    expect(previousRelease('PyPI', ['2026.9.1', '2026.10.23'], '2026.10.23')).toBe('2026.9.1');
    expect(previousRelease('PyPI', ['1.0'], '1.0')).toBeNull();
    expect(previousRelease('PyPI', ['1.0'], '1.1rc1')).toBeUndefined();
  });
});

// Public material under ~/.ssh is not a key (node9Firewall#308, JAIL-16).
// The `.ssh` rule judged every file under the directory, so `known_hosts`,
// `authorized_keys` and `*.pub` were blocked like a private key, and exporting
// a public key was a reviewed copy.
//
// Rows assert at evaluatePolicy, the layer that gates, and at the path
// predicate that the five copies of the rule share.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import { analyzeFsOperation } from '../shell/index';
import { matchSensitivePath } from '../dlp/index';
import { isPublicSshMaterial } from '../files/paths';
import { checkIdForRule } from '../catalog';
import projectJail from '../shields/builtin/project-jail.json';
import type { SmartRule } from '../types';

const config: PolicyConfig = {
  policy: {
    sandboxPaths: [],
    dangerousWords: [],
    ignoredTools: [],
    smartRules: projectJail.smartRules as SmartRule[],
    toolInspection: { bash: 'command', shell: 'command', run_shell_command: 'command' },
    dlp: { enabled: false, scanIgnoredTools: false },
  },
  settings: { mode: 'standard' },
} as unknown as PolicyConfig;

async function bash(command: string): Promise<string> {
  const v = await evaluatePolicy(config, 'Bash', { command }, { agent: 'claude' }, {});
  return String(v.decision);
}
async function tool(name: string, args: Record<string, unknown>): Promise<string> {
  const v = await evaluatePolicy(config, name, args, { agent: 'claude' }, {});
  return String(v.decision);
}

describe('reading public material is allowed', () => {
  it.each([
    'cat ~/.ssh/known_hosts',
    'cat ~/.ssh/authorized_keys',
    'cat ~/.ssh/id_rsa.pub',
    'cat ~/.ssh/id_ed25519.pub',
    'head -1 $HOME/.ssh/id_ed25519.pub',
    'cat /home/u/.ssh/known_hosts.old',
    'grep github.com ~/.ssh/known_hosts',
    'grep -q github.com ~/.ssh/known_hosts || ssh-keyscan github.com >> ~/.ssh/known_hosts',
    'wc -l ~/.ssh/authorized_keys2',
    'cat ~/.ssh/*.pub',
    'cat ~/.ssh/id_*.pub',
    'for f in ~/.ssh/*.pub; do cat "$f"; done',
    "sh -c 'cat ~/.ssh/id_rsa.pub'",
    'cat ~/.ssh/id_rsa.pub | pbcopy',
  ])('allow: %s', async (command) => {
    expect(await bash(command)).toBe('allow');
  });

  it('exporting a public key is not a reviewed copy', async () => {
    expect(await bash('cp ~/.ssh/id_rsa.pub ./deploy.pub')).toBe('allow');
    expect(await bash('scp ~/.ssh/id_ed25519.pub host:/tmp/')).not.toBe('block');
  });
});

describe('private material is still blocked', () => {
  it.each([
    'cat ~/.ssh/id_rsa',
    'cat ~/.ssh/id_ed25519',
    'cat ~/.ssh/id_ecdsa',
    'cat ~/.ssh/config',
    'cat ~/.ssh/deploy_key',
    'cat ~/.ssh/id_rsa.pub.bak',
    'cat ~/.ssh/keys/deploy.pub',
    'cat ~/.ssh/known_hosts.d/extra',
    'cat ~/.ssh/*',
    'cat ~/.ssh/id_*',
    'cat ~/.ssh/id_rsa.pub ~/.ssh/id_rsa',
    'cat ~/.ssh/id_rsa ~/.ssh/id_rsa.pub',
    'cat ~/.ssh/{id_rsa,id_rsa.pub}',
    'cat ~/.ssh/*.pu?',
    'grep -r x ~/.ssh',
    'for f in ~/.ssh/*; do cat "$f"; done',
    'cat ~/.ssh/.pub/../id_rsa',
  ])('block: %s', async (command) => {
    expect(await bash(command)).toBe('block');
  });
});

describe('a private key cannot be laundered under a public name', () => {
  it.each([
    'cp ~/.ssh/id_rsa ~/.ssh/x.pub',
    'mv ~/.ssh/id_rsa ~/.ssh/id_rsa.pub',
    'ln -s ~/.ssh/id_rsa ~/.ssh/k.pub',
    'cp ~/.ssh/id_ed25519 ~/.ssh/known_hosts',
    'cp ~/.ssh/id_rsa ~/.ssh/authorized_keys',
  ])('the copy is reviewed, not quiet: %s', async (command) => {
    expect(await bash(command)).toBe('review');
  });

  it('a rename that stays private stays quiet, as before', () => {
    expect(analyzeFsOperation('mv ~/.ssh/id_rsa ~/.ssh/id_rsa.bak')).toBeNull();
  });

  it('writing the key into a public name through a read is still the read', async () => {
    expect(await bash('cat ~/.ssh/id_rsa > ~/.ssh/k.pub')).toBe('block');
  });
});

describe('file tools: reads of public material pass, private and writes do not', () => {
  it.each([
    ['Read', { file_path: '/home/u/.ssh/known_hosts' }],
    ['Read', { file_path: '/home/u/.ssh/id_rsa.pub' }],
    ['Read', { file_path: '/home/u/.ssh/authorized_keys' }],
    ['Grep', { pattern: 'github', path: '/home/u/.ssh/known_hosts' }],
  ])('%s %j is not blocked by the shield rule', async (name, args) => {
    expect(await tool(name, args)).toBe('allow');
  });

  it.each([
    ['Read', { file_path: '/home/u/.ssh/id_rsa' }],
    ['Read', { file_path: '/home/u/.ssh/config' }],
    ['Read', { file_path: '/home/u/.ssh/id_rsa.pub.bak' }],
    ['Read', { file_path: '/home/u/.ssh/keys/deploy.pub' }],
    ['Read', { file_path: '/home/u/.ssh' }],
    ['Write', { file_path: '/home/u/.ssh/authorized_keys', content: 'ssh-ed25519 AAAA x' }],
    ['Edit', { file_path: '/home/u/.ssh/known_hosts', old_string: 'a', new_string: 'b' }],
    ['Write', { file_path: '/home/u/.ssh/id_rsa.pub', content: 'x' }],
    ['MultiEdit', { file_path: '/home/u/.ssh/authorized_keys', edits: [] }],
    // /code-review: a write tool the shield has never heard of. The write
    // rule covers every tool that is not a known reader.
    ['mcp__fs__write_file', { file_path: '/home/u/.ssh/authorized_keys', content: 'x' }],
    ['append_file', { file_path: '/home/u/.ssh/known_hosts', content: 'x' }],
  ])('%s %j is blocked', async (name, args) => {
    expect(await tool(name, args)).toBe('block');
  });

  it('the file-tool gate: a read passes, a write of the same path does not', () => {
    const p = '/home/u/.ssh/authorized_keys';
    expect(matchSensitivePath(p, p, { readOnly: true })).toBeNull();
    expect(matchSensitivePath(p, p)?.severity).toBe('block');
    expect(matchSensitivePath(p, p, { readOnly: false })?.severity).toBe('block');
    const key = '/home/u/.ssh/id_rsa';
    expect(matchSensitivePath(key, key, { readOnly: true })?.severity).toBe('block');
  });
});

describe('isPublicSshMaterial: a closed list, by name, directly inside .ssh', () => {
  it.each([
    '~/.ssh/known_hosts',
    '/home/u/.ssh/known_hosts.old',
    '/home/u/.ssh/authorized_keys',
    '/root/.ssh/authorized_keys2',
    '.ssh/id_rsa.pub',
    'C:\\Users\\u\\.ssh\\id_ed25519.pub',
    '~/.ssh/*.pub',
    '/home/u/.SSH/Known_Hosts',
  ])('public: %s', (p) => expect(isPublicSshMaterial(p)).toBe(true));

  it.each([
    '~/.ssh/id_rsa',
    '~/.ssh/config',
    '~/.ssh',
    '~/.ssh/',
    '~/.ssh/id_rsa.pub.bak',
    '~/.ssh/keys/deploy.pub',
    '~/.ssh/known_hosts_backup',
    '~/.ssh/pub',
    '~/.ssh/.pub',
    '~/project/id_rsa.pub',
    '~/.sshx/known_hosts',
    '~/.ssh/*',
    '~/.ssh/*.pu?',
    '~/.ssh/{id_rsa,x.pub}x',
  ])('not public: %s', (p) => expect(isPublicSshMaterial(p)).toBe(false));
});

describe('the write rule stays under the credential-files check', () => {
  it('a write to a trust file is the same check a read of a key is', () => {
    expect(checkIdForRule('shield:project-jail:block-write-ssh-trust-files')).toBe(
      'data.credential-files'
    );
    expect(checkIdForRule('shield:project-jail:block-read-ssh-any-tool')).toBe(
      'data.credential-files'
    );
  });
});

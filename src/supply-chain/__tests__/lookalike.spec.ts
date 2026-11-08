// The near-miss rules of the lookalike check (node9Firewall#385, wave 3),
// against a small list; the generated list is exercised once at the end.
import { describe, it, expect } from 'vitest';
import { editDistance, nearMiss, nearMissIn, describeNearMiss } from '../lookalike';

const NPM = [
  'request',
  'async',
  'buffer-xor',
  'axios',
  'next',
  '@azure/arm-quota',
  '@types/node',
  'is',
];
const PYPI = ['django', 'numpy', 'setuptools', 'simplejson', 'matplotlib', 'requests', 'six'];

describe('editDistance', () => {
  it.each([
    ['dajngo', 'django', 1],
    ['djago', 'django', 1],
    ['djanga', 'django', 1],
    ['requuest', 'request', 1],
    ['aysnc', 'async', 1],
    ['numipy', 'numpy', 1],
    ['matplatlib', 'matplotlib', 1],
    ['django', 'django', 0],
    ['abc', 'xyz', 3],
  ])('%s vs %s is %i', (a, b, d) => {
    expect(editDistance(a, b, 3)).toBe(d);
  });
  it('stops at the cap', () => {
    expect(editDistance('abcdefgh', 'zyxwvuts', 2)).toBe(3);
    expect(editDistance('react', 'vue', 3)).toBe(4);
  });
});

describe('nearMissIn', () => {
  it.each([
    ['PyPI', 'dajngo', 'django', 'edit'],
    ['PyPI', 'PyYMAL', 'pyyaml', 'edit'],
    ['PyPI', 'numipy', 'numpy', 'edit'],
    ['PyPI', 'smplejson', 'simplejson', 'edit'],
    ['PyPI', 'matplatlib', 'matplotlib', 'edit'],
    ['PyPI', 'setup-tools', 'setuptools', 'separators'],
    ['PyPI', 'setup_tools', 'setuptools', 'separators'],
    ['PyPI', 'simple.json', 'simplejson', 'separators'],
    ['npm', 'requuest', 'request', 'edit'],
    ['npm', 'bufger-xor', 'buffer-xor', 'edit'],
    ['npm', 'aysnc', 'async', 'edit'],
    ['npm', 'buffer_xor', 'buffer-xor', 'separators'],
    // One letter off a seven-letter name; the gate, not the rule, clears the
    // real neighbour (it is old and downloaded).
    ['npm', 'requests', 'request', 'edit'],
    ['npm', 'arm-quota', '@azure/arm-quota', 'scope-dropped'],
    ['npm', 'axios-http', 'axios', 'padding'],
    ['npm', 'next-util', 'next', 'padding'],
    ['PyPI', 'django-server', 'django', 'padding'],
    ['PyPI', 'python-requests', 'requests', 'padding'],
  ] as const)('%s %s looks like %s (%s)', (eco, name, popular, rule) => {
    const list = eco === 'npm' ? NPM : PYPI;
    const m = nearMissIn(eco, name, eco === 'PyPI' ? [...PYPI, 'pyyaml'] : list);
    expect(m?.popular).toBe(popular);
    expect(m?.rule).toBe(rule);
  });
  it.each([
    // The popular name itself.
    ['npm', 'request'],
    ['PyPI', 'Django'],
    // Short popular names: one letter off a four-letter name is a different word.
    ['npm', 'nexts'],
    ['PyPI', 'sex'],
    // Distance 2 from a name under ten characters.
    ['npm', 'reqst'],
    ['npm', 'reqeusts'],
    // Padding on a short name, and a token not on the list.
    ['npm', 'is-py'],
    ['npm', 'axios-retry'],
    // The scoped tail is short.
    ['npm', 'node'],
    // Nothing alike.
    ['npm', 'left-pad'],
    ['PyPI', 'boto3'],
  ] as const)('%s %s is not a near miss', (eco, name) => {
    expect(nearMissIn(eco, name, eco === 'npm' ? NPM : PYPI)).toBeNull();
  });
  it('other ecosystems have no list', async () => {
    expect(await nearMiss('RubyGems', 'railz')).toBeNull();
  });
});

describe('the generated list', () => {
  it('holds the names the rules were written for, and misses the real neighbours', async () => {
    expect((await nearMiss('PyPI', 'dajngo'))?.popular).toBe('django');
    expect((await nearMiss('npm', 'requuest'))?.popular).toBe('request');
    expect(await nearMiss('npm', 'react-dom')).toBeNull();
    expect(await nearMiss('npm', 'react-dnd')).toBeNull();
    expect(await nearMiss('PyPI', 'requests')).toBeNull();
    expect(await nearMiss('npm', 'request')).toBeNull();
  });
  it('costs under 25 ms of CPU a name', async () => {
    // CPU time of this process, not wall-clock: on a loaded machine the wait
    // for a CPU counted as the code's own time and the row failed while the
    // matcher was fast (2026-11-08, load 25).
    const cpuNow = (): number => {
      const u = process.cpuUsage();
      return (u.user + u.system) / 1000;
    };
    await nearMiss('npm', 'warm-up');
    const names = [
      'left-pad',
      'my-company-tools',
      'requuest',
      'eslint-plugin-foo',
      'zzzz',
      '@scope/thing',
    ];
    const t0 = cpuNow();
    for (const n of names) await nearMiss('npm', n);
    expect((cpuNow() - t0) / names.length).toBeLessThan(25);
  });
  it('describes each rule in plain words', () => {
    expect(describeNearMiss({ popular: 'x', rule: 'edit', distance: 1 })).toBe('one letter off');
    expect(describeNearMiss({ popular: 'x', rule: 'padding' })).toBe('its name with a word added');
  });
});

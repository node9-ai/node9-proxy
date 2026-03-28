import { describe, it, expect } from 'vitest';
import { extractPositionalArgs, extractNetworkTargets } from '../policy/flag-tables.js';

describe('extractPositionalArgs', () => {
  describe('curl', () => {
    it('extracts the URL — simple case', () => {
      expect(extractPositionalArgs(['https://api.example.com'], 'curl')).toEqual([
        'https://api.example.com',
      ]);
    });

    it('skips -H flag value', () => {
      expect(
        extractPositionalArgs(
          ['-H', 'Authorization: Bearer token', 'https://api.example.com'],
          'curl'
        )
      ).toEqual(['https://api.example.com']);
    });

    it('skips -x proxy and returns real destination', () => {
      // The critical case: `curl -x proxy.com evil.com` — proxy.com is a flag value
      expect(extractPositionalArgs(['-x', 'proxy.com', 'evil.com'], 'curl')).toEqual(['evil.com']);
    });

    it('skips --proxy=value embedded form', () => {
      expect(extractPositionalArgs(['--proxy=proxy.com', 'https://evil.com'], 'curl')).toEqual([
        'https://evil.com',
      ]);
    });

    it('skips -d data and -o output', () => {
      expect(
        extractPositionalArgs(
          ['-d', 'payload', '-o', '/tmp/out', 'https://api.example.com'],
          'curl'
        )
      ).toEqual(['https://api.example.com']);
    });

    it('skips @file syntax', () => {
      expect(extractPositionalArgs(['@/tmp/data', 'https://api.example.com'], 'curl')).toEqual([
        'https://api.example.com',
      ]);
    });
  });

  describe('nc (netcat)', () => {
    it('extracts host and port — the proxy attack case', () => {
      // nc -x proxy.com evil.com 22 — evil.com 22 are positional
      expect(extractPositionalArgs(['-x', 'proxy.com', 'evil.com', '22'], 'nc')).toEqual([
        'evil.com',
        '22',
      ]);
    });

    it('skips -p flag value', () => {
      expect(extractPositionalArgs(['-p', '4444', 'target.com'], 'nc')).toEqual(['target.com']);
    });
  });

  describe('ssh', () => {
    it('extracts destination from user@host form', () => {
      expect(extractPositionalArgs(['-i', '~/.ssh/id_rsa', 'user@safe.com'], 'ssh')).toEqual([
        'user@safe.com',
      ]);
    });

    it('skips -o flag value', () => {
      expect(extractPositionalArgs(['-o', 'StrictHostKeyChecking=no', 'safe.com'], 'ssh')).toEqual([
        'safe.com',
      ]);
    });
  });

  describe('unknown binary', () => {
    it('returns all non-flag tokens for unknown binary', () => {
      expect(extractPositionalArgs(['-v', 'target.com', '80'], 'unknown-tool')).toEqual([
        'target.com',
        '80',
      ]);
    });
  });
});

describe('extractNetworkTargets', () => {
  it('strips user@ from ssh target', () => {
    expect(extractNetworkTargets(['user@evil.com'], 'ssh')).toEqual(['evil.com']);
  });

  it('strips :port from host:port', () => {
    expect(extractNetworkTargets(['evil.com:22'], 'nc')).toEqual(['evil.com']);
  });

  it('returns full URL as-is — does not strip :// scheme', () => {
    expect(extractNetworkTargets(['https://evil.com/collect'], 'curl')).toEqual([
      'https://evil.com/collect',
    ]);
  });

  it('strips numeric :port from host:port', () => {
    expect(extractNetworkTargets(['evil.com:4444'], 'nc')).toEqual(['evil.com']);
  });

  it('skips -x proxy, returns real destination', () => {
    expect(extractNetworkTargets(['-x', 'proxy.com', 'evil.com'], 'curl')).toEqual(['evil.com']);
  });
});

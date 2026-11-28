// node9Firewall#383, phase 3: the journal that says the before-run hook
// finished for a call.
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  checkedCallKey,
  checkedCallState,
  JOURNAL_SETTLE_MS,
  noteCheckedCall,
} from '../checked-calls';

// isolate-home gives this file its own HOME; each test starts with no journal.
const dir = () => path.join(os.homedir(), '.node9', 'checked-calls');
beforeEach(() => fs.rmSync(dir(), { recursive: true, force: true }));

const NOW = Date.parse('2026-11-28T12:00:00Z');
const LONG_AGO = NOW - JOURNAL_SETTLE_MS - 1000;
const key = (n: number | string) => `tuid:sess|toolu_${n}`;

describe('checkedCallState', () => {
  it('is unknown with no journal at all', () => {
    expect(checkedCallState(key(1), NOW)).toBe('unknown');
  });

  it('is checked for a noted call, at once', () => {
    noteCheckedCall(key(1), NOW);
    expect(checkedCallState(key(1), NOW)).toBe('checked');
  });

  it('is unknown for another call while the journal is young', () => {
    // A call that was running before the journal existed wrote no line.
    noteCheckedCall(key(1), NOW);
    expect(checkedCallState(key(2), NOW + JOURNAL_SETTLE_MS - 1000)).toBe('unknown');
  });

  it('is unchecked for another call once the journal has settled', () => {
    noteCheckedCall(key(1), LONG_AGO);
    expect(checkedCallState(key(2), NOW)).toBe('unchecked');
    expect(checkedCallState(key(1), NOW)).toBe('checked');
  });

  it('keeps the start time of the first note', () => {
    noteCheckedCall(key(1), LONG_AGO);
    noteCheckedCall(key(2), NOW);
    expect(fs.readFileSync(path.join(dir(), 'since'), 'utf-8')).toBe(String(LONG_AGO));
  });

  it('matches whole lines only', () => {
    noteCheckedCall(key(1), LONG_AGO);
    const line = fs.readFileSync(path.join(dir(), 'current.log'), 'utf-8').trim();
    // Two halves of real lines, joined: not a line of any call.
    fs.writeFileSync(path.join(dir(), 'current.log'), `x${line}\n${line}y\n`);
    expect(checkedCallState(key(1), NOW)).toBe('unchecked');
  });

  it('finds a call noted long before, behind thousands of later ones and a rotation', () => {
    noteCheckedCall(key('early'), LONG_AGO);
    const filler = 'f'.repeat(16) + '\n';
    // Past the first read window, then past the rotation size.
    fs.appendFileSync(path.join(dir(), 'current.log'), filler.repeat(10_000));
    expect(checkedCallState(key('early'), NOW)).toBe('checked');
    fs.appendFileSync(path.join(dir(), 'current.log'), filler.repeat(130_000));
    noteCheckedCall(key('late'), NOW);
    expect(fs.existsSync(path.join(dir(), 'previous.log'))).toBe(true);
    expect(fs.statSync(path.join(dir(), 'current.log')).size).toBeLessThan(100);
    expect(checkedCallState(key('early'), NOW)).toBe('checked');
    expect(checkedCallState(key('late'), NOW)).toBe('checked');
    expect(checkedCallState(key('never'), NOW)).toBe('unchecked');
  });

  it('is unknown, not unchecked, when the start time is missing or junk', () => {
    noteCheckedCall(key(1), LONG_AGO);
    fs.writeFileSync(path.join(dir(), 'since'), 'not a number');
    expect(checkedCallState(key(2), NOW)).toBe('unknown');
    fs.rmSync(path.join(dir(), 'since'));
    expect(checkedCallState(key(2), NOW)).toBe('unknown');
  });

  it('writes a hash of the key, never the key', () => {
    noteCheckedCall('tuid:secret-session|toolu_secret', NOW);
    const text = fs.readFileSync(path.join(dir(), 'current.log'), 'utf-8');
    expect(text).toMatch(/^[0-9a-f]{16}\n$/);
    expect(text).not.toContain('secret');
  });
});

describe('noteCheckedCall', () => {
  it('never throws when the store cannot be written', () => {
    fs.mkdirSync(path.join(os.homedir(), '.node9'), { recursive: true });
    fs.writeFileSync(dir(), 'a file where the directory should be');
    expect(() => noteCheckedCall(key(1), NOW)).not.toThrow();
    expect(checkedCallState(key(1), NOW)).toBe('unknown');
  });
});

describe('checkedCallKey', () => {
  const payload = { session_id: 'sess', tool_use_id: 'toolu_1' };

  it('tracks the agents whose after-run event means the call ran', () => {
    expect(checkedCallKey(payload, 'Claude Code')).toBe('tuid:sess|toolu_1');
    expect(checkedCallKey(payload, 'Codex')).toBe('tuid:sess|toolu_1');
  });

  it('tracks no other agent, and no call without its own id', () => {
    expect(checkedCallKey(payload, 'Antigravity')).toBeNull();
    expect(checkedCallKey(payload, undefined)).toBeNull();
    expect(checkedCallKey({ session_id: 'sess' }, 'Claude Code')).toBeNull();
  });
});

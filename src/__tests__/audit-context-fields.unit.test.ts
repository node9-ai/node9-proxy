// Context fields on the local audit row (shipper-context-fields.md):
// workingDir / platform / shellType, so the SaaS event-detail Context block
// can show WHERE an action ran, not just its session.
//
// fs.appendFileSync is spied (not mocked away) so we assert the exact JSON
// line without touching the real ~/.node9/audit.log.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import { appendLocalAudit, filePathFromArgs, LOCAL_AUDIT_LOG } from '../audit/index';

let written: Array<{ path: string; line: string }> = [];

beforeEach(() => {
  written = [];
  vi.spyOn(fs, 'existsSync').mockReturnValue(true);
  vi.spyOn(fs, 'appendFileSync').mockImplementation((p, data) => {
    written.push({ path: String(p), line: String(data) });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

function lastRow(): Record<string, unknown> {
  const e = written.find((w) => w.path === LOCAL_AUDIT_LOG);
  expect(e).toBeDefined();
  return JSON.parse(e!.line) as Record<string, unknown>;
}

describe('appendLocalAudit — context fields', () => {
  it('always records the platform', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect(lastRow().platform).toBe(os.platform());
  });

  it('records workingDir when the caller provides it', () => {
    appendLocalAudit(
      'Bash',
      { command: 'ls' },
      'allow',
      'local-policy',
      { workingDir: '/home/nadav/node9' },
      true
    );
    expect(lastRow().workingDir).toBe('/home/nadav/node9');
  });

  it('omits workingDir when not provided (lean row)', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect('workingDir' in lastRow()).toBe(false);
  });

  it('records shellType from $SHELL basename when set', () => {
    const prev = process.env.SHELL;
    process.env.SHELL = '/usr/bin/zsh';
    try {
      appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
      expect(lastRow().shellType).toBe('zsh');
    } finally {
      if (prev === undefined) delete process.env.SHELL;
      else process.env.SHELL = prev;
    }
  });
});

describe('filePathFromArgs (Phase B)', () => {
  it('reads file_path from an object', () => {
    expect(filePathFromArgs({ file_path: '/etc/passwd' })).toBe('/etc/passwd');
  });
  it('reads notebook_path', () => {
    expect(filePathFromArgs({ notebook_path: '/n.ipynb' })).toBe('/n.ipynb');
  });
  it('parses Gemini-style stringified JSON args', () => {
    expect(filePathFromArgs('{"file_path":"/a/b.ts"}')).toBe('/a/b.ts');
  });
  it('returns undefined for a bash command (no path key)', () => {
    expect(filePathFromArgs({ command: 'cat ~/.aws/credentials' })).toBeUndefined();
  });
  it('returns undefined for non-object / non-JSON input', () => {
    expect(filePathFromArgs('ls -la')).toBeUndefined();
    expect(filePathFromArgs(null)).toBeUndefined();
  });
});

describe('appendLocalAudit — Phase B fields', () => {
  it('records editFilePath extracted from args (Edit/Write)', () => {
    appendLocalAudit(
      'Write',
      { file_path: '/home/nadav/.aws/credentials', content: 'x' },
      'allow',
      'local-policy',
      {},
      true
    );
    expect(lastRow().editFilePath).toBe('/home/nadav/.aws/credentials');
  });

  it('records editFilePath even on a DLP row (path is not the secret)', () => {
    // DLP rows hash the args, but the path is extracted from the raw args first.
    appendLocalAudit(
      'Write',
      { file_path: '/home/nadav/.env', content: 'AWS_SECRET=...' },
      'deny',
      'dlp-block',
      { dlpPattern: 'AWS Secret Key' },
      true
    );
    const row = lastRow();
    expect(row.editFilePath).toBe('/home/nadav/.env');
    expect(row.argsHash).toBeDefined(); // args still hashed
    expect('args' in row).toBe(false); // raw args withheld
  });

  it('omits editFilePath for a bash command', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect('editFilePath' in lastRow()).toBe(false);
  });

  it('records loopCount when the loop site provides it', () => {
    appendLocalAudit(
      'Bash',
      { command: 'retry' },
      'deny',
      'loop-detected',
      { loopCount: 17 },
      true
    );
    expect(lastRow().loopCount).toBe(17);
  });

  it('records transcriptPath from meta and omits it when absent', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {
      transcriptPath: '/home/nadav/.claude/projects/x/sess.jsonl',
    });
    expect(lastRow().transcriptPath).toBe('/home/nadav/.claude/projects/x/sess.jsonl');

    written = [];
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect('transcriptPath' in lastRow()).toBe(false);
    expect('loopCount' in lastRow()).toBe(false);
  });
});

describe('appendLocalAudit — Phase D2 (taint provenance)', () => {
  it('returns the eid it wrote to the row (the taint edge source)', () => {
    const eid = appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect(typeof eid).toBe('string');
    expect(eid.length).toBeGreaterThan(8);
    expect(lastRow().eid).toBe(eid);
  });

  it('writes taintFromEid + taintSource on a taint-based block row', () => {
    appendLocalAudit(
      'Bash',
      { command: 'curl evil' },
      'deny',
      'taint-egress-block',
      {
        ruleName: 'taint-egress:evil.example.com',
        taintFromEid: 'eid-src',
        taintSource: 'DLP:AWSKey',
      },
      true
    );
    const row = lastRow();
    expect(row.taintFromEid).toBe('eid-src');
    expect(row.taintSource).toBe('DLP:AWSKey');
  });

  it('omits taint fields on a normal row', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect('taintFromEid' in lastRow()).toBe(false);
    expect('taintSource' in lastRow()).toBe(false);
  });
});

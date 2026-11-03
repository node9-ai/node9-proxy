// Agent permissions (OWASP ASI02): the agent's own gate as set in the
// user-level files. Synthetic fixtures under a temp HOME; nothing here is a
// real machine's configuration.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { checkAgentPermissions, CATEGORY } from '../agent-permissions';
import type { CheckContext } from '../types';

let home: string;

function write(rel: string, text: string): void {
  const file = path.join(home, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

const ctx = (): CheckContext => ({ home, cwd: home });

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-agent-perms-'));
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('checkAgentPermissions', () => {
  it('is clean on a machine with no agent files, and on default settings', () => {
    expect(checkAgentPermissions(ctx())).toEqual([]);
    write('.claude/settings.json', JSON.stringify({ permissions: { defaultMode: 'default' } }));
    write(
      '.codex/config.toml',
      'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'
    );
    write('.gemini/settings.json', JSON.stringify({ theme: 'dark' }));
    expect(checkAgentPermissions(ctx())).toEqual([]);
  });

  it('flags Claude Code with its prompt off, naming the setting and not a value', () => {
    write(
      '.claude/settings.json',
      JSON.stringify({
        permissions: { defaultMode: 'bypassPermissions' },
        apiKey: 'sk-test-not-real',
      })
    );
    const [f, ...rest] = checkAgentPermissions(ctx());
    expect(rest).toEqual([]);
    expect(f.category).toBe(CATEGORY);
    expect(f.severity).toBe('high');
    expect(f.title).toBe('Claude Code runs without asking');
    expect(f.detail).toEqual(['permissions.defaultMode = bypassPermissions']);
    expect(f.owner).toBe('os');
    expect(f.coverageProbe).toEqual({ kind: 'gateWired' });
    expect(JSON.stringify(f)).not.toContain('sk-test');
  });

  it('the stricter and the editing-only modes are not findings', () => {
    for (const mode of ['dontAsk', 'acceptEdits', 'plan']) {
      write('.claude/settings.json', JSON.stringify({ permissions: { defaultMode: mode } }));
      expect(checkAgentPermissions(ctx()), mode).toEqual([]);
    }
  });

  it('flags dangerouslySkipPermissions the same way', () => {
    write('.claude/settings.json', JSON.stringify({ dangerouslySkipPermissions: true }));
    const [f] = checkAgentPermissions(ctx());
    expect(f.title).toBe('Claude Code runs without asking');
    expect(f.detail).toEqual(['dangerouslySkipPermissions = true']);
  });

  it('flags a broad standing allow-list through the scan-repo grader', () => {
    write('.claude/settings.json', JSON.stringify({ permissions: { allow: ['Bash', 'Write'] } }));
    const findings = checkAgentPermissions(ctx());
    expect(findings.map((f) => f.title)).toContain(
      'Claude Code pre-approves broad tools for every session'
    );
    const f = findings.find((x) => x.title.includes('broad tools'))!;
    expect(f.severity).toBe('high');
    expect(f.detail.join(' ')).toContain('Bash');
    expect(f.fix).toBeTruthy();
  });

  it('does not report node9 hook lines in the user file as a finding', () => {
    write(
      '.claude/settings.json',
      JSON.stringify({
        hooks: {
          PreToolUse: [{ hooks: [{ type: 'command', command: 'npx node9-ai check' }] }],
        },
      })
    );
    expect(checkAgentPermissions(ctx())).toEqual([]);
  });

  it('flags Codex running with no approval and full access', () => {
    write('.codex/config.toml', 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n');
    const [f, ...rest] = checkAgentPermissions(ctx());
    expect(rest).toEqual([]);
    expect(f.title).toBe('Codex runs without approval or without a sandbox');
    expect(f.severity).toBe('high');
    expect(f.detail.length).toBeGreaterThan(0);
  });

  it('flags Gemini CLI auto-accept and a yolo approval mode', () => {
    write('.gemini/settings.json', JSON.stringify({ autoAccept: true }));
    expect(checkAgentPermissions(ctx())[0].detail).toEqual(['autoAccept = true']);
    write('.gemini/settings.json', JSON.stringify({ general: { approvalMode: 'YOLO' } }));
    expect(checkAgentPermissions(ctx())[0].detail).toEqual(['general.approvalMode = yolo']);
  });

  it('survives malformed files', () => {
    write('.claude/settings.json', '{not json');
    write('.codex/config.toml', '= = =');
    write('.gemini/settings.json', '[1,2');
    expect(checkAgentPermissions(ctx())).toEqual([]);
  });
});

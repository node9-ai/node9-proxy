// T.9 — settings grants that run code without a prompt (2026-10-11). WRITTEN BEFORE THE
// IMPLEMENTATION. S.3 made interpreters, network tools and shells broad. Some everyday commands
// run other commands too (`awk 'BEGIN{system()}'`, `sed e`, `tee` to any path, `make`), some run a program (`dotnet run`, `cargo run`, `tmux`), some destroy or publish
// (`rm`, `git push`, `gh repo`), and some MCP tools execute code. Each counts only when the
// grant ends in a wildcard; an exact command or a fixed sub-command stays scoped.

import { describe, it, expect } from 'vitest';
import { analyzeAgentConfig } from '../ci-check/agent-config';

const broad = (allow: string[], key = 'allow') =>
  analyzeAgentConfig(
    '.claude/settings.json',
    JSON.stringify({ permissions: { [key]: allow, deny: [] } })
  ).filter((f) => f.rule === 'CI-1.broad-allow');

describe('T.9 — broad', () => {
  it.each([
    'Bash(awk:*)',
    'Bash(sed:*)',
    'Bash(tee:*)',
    'Bash(make:*)',
    'Bash(dotnet run:*)',
    'Bash(cargo run:*)',
    'Bash(tmux:*)',
    'Bash(timeout:*)',
    'Bash(rm:*)',
    'Bash(git push:*)',
    'Bash(git push *)',
    'Bash(gh repo:*)',
    'mcp__ide__executeCode',
    'mcp__plugin_tools__ctx_execute',
    'PowerShell(git push *)',
  ])('%s', (g) => {
    const [f] = broad([g]);
    expect(f?.severity).toBe('medium');
  });

  it('`permissions.allowedTools` is read like `permissions.allow`', () => {
    expect(broad(['Bash(tmux:*)'], 'allowedTools')).toHaveLength(1);
  });
});

describe('T.9 — scoped', () => {
  it.each([
    'Bash(grep:*)',
    'Bash(cat:*)',
    'Bash(git status:*)',
    'Bash(git diff:*)',
    'Bash(git fetch *)',
    'Bash(git checkout *)',
    'Bash(dotnet build:*)',
    'Bash(dotnet test:*)',
    'Bash(find . -name)',
    'Bash(find:*)',
    'Bash(make -n:*)',
    'Bash(gh repo view:*)',
    'Bash(gh pr view:*)',
    'mcp__github__get_issue',
    'mcp__ide__getDiagnostics',
    'PowerShell(git status)',
  ])('%s', (g) => {
    expect(broad([g])).toHaveLength(0);
  });
});

import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { AGENT_SPECS } from '../agent-wiring';

// docs/agents is documentation, and documentation drifts. These assertions tie
// each page to the registry that `node9 doctor` uses, so an agent added to the
// code without a page, or a page whose setup command stops matching, fails here.

const DOCS = join(__dirname, '..', '..', 'docs', 'agents');

const PAGE_FOR: Record<string, string> = {
  claude: 'claude-code.md',
  gemini: 'gemini-cli.md',
  codex: 'codex.md',
  antigravity: 'antigravity.md',
  copilot: 'copilot-cli.md',
  cursor: 'cursor.md',
  hermes: 'hermes.md',
  opencode: 'opencode.md',
  pi: 'pi.md',
};

describe('docs/agents', () => {
  it('has a page for every agent in the wiring registry', () => {
    for (const spec of AGENT_SPECS) {
      const page = PAGE_FOR[spec.id];
      expect(page, `no page mapped for registry agent "${spec.id}"`).toBeDefined();
      expect(existsSync(join(DOCS, page))).toBe(true);
    }
  });

  it('every page shows the exact setup command the registry uses', () => {
    for (const spec of AGENT_SPECS) {
      const text = readFileSync(join(DOCS, PAGE_FOR[spec.id]), 'utf8');
      expect(text).toContain(spec.setupCommand);
    }
  });

  it('every page says what is not covered and how to verify', () => {
    for (const file of readdirSync(DOCS).filter((f) => f.endsWith('.md') && f !== 'README.md')) {
      const text = readFileSync(join(DOCS, file), 'utf8');
      expect(text, file).toContain('## What is not covered');
      expect(text, file).toContain('node9 doctor');
      expect(text, file).toContain("node9 explain Bash 'cat ~/.ssh/id_rsa'");
    }
  });

  it('the index links every page', () => {
    const index = readFileSync(join(DOCS, 'README.md'), 'utf8');
    for (const file of readdirSync(DOCS).filter((f) => f.endsWith('.md') && f !== 'README.md')) {
      expect(index, file).toContain(`(${file})`);
    }
  });
});

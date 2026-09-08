import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * docs/ is the single source for node9's documentation: GitHub renders these
 * files directly and node9.ai renders them from the published package. That
 * only stays honest if the tests next to the code can check them, which is the
 * whole reason the pages live in this repository.
 *
 * See doc/roadmap/active/docs-single-source-design.md.
 */

const DOCS = join(__dirname, '..', '..', 'docs');
const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');

interface Page {
  file: string;
  front: Record<string, string>;
  body: string;
}

/** Pages with front matter. docs/README.md and docs/agents/* are prose indexes. */
function loadPages(): Page[] {
  return readdirSync(DOCS)
    .filter((f) => f.endsWith('.md') && f !== 'README.md')
    .map((file) => {
      const raw = readFileSync(join(DOCS, file), 'utf8');
      const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(raw);
      const front: Record<string, string> = {};
      if (m) {
        for (const line of m[1].split('\n')) {
          const kv = /^([a-z]+):\s*(.+)$/.exec(line.trim());
          if (kv) front[kv[1]] = kv[2].trim();
        }
      }
      return { file, front, body: m ? m[2] : raw };
    })
    .filter((p) => Object.keys(p.front).length > 0);
}

/** Top-level command names, from the CLI's own help. */
function cliCommands(): string[] {
  const help = execFileSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' });
  const start = help.indexOf('Commands:');
  return [
    ...new Set(
      help
        .slice(start === -1 ? 0 : start)
        .split('\n')
        .map((l) => /^\s{2}([a-z][a-z-]*)[\s|]/.exec(l)?.[1])
        .filter((c): c is string => !!c && !['help'].includes(c))
    ),
  ];
}

/** Subcommands of one command, from its own help. */
function subcommands(cmd: string): string[] {
  const help = execFileSync(process.execPath, [CLI, cmd, '--help'], { encoding: 'utf8' });
  const start = help.indexOf('Commands:');
  if (start === -1) return [];
  return help
    .slice(start)
    .split('\n')
    .map((l) => /^\s{2}([a-z][a-z-]*)[\s<[]/.exec(l)?.[1])
    .filter((c): c is string => !!c && c !== 'help');
}

/**
 * Commands with no page yet. This list only shrinks: adding a page removes an
 * entry, and a NEW command must arrive with a page rather than be appended
 * here. Written down so the test is green today and still catches regressions,
 * instead of being red on day one and switched off.
 */
const UNDOCUMENTED_FOR_NOW = new Set([
  'agents',
  'audit',
  'blast',
  'config',
  'connect',
  'daemon',
  'decisions',
  'doctor',
  'explain',
  'heal',
  'init',
  'jail',
  'log',
  'login',
  'logout',
  'mask',
  'mcp',
  'mcp-gateway',
  'mcp-server',
  'monitor',
  'pause',
  'policy',
  'posture',
  'report',
  'resume',
  'sandbox',
  'scan',
  'scan-repo',
  'session-taint',
  'sessions',
  'shield',
  'signup',
  'skill',
  'status',
  'tail',
  'trust',
  'undo',
  'uninstall',
  'check',
  'dlp',
  'egress-check',
  'canary',
]);

describe('docs pages', () => {
  const pages = loadPages();

  it('has at least one page with front matter', () => {
    expect(pages.length).toBeGreaterThan(0);
  });

  it('every page declares id, label, description, group and order, and ids are unique', () => {
    const ids = new Set<string>();
    for (const p of pages) {
      for (const key of ['id', 'label', 'description', 'group', 'order']) {
        expect(p.front[key], `${p.file} is missing "${key}"`).toBeTruthy();
      }
      expect(p.front.id, `${p.file}: id must be url-safe`).toMatch(/^[a-z0-9-]+$/);
      expect(Number.isFinite(Number(p.front.order)), `${p.file}: order must be a number`).toBe(
        true
      );
      expect(ids.has(p.front.id), `duplicate id ${p.front.id}`).toBe(false);
      ids.add(p.front.id);
    }
  });

  it('every page says what the feature does not do', () => {
    for (const p of pages) {
      expect(p.body, `${p.file} has no "what this does not do" section`).toMatch(
        /does not do|is not covered|What this does not/i
      );
    }
  });

  it('every command a page names actually exists', () => {
    // The check that would have caught `node9 egress protect`, `node9 config set`
    // and `node9 audit log`, each of which shipped in published copy.
    //
    // Only code is checked: fenced blocks and inline `code` spans. Prose says
    // things like "node9 decides from the destination", which is a sentence,
    // not an invocation.
    const top = new Set(cliCommands());
    const subs = new Map<string, Set<string>>();
    for (const p of pages) {
      const code = [
        ...[...p.body.matchAll(/```[a-z]*\n([\s\S]*?)```/g)].map((m) => m[1]),
        ...[...p.body.matchAll(/`([^`\n]+)`/g)].map((m) => m[1]),
      ].join('\n');
      for (const [, cmd, sub] of code.matchAll(/\bnode9 ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?/g)) {
        expect(top.has(cmd), `${p.file}: "node9 ${cmd}" is not a command`).toBe(true);
        if (!sub) continue;
        if (!subs.has(cmd)) subs.set(cmd, new Set(subcommands(cmd)));
        const known = subs.get(cmd)!;
        // A command with no subcommands takes arguments; only check real ones.
        if (known.size === 0) continue;
        expect(known.has(sub), `${p.file}: "node9 ${cmd} ${sub}" is not a subcommand`).toBe(true);
      }
    }
  });

  it('every documented command is covered, and the undocumented list only shrinks', () => {
    const documented = new Set(pages.map((p) => p.front.id));
    const missing = cliCommands().filter((c) => !documented.has(c) && !UNDOCUMENTED_FOR_NOW.has(c));
    expect(missing, `commands with no docs page: ${missing.join(', ')}`).toEqual([]);

    // A command that gained a page must leave the list, so it cannot rot.
    const stale = [...UNDOCUMENTED_FOR_NOW].filter((c) => documented.has(c));
    expect(stale, `remove from UNDOCUMENTED_FOR_NOW: ${stale.join(', ')}`).toEqual([]);
  });
});

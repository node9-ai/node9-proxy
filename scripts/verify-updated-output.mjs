#!/usr/bin/env node
// Live check: does Claude Code apply `updatedToolOutput` for each tool?
//
// node9's Mode C (src/cli/commands/log.ts) replaces a tool result in the
// tool's own shape. Claude Code drops a replacement it does not accept
// WITHOUT an error, so the only proof is to run it: for each tool, a
// PostToolUse hook maps every string leaf of tool_response (as node9 does),
// replacing a marker with a canary, and the stream-json transcript shows
// whether the model received the canary.
//
// Needs a signed-in `claude` on PATH. Uses a cheap model and one short
// session per tool. Not part of CI. Record the result table, with the Claude
// Code version it prints, in the issue tracking Mode C.
//
//   node scripts/verify-updated-output.mjs [Bash Read Grep Glob Write Edit WebFetch]

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const MARK = 'node9-marker-7781';
const CANARY = 'NODE9-CANARY-REPLACED';
const MODEL = process.env.VERIFY_MODEL || 'claude-haiku-4-5-20251001';

const CASES = {
  Bash: { allow: 'Bash(echo:*)', prompt: `Run the Bash command: echo ${MARK}` },
  Read: { allow: 'Read', prompt: 'Read the file sample.txt with the Read tool.' },
  Grep: {
    allow: 'Grep',
    prompt: `Use the Grep tool to search for ${MARK} in this directory, content mode.`,
  },
  Glob: { allow: 'Glob', prompt: `Use the Glob tool with the pattern **/${MARK}*.txt` },
  Write: { allow: 'Write', prompt: `Write a file named out.txt containing exactly: ${MARK}` },
  Edit: { allow: 'Edit', prompt: `Edit sample.txt, replacing "line one" with "line 1 ${MARK}".` },
  WebFetch: {
    allow: 'WebFetch',
    prompt: `Fetch https://example.com with WebFetch and reply with the word ${MARK}.`,
  },
};

const HOOK = `
const fs = require('fs');
let raw = '';
process.stdin.on('data', (d) => (raw += d));
process.stdin.on('end', () => {
  const p = JSON.parse(raw);
  const walk = (v, d) => typeof v === 'string' ? v.split(${JSON.stringify(MARK)}).join(${JSON.stringify(CANARY)})
    : d >= 8 || v === null || typeof v !== 'object' ? v
    : Array.isArray(v) ? v.map((x) => walk(x, d + 1))
    : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x, d + 1)]));
  const before = JSON.stringify(p.tool_response);
  const updated = walk(p.tool_response, 0);
  fs.appendFileSync(__dirname + '/hook.log', JSON.stringify({ tool: p.tool_name, marked: before.includes(${JSON.stringify(MARK)}) }) + '\\n');
  if (JSON.stringify(updated) !== before)
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: updated } }));
});
`;

const version = spawnSync('claude', ['--version'], { encoding: 'utf8' }).stdout.trim();
console.log(`Claude Code ${version || '(not found)'}, model ${MODEL}\n`);
const tools = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(CASES);
const rows = [];

for (const tool of tools) {
  const c = CASES[tool];
  if (!c) {
    rows.push([tool, 'unknown tool']);
    continue;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `node9-verify-${tool}-`));
  fs.writeFileSync(path.join(dir, 'hook.cjs'), HOOK);
  fs.writeFileSync(path.join(dir, 'sample.txt'), `line one\n${MARK}\n`);
  fs.writeFileSync(path.join(dir, `${MARK}.txt`), 'x\n');
  const settings = {
    hooks: {
      PostToolUse: [
        {
          matcher: tool,
          hooks: [{ type: 'command', command: `node ${path.join(dir, 'hook.cjs')}` }],
        },
      ],
    },
  };
  fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify(settings));
  const r = spawnSync(
    'claude',
    [
      '-p',
      `${c.prompt} Then reply with only the exact text the tool returned to you, verbatim.`,
      '--settings',
      path.join(dir, 'settings.json'),
      '--allowedTools',
      c.allow,
      '--model',
      MODEL,
      '--output-format',
      'stream-json',
      '--verbose',
    ],
    { cwd: dir, encoding: 'utf8', input: '', timeout: 240_000 }
  );
  let seen = '';
  let error = '';
  for (const line of (r.stdout || '').split('\n')) {
    let ev;
    try {
      ev = JSON.parse(line);
    } catch {
      continue;
    }
    if (ev.type === 'user')
      for (const part of ev.message?.content ?? [])
        if (part?.type === 'tool_result') seen += JSON.stringify(part.content);
    if (ev.type === 'result' && ev.is_error) error = String(ev.result).slice(0, 80);
  }
  const log = fs.existsSync(path.join(dir, 'hook.log'))
    ? fs.readFileSync(path.join(dir, 'hook.log'), 'utf8')
    : '';
  const marked = log.includes('"marked":true');
  const verdict = error
    ? `error: ${error}`
    : !log
      ? 'hook did not run'
      : !marked
        ? 'marker not in tool_response (inconclusive)'
        : seen.includes(CANARY)
          ? 'APPLIED'
          : seen.includes(MARK)
            ? 'IGNORED (original delivered)'
            : 'inconclusive';
  rows.push([tool, verdict]);
  fs.rmSync(dir, { recursive: true, force: true });
}

for (const [tool, verdict] of rows) console.log(`${tool.padEnd(10)} ${verdict}`);
process.exitCode = rows.some(([, v]) => v.startsWith('IGNORED')) ? 1 : 0;

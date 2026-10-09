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
  // An MCP tool through the hook path: a tiny stdio server (MCP_SERVER below)
  // whose one tool returns the marker.
  MCP: {
    tool: 'mcp__verify__echo',
    allow: 'mcp__verify__echo',
    mcp: true,
    prompt: 'Call the mcp__verify__echo tool once.',
  },
  WebFetch: {
    allow: 'WebFetch',
    // WebFetch returns its own model's answer about the page, so the marker
    // has to be in the prompt it is given.
    prompt: `Use WebFetch on https://example.com with this prompt: "Begin your answer with the word ${MARK}, then give the page title."`,
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

const MCP_SERVER = `
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
const send = (m) => process.stdout.write(JSON.stringify(m) + String.fromCharCode(10));
rl.on('line', (line) => {
  const msg = JSON.parse(line);
  if (msg.id === undefined) return; // notification
  if (msg.method === 'initialize')
    return send({ jsonrpc: '2.0', id: msg.id, result: {
      protocolVersion: msg.params.protocolVersion, capabilities: { tools: {} },
      serverInfo: { name: 'verify', version: '1.0.0' } } });
  if (msg.method === 'tools/list')
    return send({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'echo',
      description: 'Returns a fixed line', inputSchema: { type: 'object', properties: {} } }] } });
  if (msg.method === 'tools/call')
    return send({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: 'echo: ${MARK}' }] } });
  send({ jsonrpc: '2.0', id: msg.id, result: {} });
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
  const toolName = c.tool ?? tool;
  const settings = {
    hooks: {
      PostToolUse: [
        {
          matcher: toolName,
          hooks: [{ type: 'command', command: `node ${path.join(dir, 'hook.cjs')}` }],
        },
      ],
    },
  };
  fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify(settings));
  const mcpArgs = [];
  if (c.mcp) {
    fs.writeFileSync(path.join(dir, 'server.cjs'), MCP_SERVER);
    fs.writeFileSync(
      path.join(dir, 'mcp.json'),
      JSON.stringify({
        mcpServers: { verify: { command: 'node', args: [path.join(dir, 'server.cjs')] } },
      })
    );
    mcpArgs.push('--mcp-config', path.join(dir, 'mcp.json'), '--strict-mcp-config');
  }
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
      ...mcpArgs,
    ],
    { cwd: dir, encoding: 'utf8', input: '', timeout: 240_000 }
  );
  // Only results of THIS tool count: a model often runs another tool first
  // (Edit needs a Read), and that tool has no hook in this run.
  let seen = '';
  let error = '';
  const toolOf = new Map();
  for (const line of (r.stdout || '').split('\n')) {
    let ev;
    try {
      ev = JSON.parse(line);
    } catch {
      continue;
    }
    if (ev.type === 'assistant')
      for (const part of ev.message?.content ?? [])
        if (part?.type === 'tool_use') toolOf.set(part.id, part.name);
    if (ev.type === 'user')
      for (const part of ev.message?.content ?? [])
        if (part?.type === 'tool_result' && toolOf.get(part.tool_use_id) === toolName)
          seen += JSON.stringify(part.content);
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
            : !seen
              ? 'inconclusive (tool not run)'
              : 'n/a: the result the model reads does not carry the content';
  rows.push([tool, verdict]);
  fs.rmSync(dir, { recursive: true, force: true });
}

for (const [tool, verdict] of rows) console.log(`${tool.padEnd(10)} ${verdict}`);
process.exitCode = rows.some(([, v]) => v.startsWith('IGNORED')) ? 1 : 0;

/**
 * Gate-contract matrix — replay REAL captured agent payloads through the real gate.
 *
 * Why this exists (test-robustness-plan P0b): the app-permission gate shipped DEAD
 * to production while its unit tests were green, because those tests fed the gate
 * synthetic inputs the real caller never sends. This suite kills that class: every
 * payload here was CAPTURED from a live agent session (~/.node9/hook-debug.log via
 * scripts in doc/roadmap/active/test-robustness-plan.md), sanitized (ids/usernames
 * only — never shape), and is replayed through the REAL built CLI exactly the way
 * the production hook delivers it: `node9 check` with the payload piped on STDIN
 * (no argv payload — see ~/.claude/settings.json hook command).
 *
 * Per agent, two rows:
 *   1. verbatim  — the captured payload as-is → must be ALLOWED (exit 0, no output)
 *   2. cred-read — the SAME envelope with only the command/path swapped to a
 *      credential read (or a secret injected into args) → must be BLOCKED with
 *      that agent's exact live-verified output contract (see sendBlock in check.ts).
 *
 * Agents with no real capture available (Copilot, Antigravity, Hermes) are
 * deliberately visible as todo rows — DO NOT hand-write their fixtures. Capture
 * one from a live session (they log to hook-debug.log) and add the file.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const FIXTURES = path.resolve(__dirname, 'fixtures/gate-inputs');

// Composed at runtime so node9's own DLP never flags this source file.
const FAKE_GH_TOKEN = 'ghp_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';

interface MatrixRow {
  fixture: string; // fixtures/gate-inputs/<fixture>.json
  agent: string; // expected audit attribution derived from payload SHAPE alone
  /** Mutate ONLY the tool arguments into a block-worthy variant. The envelope —
   *  the part that killed the dead gate — must stay byte-identical. */
  toBlocked: (p: Record<string, unknown>) => void;
}

const MATRIX: MatrixRow[] = [
  {
    fixture: 'claude-bash',
    agent: 'Claude Code',
    toBlocked: (p) => {
      (p.tool_input as Record<string, unknown>).command = 'cat ~/.aws/credentials';
    },
  },
  {
    fixture: 'claude-read',
    agent: 'Claude Code',
    toBlocked: (p) => {
      (p.tool_input as Record<string, unknown>).file_path = path.join(
        os.homedir(),
        '.aws/credentials'
      );
    },
  },
  {
    // Hook mode sees Claude's NAMESPACED MCP tool name (mcp__server__tool) —
    // unlike the stdio gateway, which forwards the BARE name. Both real shapes
    // must hold; the bare-name gateway path is covered by the app-permission
    // gate tests + the P0a round-trip.
    fixture: 'claude-mcp-tool',
    agent: 'Claude Code',
    toBlocked: (p) => {
      // DLP argv scan: a secret anywhere in the tool arguments must block.
      (p.tool_input as Record<string, unknown>).key = `token ${FAKE_GH_TOKEN}`;
    },
  },
  {
    fixture: 'gemini-shell',
    agent: 'Gemini CLI',
    toBlocked: (p) => {
      (p.tool_input as Record<string, unknown>).command = 'cat ~/.aws/credentials';
    },
  },
  {
    fixture: 'codex-bash',
    agent: 'Codex',
    toBlocked: (p) => {
      (p.tool_input as Record<string, unknown>).command = 'cat ~/.aws/credentials';
    },
  },
];

let tmpHome: string;

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found — run "npm run build" first.\nExpected: ${CLI}`);
  }
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gate-matrix-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(
    path.join(node9Dir, 'config.json'),
    JSON.stringify({ settings: { mode: 'standard', autoStartDaemon: false } })
  );
});

afterAll(() => {
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    /* leaked temp dir is non-fatal */
  }
});

/** Run the real CLI the way the production hook does: `node9 check` + STDIN. */
function runGate(payload: Record<string, unknown>) {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY; // never let a matrix test reach the real API
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'check'], {
    input: JSON.stringify(payload),
    encoding: 'utf-8',
    timeout: 60000,
    cwd: tmpHome,
    env: {
      ...baseEnv,
      HOME: tmpHome,
      USERPROFILE: tmpHome,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
    },
  });
  expect(r.error, `spawn failed: ${r.error?.message}`).toBeUndefined();
  expect(r.status, `CLI did not exit (signal ${r.signal})`).not.toBeNull();
  return r;
}

function loadFixture(name: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), 'utf-8')) as Record<
    string,
    unknown
  >;
}

function lastAuditRow(): Record<string, unknown> {
  const lines = fs
    .readFileSync(path.join(tmpHome, '.node9', 'audit.log'), 'utf-8')
    .trim()
    .split('\n');
  return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
}

describe.each(MATRIX)('gate contract: $fixture', ({ fixture, agent, toBlocked }) => {
  it('verbatim real payload is allowed (exit 0, silent)', () => {
    const payload = loadFixture(fixture);
    const r = runGate(payload);
    expect(r.status, `stderr: ${r.stderr}\nstdout: ${r.stdout}`).toBe(0);
    // An allow must be SILENT on stdout — any JSON here would alter agent behavior.
    expect(r.stdout).toBe('');
  });

  it('same envelope with a credential read is blocked with the agent contract', () => {
    const payload = loadFixture(fixture);
    toBlocked(payload);
    const r = runGate(payload);

    // Claude / Gemini / Codex share the live-verified block contract:
    // stdout JSON {decision:'block', hookSpecificOutput.permissionDecision:'deny'}
    // + exit 2 (see sendBlock in check.ts — Antigravity/Copilot differ, but we
    // have no real captures for those yet; see todos below).
    expect(r.status, `expected a BLOCK exit.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`).toBe(2);
    const body = JSON.parse(r.stdout) as {
      decision: string;
      hookSpecificOutput: { permissionDecision?: string };
    };
    expect(body.decision).toBe('block');
    expect(body.hookSpecificOutput.permissionDecision).toBe('deny');

    // Attribution: the audit row must identify the agent from payload shape alone.
    expect(lastAuditRow().agent).toBe(agent);
  });
});

// ── Visible gaps — agents with NO real captured payload on this machine ──────
// Per the plan: capture, don't invent. When one of these agents runs live with
// node9 wired, hook-debug.log records its STDIN payload — add it as a fixture
// and move the agent into MATRIX. Until then these rows stay red-by-visibility.
describe('gate contract: agents pending a real capture', () => {
  it.todo('copilot — BeforeTool shape, flat permissionDecision block contract');
  it.todo('antigravity — PreToolUse shape, decision:"deny" + exit 0 block contract');
  it.todo('hermes — pre_tool_call shape (upstream session_id bug #48311)');
});

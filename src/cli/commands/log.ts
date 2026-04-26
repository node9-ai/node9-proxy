// src/cli/commands/log.ts
// PostToolUse hook — records executed tool calls to the audit log.
// Registered as `node9 log` by cli.ts.
import type { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { redactSecrets, appendToLog, LOCAL_AUDIT_LOG } from '../../audit';
import { getConfig } from '../../config';
import { createShadowSnapshot, getSnapshotHistory } from '../../undo';
import { notifyTaintPropagate, isDaemonRunning, notifyActivitySocket } from '../../auth/daemon';
import { parseCpMvOp } from '../../utils/cp-mv-parser';

// Patterns for common test runners
const TEST_COMMAND_RE =
  /(?:^|\s)(npm\s+(?:run\s+)?test|npx\s+(?:vitest|jest|mocha)|yarn\s+(?:run\s+)?test|pnpm\s+(?:run\s+)?test|vitest|jest|mocha|pytest|py\.test|cargo\s+test|go\s+test|bundle\s+exec\s+rspec|rspec|phpunit|dotnet\s+test)\b/i;

function detectTestResult(command: string, output: string): 'pass' | 'fail' | null {
  if (!TEST_COMMAND_RE.test(command)) return null;
  const out = output.toLowerCase();
  // Success indicators (check these first — some failure messages contain "pass")
  if (
    /\b(tests?\s+passed|all\s+tests?\s+passed|passing|test\s+suites?.*passed|ok\b|\d+\s+passed)/i.test(
      out
    ) &&
    !/\b(fail|error|failed)\b/.test(out)
  ) {
    return 'pass';
  }
  // Failure indicators
  if (/\b(tests?\s+failed|failing|failed|error|assertion\s+error|\d+\s+failed)\b/i.test(out)) {
    return 'fail';
  }
  return null;
}

function sanitize(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1F\x7F]/g, '');
}

export function registerLogCommand(program: Command): void {
  program
    .command('log')
    .description('PostToolUse hook — records executed tool calls')
    .argument('[data]', 'JSON string of the tool call')
    .action(async (data) => {
      const logPayload = async (raw: string) => {
        try {
          if (!raw || raw.trim() === '') process.exit(0);
          const payload = JSON.parse(raw) as {
            tool_name?: string;
            name?: string;
            tool_input?: unknown;
            tool_response?: { output?: string };
            args?: unknown;
            cwd?: string;
            hook_event_name?: string;
            tool_use_id?: string;
            permission_mode?: string;
            timestamp?: string;
          };

          // Handle both Claude (tool_name) and Gemini (name)
          const tool = sanitize(payload.tool_name ?? payload.name ?? 'unknown');
          const rawInput = payload.tool_input ?? payload.args ?? {};

          // Detect agent from hook payload — same logic as check.ts
          const agent =
            payload.hook_event_name === 'PreToolUse' ||
            payload.hook_event_name === 'PostToolUse' ||
            payload.tool_use_id !== undefined ||
            payload.permission_mode !== undefined
              ? 'Claude Code'
              : payload.hook_event_name === 'BeforeTool' ||
                  payload.hook_event_name === 'AfterTool' ||
                  payload.timestamp !== undefined
                ? 'Gemini CLI'
                : undefined;

          // Audit write FIRST — before any config load that could fail.
          // A config error must never silently skip the audit entry.
          const entry: Record<string, unknown> = {
            ts: new Date().toISOString(),
            tool: tool,
            args: JSON.parse(redactSecrets(JSON.stringify(rawInput))),
            decision: 'allowed',
            source: 'post-hook',
          };
          if (agent) entry.agent = agent;

          const logPath = path.join(os.homedir(), '.node9', 'audit.log');
          if (!fs.existsSync(path.dirname(logPath)))
            fs.mkdirSync(path.dirname(logPath), { recursive: true });
          fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');

          // Taint propagation: if the completed bash command was a cp or mv,
          // forward taint from source to destination so a later network upload
          // of the copy is still caught. Must be awaited before process.exit(0)
          // — fire-and-forget would lose the propagation when the process exits.
          if ((tool === 'Bash' || tool === 'bash') && isDaemonRunning()) {
            const command =
              typeof rawInput === 'object' &&
              rawInput !== null &&
              'command' in rawInput &&
              typeof (rawInput as Record<string, unknown>).command === 'string'
                ? ((rawInput as Record<string, unknown>).command as string)
                : null;
            if (command) {
              const op = parseCpMvOp(command);
              // parseCpMvOp returns null for two distinct reasons:
              //   1. Not a cp/mv command — no taint propagation needed (correct).
              //   2. cp/mv that couldn't be safely parsed — e.g. env-prefixed
              //      commands like `IFS=/ cp src dest`, glob patterns, shell
              //      metacharacters, or multi-source invocations. In these cases
              //      null is the safe/conservative choice: taint stays on the
              //      source rather than propagating to a potentially wrong dest.
              // Callers that need to distinguish the two cases should extend
              // parseCpMvOp to return a reason code. For audit purposes here,
              // both cases are equivalent: no propagation occurs.
              if (op) {
                await notifyTaintPropagate(op.src, op.dest, op.clearSource);
              }
            }
          }

          // Test result detection for stateful smart rules (e.g. "block push if no
          // passing test since last edit"). Only fires when daemon is running and
          // the completed command looks like a test runner invocation.
          if ((tool === 'Bash' || tool === 'bash') && isDaemonRunning()) {
            const bashCommand =
              typeof rawInput === 'object' &&
              rawInput !== null &&
              'command' in rawInput &&
              typeof (rawInput as Record<string, unknown>).command === 'string'
                ? ((rawInput as Record<string, unknown>).command as string)
                : null;
            const output = payload.tool_response?.output ?? '';
            if (bashCommand && output) {
              const testResult = detectTestResult(bashCommand, output);
              if (testResult) {
                // Write to audit log regardless of daemon status — report reads this offline
                appendToLog(LOCAL_AUDIT_LOG, {
                  ts: new Date().toISOString(),
                  tool,
                  testResult,
                  source: 'test-result',
                });
                if (isDaemonRunning()) {
                  await notifyActivitySocket({
                    id: 'test-result',
                    ts: Date.now(),
                    tool: tool,
                    status: testResult === 'pass' ? 'test_pass' : 'test_fail',
                  });
                }
              }
            }
          }

          // Validate cwd is absolute before passing to getConfig() — prevents path
          // traversal via a crafted hook payload (e.g. cwd: "../../../../etc").
          // A relative or empty cwd falls back to ambient process.cwd().
          const safeCwd =
            typeof payload.cwd === 'string' && path.isAbsolute(payload.cwd)
              ? payload.cwd
              : undefined;

          // Config load and snapshot run AFTER the audit write — a config failure
          // here is non-fatal and must not retroactively gap the audit trail above.
          const config = getConfig(safeCwd);

          // PostToolUse: snapshot Bash commands only.
          // Edit/Write tools are already snapshotted by PreToolUse in check.ts with full
          // metadata. Snapshotting them here again creates duplicate 'unknown' entries.
          // For Bash, we capture post-execution state so that sed -i, echo >, tee etc.
          // are reversible. Guard: only snapshot if a prior snapshot exists for this cwd —
          // avoids cold-start overhead on projects where undo was never used.
          if ((tool === 'Bash' || tool === 'bash') && config.settings.enableUndo !== false) {
            const bashCommand =
              typeof rawInput === 'object' &&
              rawInput !== null &&
              'command' in rawInput &&
              typeof (rawInput as Record<string, unknown>).command === 'string'
                ? ((rawInput as Record<string, unknown>).command as string)
                : null;
            if (bashCommand) {
              const effectiveCwd = safeCwd ?? process.cwd();
              const history = getSnapshotHistory();
              const hasPrior = history.some((e) => e.cwd === effectiveCwd);
              if (hasPrior) {
                await createShadowSnapshot(
                  'Bash',
                  { command: bashCommand },
                  config.policy.snapshot.ignorePaths
                );
              }
            }
          }
        } catch (err) {
          // Always write to hook-debug.log — this catch guards the audit trail, so
          // silent failures here directly create audit gaps. Do NOT call getConfig()
          // here: if it caused the original error, calling it again re-throws and
          // hides the real message.
          const msg = err instanceof Error ? err.message : String(err);
          // Emit to stderr so the failure surfaces in the tool output stream — operators
          // should not need to proactively check hook-debug.log to learn of audit gaps.
          process.stderr.write(`[Node9] audit log error: ${msg}\n`);
          const debugPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
          try {
            fs.appendFileSync(debugPath, `[${new Date().toISOString()}] LOG_ERROR: ${msg}\n`);
          } catch {
            /* if we can't write the debug log, nothing we can do */
          }
          // Intentional: exit(0) even on audit failure. Returning a non-zero code
          // here would cause Claude/Gemini to treat the *tool call itself* as failed,
          // which is incorrect — the tool already ran. The tradeoff is that the hook
          // host sees success even when audit.log was not written; the error is
          // surfaced on stderr and in hook-debug.log for operator visibility.
        }
        process.exit(0);
      };

      if (data) {
        await logPayload(data);
      } else {
        let raw = '';
        process.stdin.setEncoding('utf-8');
        process.stdin.on('data', (chunk) => (raw += chunk));
        process.stdin.on('end', () => {
          void logPayload(raw);
        });
        setTimeout(() => {
          if (!raw) process.exit(0);
        }, 500);
      }
    });
}

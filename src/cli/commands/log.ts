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
import {
  notifyTaintPropagate,
  isDaemonRunning,
  notifyActivitySocket,
  notifySessionTaint,
} from '../../auth/daemon';
import { scanText, redactText } from '../../dlp';
import { parseCpMvOp } from '../../utils/cp-mv-parser';
import {
  extractToolName,
  extractToolInput,
  canonicalToolName,
  canonicalToolInput,
  agentLabelFromFlag,
} from '../../utils/hook-payload';

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
    .command('log', { hidden: true })
    .description('PostToolUse hook — records executed tool calls')
    .argument('[data]', 'JSON string of the tool call')
    .option(
      '--agent <name>',
      'Agent identity override, set by node9-authored hook registrations (e.g. antigravity)'
    )
    .option(
      '--redact-output',
      'gap1 Mode A: redact secrets in tool_response.output and print { redacted, found } JSON ' +
        'on stdout so an output-mutating shim (OpenCode/Pi/Hermes) can replace the result'
    )
    .action(async (data, opts: { agent?: string; redactOutput?: boolean }) => {
      const agentOverride = agentLabelFromFlag(opts?.agent);
      const redactOutputMode = opts?.redactOutput === true;
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
            session_id?: string;
            turn_id?: string; // Codex-specific
            // Antigravity (agy) dialect — verified against agy 1.0.6:
            toolCall?: { name?: string; args?: unknown } | null;
            conversationId?: string; // agy's session_id equivalent
            workspacePaths?: string[]; // agy has no top-level cwd
          };

          // Antigravity fires PostToolUse on non-tool steps too (planner
          // responses) with toolCall: null — nothing executed, nothing to
          // audit. Without this guard every model turn writes a junk
          // `unknown` row to audit.log.
          if (payload.toolCall === null) process.exit(0);

          const rawToolName = sanitize(extractToolName(payload, 'unknown'));
          const tool = canonicalToolName(rawToolName);
          const rawInput = canonicalToolInput(rawToolName, extractToolInput(payload));

          // Detect agent from hook payload — must mirror check.ts detectAiAgent.
          // Layer 0: explicit meta.agent tag set by a node9-authored shim
          // (Pi, Opencode, and any future agent). Must precede Layer 1
          // because shim payloads still carry hook_event_name: "PostToolUse"
          // to match the shape this command understands — without Layer 0,
          // they'd be misattributed to "Claude Code".
          // Layer 1 (turn_id / hook_event_name / etc.) below is unchanged.
          const metaTag = (() => {
            const m = (payload as { meta?: unknown }).meta;
            if (m && typeof m === 'object') {
              const tagged = (m as { agent?: unknown }).agent;
              if (typeof tagged === 'string' && tagged.length > 0) return tagged;
            }
            return undefined;
          })();
          // Layer 1: payload fingerprint (most reliable).
          // Layer 2 (env-var fallback): mirrors check.ts:detectAiAgent.
          // Currently only Hermes — gateway/cron mode can lose payload
          // fingerprints when the dispatcher rewrites payloads but env
          // stays intact (run_agent.py:1913 sets HERMES_SESSION_ID on
          // every session before tool dispatch). Other agents could be
          // added the same way; keeping the surface minimal until there
          // is a confirmed need.
          // --agent flag (Layer -1): node9 wrote the hook registration, so
          // the flag is the most deterministic signal of all — mirrors the
          // agentOverride precedence in check.ts.
          // Antigravity branch mirrors check.ts:detectAiAgent — toolCall /
          // conversationId fingerprint (no hook_event_name in agy payloads),
          // ANTIGRAVITY_CONVERSATION_ID env fallback.
          const agent =
            agentOverride !== undefined
              ? agentOverride
              : metaTag !== undefined
                ? metaTag
                : payload.turn_id !== undefined
                  ? 'Codex'
                  : payload.toolCall !== undefined || payload.conversationId !== undefined
                    ? 'Antigravity'
                    : payload.hook_event_name === 'pre_tool_call' ||
                        payload.hook_event_name === 'post_tool_call'
                      ? 'Hermes'
                      : payload.hook_event_name === 'PreToolUse' ||
                          payload.hook_event_name === 'PostToolUse' ||
                          payload.tool_use_id !== undefined ||
                          payload.permission_mode !== undefined
                        ? 'Claude Code'
                        : payload.hook_event_name === 'BeforeTool' ||
                            payload.hook_event_name === 'AfterTool' ||
                            payload.timestamp !== undefined
                          ? 'Gemini CLI'
                          : process.env.HERMES_SESSION_ID ||
                              process.env.HERMES_HOME ||
                              process.env.HERMES_INTERACTIVE
                            ? 'Hermes'
                            : process.env.ANTIGRAVITY_CONVERSATION_ID
                              ? 'Antigravity'
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
          // Preserve the agent-native tool name when canonicalisation
          // rewrote it (e.g. Hermes `terminal` → `Bash`). Lets users
          // grep audit.log for the name they actually see in their
          // agent's UI without losing the canonical for shield/report
          // aggregation.
          if (rawToolName !== tool) entry.agentToolName = rawToolName;
          // Antigravity alias: conversationId ≙ session_id.
          const payloadSessionId = payload.session_id ?? payload.conversationId;
          if (payloadSessionId) entry.sessionId = payloadSessionId;

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

          // ── gap1: response-channel DLP — scan what the tool RETURNED ─────────
          // The output is about to enter (or, on observe-only agents, has just
          // entered) the model's context. On a secret hit we taint the session
          // so the next high-risk call is routed to review, and — on Claude/Codex
          // (their post-tool hook can inject context) — warn the model directly.
          // We can't redact post-hoc on these agents, but we stop the leaked
          // secret from being acted on / exfiltrated.
          {
            const toolOutput = payload.tool_response?.output;
            if (typeof toolOutput === 'string' && toolOutput.length > 0) {
              if (redactOutputMode) {
                // Mode A (OpenCode/Pi/Hermes): the calling shim CAN mutate the
                // result, so redact the secret out before the model sees it and
                // hand the cleaned text back. No session taint — the secret is
                // removed, so there's nothing to contain downstream.
                const { result, found } = redactText(toolOutput);
                process.stdout.write(JSON.stringify({ redacted: result, found }) + '\n');
              } else {
                // Mode B (Claude/Codex): the model already received the output and
                // the hook can't suppress it. Detect → warn the model via
                // additionalContext + taint the session so the next high-risk call
                // is routed to review (the leaked secret can't then be exfiltrated).
                const hit = scanText(toolOutput);
                if (hit) {
                  await notifySessionTaint(
                    payloadSessionId ?? '',
                    `output-secret:${hit.patternName}`
                  );
                  if (agent === 'Claude Code' || agent === 'Codex') {
                    process.stdout.write(
                      JSON.stringify({
                        hookSpecificOutput: {
                          hookEventName: 'PostToolUse',
                          additionalContext:
                            `⚠️ node9: this tool output contained a credential (${hit.patternName}). ` +
                            `Do not echo, store, or transmit it — treat it as compromised and rotate it. ` +
                            `node9 has flagged this session: the next network or write action will require approval.`,
                        },
                      }) + '\n'
                    );
                  }
                }
              }
            }
          }

          // Validate cwd is absolute before passing to getConfig() — prevents path
          // traversal via a crafted hook payload (e.g. cwd: "../../../../etc").
          // A relative or empty cwd falls back to ambient process.cwd().
          // Antigravity has no top-level cwd; workspacePaths[0] is the
          // workspace root (mirrors check.ts).
          const payloadCwd =
            typeof payload.cwd === 'string'
              ? payload.cwd
              : Array.isArray(payload.workspacePaths) &&
                  typeof payload.workspacePaths[0] === 'string'
                ? payload.workspacePaths[0]
                : undefined;
          const safeCwd =
            typeof payloadCwd === 'string' && path.isAbsolute(payloadCwd) ? payloadCwd : undefined;

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

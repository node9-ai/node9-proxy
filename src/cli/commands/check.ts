// src/cli/commands/check.ts
// PreToolUse hook handler — evaluates a tool call before execution.
// Registered as `node9 check` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { spawn } from 'child_process';
import path from 'path';
import os from 'os';
import { authorizeHeadless } from '../../auth/orchestrator';
import { isDaemonRunning } from '../../auth/daemon';
import { getConfig } from '../../config';
import { shouldSnapshot } from '../../policy';
import { buildNegotiationMessage } from '../../policy/negotiation';
import { createShadowSnapshot } from '../../undo';
import { autoStartDaemonAndWait } from '../daemon-starter';

function sanitize(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1F\x7F]/g, '');
}

export function registerCheckCommand(program: Command): void {
  program
    .command('check')
    .description('Hook handler — evaluates a tool call before execution')
    .argument('[data]', 'JSON string of the tool call')
    .action(async (data) => {
      const processPayload = async (raw: string) => {
        try {
          if (!raw || raw.trim() === '') process.exit(0);

          let payload = JSON.parse(raw) as {
            tool_name?: string;
            tool_input?: unknown;
            name?: string;
            args?: unknown;
            cwd?: string;
            session_id?: string;
            hook_event_name?: string; // Claude: "PreToolUse" | Gemini: "BeforeTool"
            tool_use_id?: string; // Claude-only
            permission_mode?: string; // Claude-only
            timestamp?: string; // Gemini-only
          };

          try {
            payload = JSON.parse(raw);
          } catch (err) {
            // If JSON is broken (e.g. half-sent due to timeout), log it and fail open.
            // We load config temporarily just to check if debug logging is on.
            const tempConfig = getConfig();
            if (process.env.NODE9_DEBUG === '1' || tempConfig.settings.enableHookLogDebug) {
              const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
              const errMsg = err instanceof Error ? err.message : String(err);
              fs.appendFileSync(
                logPath,
                `[${new Date().toISOString()}] JSON_PARSE_ERROR: ${errMsg}\nRAW: ${raw}\n`
              );
            }
            process.exit(0);
          }

          // Pass payload.cwd directly to getConfig() instead of mutating process.chdir —
          // process.chdir is process-global and would race with concurrent hook invocations.
          const config = getConfig(payload.cwd || undefined);

          // Eagerly start the daemon for activity logging (fire-and-forget).
          // Without this, tool events never reach `node9 tail` if the daemon
          // wasn't already running when the Claude Code session started.
          if (
            config.settings.autoStartDaemon &&
            !isDaemonRunning() &&
            !process.env.NODE9_NO_AUTO_DAEMON
          ) {
            try {
              // Resolve symlinks on argv[1] and verify it matches this package's own
              // CLI entry (dist/cli.js). Prevents spawn from executing an attacker-
              // controlled script if the process is invoked via a malicious wrapper or
              // crafted argv.
              const scriptPath = process.argv[1];
              if (typeof scriptPath !== 'string' || !path.isAbsolute(scriptPath))
                throw new Error('node9: argv[1] is not an absolute path');
              const resolvedScript = fs.realpathSync(scriptPath);
              const expectedCli = fs.realpathSync(path.resolve(__dirname, '../../cli.js'));
              if (resolvedScript !== expectedCli)
                throw new Error(
                  'node9: daemon spawn aborted — argv[1] does not resolve to the node9 CLI'
                );
              // Strip env vars that can inject code into the spawned Node.js process.
              const safeEnv = { ...process.env };
              for (const key of [
                'NODE_OPTIONS',
                'LD_PRELOAD',
                'LD_LIBRARY_PATH',
                'DYLD_INSERT_LIBRARIES',
                'NODE_PATH',
                'ELECTRON_RUN_AS_NODE',
              ]) {
                delete safeEnv[key];
              }
              const d = spawn(process.execPath, [scriptPath, 'daemon'], {
                detached: true,
                stdio: 'ignore',
                env: { ...safeEnv, NODE9_AUTO_STARTED: '1', NODE9_BROWSER_OPENED: '1' },
              });
              d.unref();
            } catch {}
          }

          // Debug logging — controlled by Env Var OR new Settings config
          if (process.env.NODE9_DEBUG === '1' || config.settings.enableHookLogDebug) {
            const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
            if (!fs.existsSync(path.dirname(logPath)))
              fs.mkdirSync(path.dirname(logPath), { recursive: true });
            fs.appendFileSync(logPath, `[${new Date().toISOString()}] STDIN: ${raw}\n`);
          }
          const toolName = sanitize(payload.tool_name ?? payload.name ?? '');
          const toolInput = payload.tool_input ?? payload.args ?? {};

          // Both Claude and Gemini send session_id + hook_event_name, but with different values:
          //   Claude:  hook_event_name = "PreToolUse" | "PostToolUse", also sends tool_use_id
          //   Gemini:  hook_event_name = "BeforeTool" | "AfterTool",   also sends timestamp
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
                : payload.tool_name !== undefined || payload.name !== undefined
                  ? 'Unknown Agent'
                  : 'Terminal';
          const mcpMatch = toolName.match(/^mcp__([^_](?:[^_]|_(?!_))*?)__/i);
          const mcpServer = mcpMatch?.[1];

          // ── THE NEGOTIATION LOOP (TALKING BACK TO THE AI) ───────────────
          const sendBlock = (
            msg: string,
            result?: {
              blockedBy?: string;
              changeHint?: string;
              blockedByLabel?: string;
              recoveryCommand?: string;
              ruleDescription?: string;
            }
          ) => {
            // 1. Determine the context (User vs Policy)
            const blockedByContext =
              result?.blockedByLabel || result?.blockedBy || 'Local Security Policy';

            // 2. Identify if it was a human decision or an automated rule
            const isHumanDecision =
              blockedByContext.toLowerCase().includes('user') ||
              blockedByContext.toLowerCase().includes('daemon') ||
              blockedByContext.toLowerCase().includes('decision');

            // 3. Print to the human terminal for visibility.
            // MUST NOT use stderr (console.error) — Claude Code treats any stderr
            // output as a hook error and fails open, allowing the tool to proceed
            // regardless of the JSON block payload. Write directly to /dev/tty so
            // the message appears on the developer's screen without touching the
            // Claude Code pipe.
            let ttyFd: number | null = null;
            try {
              ttyFd = fs.openSync('/dev/tty', 'w');
              const writeTty = (line: string) => fs.writeSync(ttyFd!, line + '\n');
              if (
                blockedByContext.includes('DLP') ||
                blockedByContext.includes('Secret Detected') ||
                blockedByContext.includes('Credential Review')
              ) {
                writeTty(chalk.bgRed.white.bold(`\n 🚨 NODE9 DLP ALERT — CREDENTIAL DETECTED `));
                writeTty(chalk.red.bold(`   A sensitive secret was found in the tool arguments!`));
              } else {
                writeTty(chalk.red(`\n🛑 Node9 blocked "${toolName}"`));
              }
              if (result?.ruleDescription) writeTty(chalk.white(`   ${result.ruleDescription}`));
              writeTty(chalk.gray(`   Triggered by: ${blockedByContext}`));
              if (result?.changeHint) writeTty(chalk.cyan(`   To change:  ${result.changeHint}`));
              if (result?.recoveryCommand)
                writeTty(chalk.green(`   💡 Run:      ${result.recoveryCommand}`));
              writeTty('');
            } catch {
              // /dev/tty unavailable (CI, non-interactive) — skip visual output
            } finally {
              if (ttyFd !== null)
                try {
                  fs.closeSync(ttyFd);
                } catch {
                  /* ignore */
                }
            }

            // 4. THE NEGOTIATION PROMPT: Context-specific instruction for the AI
            const aiFeedbackMessage = buildNegotiationMessage(
              blockedByContext,
              isHumanDecision,
              msg,
              result?.recoveryCommand
            );

            // 5. Send the structured JSON back to the LLM agent
            process.stdout.write(
              JSON.stringify({
                decision: 'block',
                reason: aiFeedbackMessage, // This is the core instruction
                hookSpecificOutput: {
                  hookEventName: 'PreToolUse',
                  permissionDecision: 'deny',
                  permissionDecisionReason: aiFeedbackMessage,
                },
              }) + '\n'
            );
            // Exit code 2 signals a block to Claude Code. Exit 0 = allow, non-zero = block.
            process.exit(2);
          };
          if (!toolName) {
            sendBlock('Node9: unrecognised hook payload — tool name missing.');
            return;
          }

          const meta = { agent, mcpServer };

          // Snapshot BEFORE the tool runs (PreToolUse) so undo can restore to
          // the state prior to this change. Snapshotting after (PostToolUse)
          // captures the changed state, making undo a no-op.
          if (shouldSnapshot(toolName, toolInput, config)) {
            await createShadowSnapshot(toolName, toolInput, config.policy.snapshot.ignorePaths);
          }

          const safeCwdForAuth =
            typeof payload.cwd === 'string' && path.isAbsolute(payload.cwd)
              ? payload.cwd
              : undefined;
          const result = await authorizeHeadless(toolName, toolInput, meta, {
            cwd: safeCwdForAuth,
          });

          if (result.approved) {
            // Only write to stderr in debug mode — Claude Code treats any stderr
            // output as a hook error regardless of exit code (see GitHub issue).
            if (result.checkedBy && process.env.NODE9_DEBUG === '1')
              process.stderr.write(`✓ node9 [${result.checkedBy}]: "${toolName}" allowed\n`);
            process.exit(0);
          }

          // Auto-start daemon if allowed
          if (
            result.noApprovalMechanism &&
            !isDaemonRunning() &&
            !process.env.NODE9_NO_AUTO_DAEMON &&
            !process.stdout.isTTY &&
            config.settings.autoStartDaemon
          ) {
            try {
              const tty = fs.openSync('/dev/tty', 'w');
              fs.writeSync(
                tty,
                chalk.cyan('\n🛡️  Node9: Starting approval daemon automatically...\n')
              );
              fs.closeSync(tty);
            } catch {
              /* non-interactive env */
            }
            const daemonReady = await autoStartDaemonAndWait();
            if (daemonReady) {
              const retry = await authorizeHeadless(toolName, toolInput, meta, {
                cwd: safeCwdForAuth,
              });
              if (retry.approved) {
                if (retry.checkedBy && process.env.NODE9_DEBUG === '1')
                  process.stderr.write(`✓ node9 [${retry.checkedBy}]: "${toolName}" allowed\n`);
                process.exit(0);
              }
              // Denials communicate via exit code (non-zero) and JSON on stdout —
              // stderr is intentionally unused so Claude Code never treats a block
              // as a "hook error" (it does so on any stderr output regardless of exit code).
              sendBlock(retry.reason ?? `Node9 blocked "${toolName}".`, {
                ...retry,
                blockedByLabel: retry.blockedByLabel,
              });
              return;
            }
          }

          // Denials communicate via exit code (non-zero) and JSON on stdout —
          // stderr is intentionally unused so Claude Code never treats a block
          // as a "hook error" (it does so on any stderr output regardless of exit code).
          sendBlock(result.reason ?? `Node9 blocked "${toolName}".`, {
            ...result,
            blockedByLabel: result.blockedByLabel,
          });
        } catch (err: unknown) {
          if (process.env.NODE9_DEBUG === '1') {
            const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
            const errMsg = err instanceof Error ? err.message : String(err);
            fs.appendFileSync(logPath, `[${new Date().toISOString()}] ERROR: ${errMsg}\n`);
          }
          process.exit(0); // Fail open so we never break Claude on a parse error
        }
      };

      if (data) {
        await processPayload(data);
      } else {
        let raw = '';
        let processed = false;
        let inactivityTimer: NodeJS.Timeout | null = null;

        const done = async () => {
          // Atomic check: prevents double-processing if 'end' and 'timeout' fire together
          if (processed) return;
          processed = true;

          // Kill the timer so it doesn't fire while we are waiting for human approval
          if (inactivityTimer) clearTimeout(inactivityTimer);

          if (!raw.trim()) return process.exit(0);

          await processPayload(raw);
        };

        process.stdin.setEncoding('utf-8');

        process.stdin.on('data', (chunk) => {
          raw += chunk;

          // Sliding window: reset timer every time data arrives
          if (inactivityTimer) clearTimeout(inactivityTimer);
          inactivityTimer = setTimeout(() => void done(), 2000);
        });

        process.stdin.on('end', () => {
          void done();
        });

        // Initial safety: if no data arrives at all within 5s, exit.
        inactivityTimer = setTimeout(() => void done(), 5000);
      }
    });
}

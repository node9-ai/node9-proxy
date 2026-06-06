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
import { defaultSkillRoots, resolveUserSkillRoot, verifyAndPinRoots } from '../../skill-pin';
import { scanArgs } from '../../dlp';
import { appendLocalAudit } from '../../audit';
import {
  extractToolName,
  extractToolInput,
  canonicalToolName,
  canonicalToolInput,
  agentLabelFromFlag,
} from '../../utils/hook-payload';

function sanitize(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1F\x7F]/g, '');
}

/**
 * Identify the AI agent running this tool call. Source of truth for the
 * SaaS Report's "AI Agents" breakdown — the value flows: detected here →
 * passed in `meta.agent` → backend stores as the row's hostname column.
 *
 * Detection layers, ordered by signal strength:
 *
 *   1. Hook payload fingerprint — most reliable. Claude Code's hook
 *      sends `PreToolUse` event names + `tool_use_id`; Gemini CLI sends
 *      `BeforeTool` + `timestamp`. These are deterministic.
 *
 *   2. Environment variables — a process running under an AI host often
 *      sets identifying env vars even when the call doesn't come through
 *      the hook (e.g. user runs `node9 check` directly inside a Claude
 *      Code subshell). These are softer but useful when the payload is
 *      absent.
 *
 *   3. Final fallback — "Terminal" for bare-shell calls, "Unknown Agent"
 *      when there's a tool-name signal but no AI hint at all.
 *
 * Exported for unit testing — pure function over (payload, process.env).
 */
export function detectAiAgent(payload: Record<string, unknown>): string {
  // Layer 0: explicit meta.agent tag set by a node9-authored plugin
  // shim (Opencode, Pi, and any future agent we wire up by dropping a
  // plugin file). The shim controls both ends — it shapes the payload
  // and sets meta.agent — so we trust the tag absolutely when present
  // and well-formed. Must precede Layer 1 because these shims still
  // include hook_event_name: "PreToolUse" in the payload to match the
  // shape `node9 check` already understands.
  const meta = payload.meta;
  if (meta && typeof meta === 'object') {
    const tagged = (meta as { agent?: unknown }).agent;
    if (typeof tagged === 'string' && tagged.length > 0) return tagged;
  }

  // Layer 1: payload fingerprint (existing, most reliable).
  // Codex's payload is Claude-compatible (same hook_event_name, tool_use_id,
  // permission_mode) PLUS a Codex-specific `turn_id` field per
  // openai/codex pre-tool-use.command.input.schema.json ("Codex extension:
  // expose the active turn id"). Must run before the Claude branch or every
  // Codex tool call gets misattributed.
  if (payload.turn_id !== undefined) {
    return 'Codex';
  }
  // Antigravity (agy) — third dialect, verified against agy 1.0.6
  // spy-hook captures: tool name/args nest under `toolCall`, the
  // conversation id is `conversationId`, and there is NO
  // hook_event_name field at all — so no overlap with the Claude
  // branch below. `toolCall !== undefined` also matches the
  // `toolCall: null` non-tool PostToolUse payloads.
  if (payload.toolCall !== undefined || payload.conversationId !== undefined) {
    return 'Antigravity';
  }
  if (
    payload.hook_event_name === 'PreToolUse' ||
    payload.hook_event_name === 'PostToolUse' ||
    payload.tool_use_id !== undefined ||
    payload.permission_mode !== undefined
  ) {
    return 'Claude Code';
  }
  if (
    payload.hook_event_name === 'BeforeTool' ||
    payload.hook_event_name === 'AfterTool' ||
    payload.timestamp !== undefined
  ) {
    return 'Gemini CLI';
  }
  // Hermes Agent uses lowercase snake_case hook event names per
  // agent/shell_hooks.py:_serialize_payload — distinct from Claude's
  // PascalCase and Gemini's BeforeTool/AfterTool so no overlap.
  if (payload.hook_event_name === 'pre_tool_call' || payload.hook_event_name === 'post_tool_call') {
    return 'Hermes';
  }

  // Layer 2: env-var fallback. Order matters — most specific first.
  // CLAUDECODE is set by the Claude Code CLI on session start. Gemini's
  // CLI sets GEMINI_API_KEY (often present) or GEMINI_CLI_VERSION (newer
  // versions). Cursor sets CURSOR_TRACE_ID for tool-call attribution.
  // Aider sets AIDER_VERSION when running under aider. Hermes sets
  // HERMES_SESSION_ID on every session before tool dispatch
  // (run_agent.py:1913).
  if (process.env.CLAUDECODE === '1' || process.env.CLAUDE_CODE_SESSION_ID) {
    return 'Claude Code';
  }
  if (process.env.HERMES_SESSION_ID || process.env.HERMES_HOME || process.env.HERMES_INTERACTIVE) {
    return 'Hermes';
  }
  // agy sets ANTIGRAVITY_CONVERSATION_ID in every hook's environment
  // (verified, agy 1.0.6). Must precede the Gemini check — a machine
  // with a leftover GEMINI_API_KEY in the shell profile would otherwise
  // misattribute agy calls to the (EOL'd) Gemini CLI.
  if (process.env.ANTIGRAVITY_CONVERSATION_ID) {
    return 'Antigravity';
  }
  if (process.env.GEMINI_CLI_VERSION || process.env.GEMINI_API_KEY) {
    return 'Gemini CLI';
  }
  if (process.env.CURSOR_TRACE_ID || process.env.CURSOR_SESSION_ID) {
    return 'Cursor';
  }
  if (process.env.AIDER_VERSION) {
    return 'Aider';
  }

  // Layer 3: payload has a tool name but no AI fingerprint — call came
  // from somewhere we don't recognise yet.
  if (payload.tool_name !== undefined || payload.name !== undefined) {
    return 'Unknown Agent';
  }
  return 'Terminal';
}

export function registerCheckCommand(program: Command): void {
  program
    .command('check', { hidden: true })
    .description('Hook handler — evaluates a tool call before execution')
    .argument('[data]', 'JSON string of the tool call')
    .option(
      '--agent <name>',
      'Agent identity override, set by node9-authored hook registrations (e.g. antigravity)'
    )
    .action(async (data, opts: { agent?: string }) => {
      const agentOverride = agentLabelFromFlag(opts?.agent);
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
            // Path to the agent's session JSONL/transcript file. Both Claude
            // Code and Gemini CLI populate this in the hook payload. Forwarded
            // to the SaaS so the dashboard can correlate audit rows to the
            // session content — essential for Gemini, where session_id can
            // drift across resumes but transcript_path is stable.
            transcript_path?: string;
            hook_event_name?: string; // Claude: "PreToolUse" | Gemini: "BeforeTool"
            tool_use_id?: string; // Claude-only
            permission_mode?: string; // Claude-only
            timestamp?: string; // Gemini-only
            turn_id?: string; // Codex-only (#178 fingerprint)
            prompt?: string; // UserPromptSubmit payload body
            // Antigravity (agy) dialect — verified against agy 1.0.6:
            toolCall?: { name?: string; args?: unknown } | null;
            conversationId?: string; // agy's session_id equivalent
            transcriptPath?: string; // agy's transcript_path equivalent
            workspacePaths?: string[]; // agy has no top-level cwd; [0] is the workspace root
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

          // UserPromptSubmit — paste-into-prompt DLP. The payload has `prompt`
          // but no tool_name / tool_input, so the tool-call codepath below
          // would reach the "tool name missing" sendBlock. Handle it here:
          // scan the prompt for credentials and block before the prompt ever
          // reaches the model. No tool-call config/orchestrator path needed —
          // DLP is enabled by default for these patterns.
          if (payload.hook_event_name === 'UserPromptSubmit') {
            const prompt = typeof payload.prompt === 'string' ? payload.prompt : '';

            // Debug logging — sanitize the prompt before persisting so a
            // pasted secret never lands on disk via hook-debug.log. We early-
            // exit before the generic debug log at line ~212, so this is the
            // only place that records UserPromptSubmit telemetry.
            if (process.env.NODE9_DEBUG === '1') {
              try {
                const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
                if (!fs.existsSync(path.dirname(logPath)))
                  fs.mkdirSync(path.dirname(logPath), { recursive: true });
                const sanitized = JSON.stringify({
                  ...payload,
                  prompt: `<redacted, ${prompt.length} bytes>`,
                });
                fs.appendFileSync(logPath, `[${new Date().toISOString()}] STDIN: ${sanitized}\n`);
              } catch {
                // Non-fatal — debug logging is best-effort.
              }
            }

            if (!prompt) process.exit(0);

            const dlpMatch = scanArgs({ prompt });
            if (!dlpMatch) process.exit(0);

            // Audit FIRST — the block record must survive any downstream error.
            // Force argsHash so the secret value never lands in the audit log.
            const agent = detectAiAgent(payload);
            const sessionId =
              typeof payload.session_id === 'string' ? payload.session_id : undefined;
            appendLocalAudit(
              'UserPromptSubmit',
              { prompt },
              'deny',
              'dlp-block',
              { agent, sessionId },
              true
            );

            const reason =
              `🚨 Node9 DLP: ${dlpMatch.patternName} detected in prompt ` +
              `(${dlpMatch.redactedSample}). Prompt was not submitted — ` +
              `remove the credential and try again.`;

            // /dev/tty banner for the human, mirroring sendBlock's UX. Never
            // stderr (Codex parses stderr for the block reason and would echo
            // the entire banner back as the LLM-visible message).
            try {
              const ttyFd = fs.openSync('/dev/tty', 'w');
              fs.writeSync(
                ttyFd,
                chalk.bgRed.white.bold(`\n 🚨 NODE9 DLP — PROMPT BLOCKED \n`) +
                  chalk.red(`   ${dlpMatch.patternName} detected in your prompt.\n`) +
                  chalk.gray(`   Match: ${dlpMatch.redactedSample}\n`) +
                  chalk.cyan(`   Edit the prompt to remove the credential and resubmit.\n\n`)
              );
              fs.closeSync(ttyFd);
            } catch {
              // /dev/tty unavailable (CI, non-interactive) — skip visual output.
            }

            // Both Codex and Claude read JSON-on-stdout with decision="block".
            // The only shape difference is hookSpecificOutput.permissionDecision:
            // Claude requires it ('deny'); Codex's UserPromptSubmit schema
            // explicitly does not define it (additionalProperties: false).
            const isCodex = agent === 'Codex';
            process.stdout.write(
              JSON.stringify({
                decision: 'block',
                reason,
                systemMessage: reason,
                hookSpecificOutput: isCodex
                  ? { hookEventName: 'UserPromptSubmit' }
                  : {
                      hookEventName: 'UserPromptSubmit',
                      permissionDecision: 'deny',
                      permissionDecisionReason: reason,
                    },
              }) + '\n'
            );
            // Non-zero exit signals block to both agents.
            process.exit(2);
          }

          // Antigravity payloads carry no top-level cwd; the workspace root
          // in workspacePaths[0] is the correct base for per-project config
          // resolution (verified payload shape, agy 1.0.6).
          const payloadCwd =
            typeof payload.cwd === 'string'
              ? payload.cwd
              : Array.isArray(payload.workspacePaths) &&
                  typeof payload.workspacePaths[0] === 'string'
                ? payload.workspacePaths[0]
                : undefined;

          // Pass payload.cwd directly to getConfig() instead of mutating process.chdir —
          // process.chdir is process-global and would race with concurrent hook invocations.
          // CLAUDE.md: validate with path.isAbsolute() before passing to getConfig() to
          // prevent a hook payload from steering config resolution at a traversal path.
          // Matches the pattern already used at the other payload.cwd sites in this file.
          const safeCwdForConfig =
            typeof payloadCwd === 'string' && path.isAbsolute(payloadCwd) ? payloadCwd : undefined;
          const config = getConfig(safeCwdForConfig);

          // Eagerly start the daemon for activity logging (fire-and-forget).
          // Without this, tool events never reach `node9 tail` if the daemon
          // wasn't already running when the Claude Code session started.
          if (
            config.settings.autoStartDaemon &&
            !isDaemonRunning() &&
            !process.env.NODE9_NO_AUTO_DAEMON
          ) {
            try {
              const scriptPath = process.argv[1];
              if (typeof scriptPath !== 'string' || !path.isAbsolute(scriptPath))
                throw new Error('node9: argv[1] is not an absolute path');

              // Security: verify argv[1] lives inside this package's own dist/
              // directory — prevents spawn from executing an attacker-controlled
              // script if the process is invoked via a malicious wrapper.
              // We check directory prefix (not exact path equality) so the check
              // survives different install roots: nvm, global npm, local installs,
              // and symlinked bin entries all resolve to the same dist/ tree.
              const resolvedScript = fs.realpathSync(scriptPath);
              const packageDist = fs.realpathSync(path.resolve(__dirname, '../..'));
              if (
                !resolvedScript.startsWith(packageDist + path.sep) &&
                resolvedScript !== packageDist
              )
                throw new Error(
                  `node9: daemon spawn aborted — argv[1] (${resolvedScript}) is outside package dist (${packageDist})`
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
                env: { ...safeEnv, NODE9_AUTO_STARTED: '1' },
              });
              d.unref();
            } catch (spawnErr) {
              // Log spawn failures so they're visible in hook-debug.log instead
              // of silently swallowed — makes install-path mismatches diagnosable.
              const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
              const msg = spawnErr instanceof Error ? spawnErr.message : String(spawnErr);
              try {
                fs.appendFileSync(
                  logPath,
                  `[${new Date().toISOString()}] daemon-autostart-failed: ${msg}\n`
                );
              } catch {
                /* non-fatal */
              }
            }
          }

          // Debug logging — controlled by Env Var OR new Settings config
          if (process.env.NODE9_DEBUG === '1' || config.settings.enableHookLogDebug) {
            const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
            if (!fs.existsSync(path.dirname(logPath)))
              fs.mkdirSync(path.dirname(logPath), { recursive: true });
            fs.appendFileSync(logPath, `[${new Date().toISOString()}] STDIN: ${raw}\n`);
          }
          const rawToolName = sanitize(extractToolName(payload));
          const toolName = canonicalToolName(rawToolName);
          // Normalise agent-native arg shapes (agy run_command:
          // CommandLine/Cwd → command/cwd) before shields, DLP and
          // snapshot inspect them.
          const toolInput = canonicalToolInput(rawToolName, extractToolInput(payload));

          const agent = agentOverride ?? detectAiAgent(payload);
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
            if (agent === 'Antigravity') {
              // Antigravity honours ONLY `decision: "deny"` — verified live
              // against agy 1.0.6: the Claude shape below (`decision:
              // "block"` + exit 2) is silently ignored and the tool RUNS
              // (fail-open). The reason string is surfaced to the model as
              // "Tool call denied with reason: …", so the negotiation
              // message still works. Exit code is ignored by agy; exit 0
              // matches the verified capture exactly.
              process.stdout.write(
                JSON.stringify({ decision: 'deny', reason: aiFeedbackMessage }) + '\n'
              );
              process.exit(0);
            }
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

          // Antigravity aliases: conversationId ≙ session_id,
          // transcriptPath ≙ transcript_path.
          const sessionId =
            typeof payload.session_id === 'string'
              ? payload.session_id
              : typeof payload.conversationId === 'string'
                ? payload.conversationId
                : undefined;
          const transcriptPath =
            typeof payload.transcript_path === 'string'
              ? payload.transcript_path
              : typeof payload.transcriptPath === 'string'
                ? payload.transcriptPath
                : undefined;
          const meta = { agent, mcpServer, sessionId, transcriptPath };

          // ── Skill pinning — supply chain & update drift defense (AST 02 + AST 07) ──
          // Off by default; opt-in via config.policy.skillPinning.enabled.
          // mode 'warn': /dev/tty notification on drift, tool call allowed (exit 0).
          // mode 'block': hard quarantine on drift, tool call blocked (exit 2).
          // Per-session memoisation in ~/.node9/skill-sessions/ so hashing
          // runs at most once per Claude/Gemini session id.
          const skillPinCfg = config.policy.skillPinning;
          const rawSessionId = sessionId ?? '';
          const safeSessionId = /^[A-Za-z0-9_\-]{1,128}$/.test(rawSessionId) ? rawSessionId : '';
          if (skillPinCfg.enabled && safeSessionId) {
            try {
              const sessionsDir = path.join(os.homedir(), '.node9', 'skill-sessions');
              const flagPath = path.join(sessionsDir, `${safeSessionId}.json`);
              let flag: { state?: string; detail?: string } | null = null;
              try {
                flag = JSON.parse(fs.readFileSync(flagPath, 'utf-8'));
              } catch {
                /* missing/unreadable — treat as fresh */
              }

              const writeFlag = (data: { state: string; detail?: string }) => {
                try {
                  fs.mkdirSync(sessionsDir, { recursive: true });
                  fs.writeFileSync(
                    flagPath,
                    JSON.stringify({ ...data, timestamp: new Date().toISOString() }, null, 2),
                    { mode: 0o600 }
                  );
                } catch {
                  /* best effort */
                }
              };

              // /dev/tty notification — non-blocking (warn mode only).
              const sendSkillWarn = (detail: string, recoveryCmd?: string) => {
                let ttyFd: number | null = null;
                try {
                  ttyFd = fs.openSync('/dev/tty', 'w');
                  const w = (line: string) => fs.writeSync(ttyFd!, line + '\n');
                  w(chalk.yellow(`\n⚠️  Node9: installed skill drift detected`));
                  w(chalk.gray(`   ${detail}`));
                  w(
                    chalk.gray(
                      `   If you updated a plugin, acknowledge the change to clear this warning.`
                    )
                  );
                  if (recoveryCmd) w(chalk.green(`   💡 Run:  ${recoveryCmd}`));
                  w('');
                } catch {
                  /* /dev/tty unavailable in CI — skip */
                } finally {
                  if (ttyFd !== null)
                    try {
                      fs.closeSync(ttyFd);
                    } catch {
                      /* ignore */
                    }
                }
              };

              // Memoised states: 'verified' / 'warned' → skip.
              // 'quarantined' → only block in block mode; in warn mode, re-verify.
              if (flag && flag.state === 'quarantined' && skillPinCfg.mode === 'block') {
                sendBlock(
                  `Node9: session quarantined — installed skill changed. Open a separate terminal and run: node9 skill pin list (to see what changed) then: node9 skill pin update <rootKey> (to acknowledge). If you updated a plugin intentionally, this is expected.`,
                  {
                    blockedByLabel: 'Skill Pin Quarantine',
                    recoveryCommand: 'node9 skill pin list',
                  }
                );
                return;
              }

              if (!flag || (flag.state !== 'verified' && flag.state !== 'warned')) {
                const absoluteCwd =
                  typeof payloadCwd === 'string' && path.isAbsolute(payloadCwd)
                    ? payloadCwd
                    : undefined;
                const extraRoots = skillPinCfg.roots;
                const resolvedExtra = extraRoots
                  .map((r) => resolveUserSkillRoot(r, absoluteCwd))
                  .filter((r): r is string => typeof r === 'string');
                const roots = [...defaultSkillRoots(absoluteCwd), ...resolvedExtra];

                const result = verifyAndPinRoots(roots);

                if (result.kind === 'corrupt') {
                  if (skillPinCfg.mode === 'block') {
                    writeFlag({
                      state: 'quarantined',
                      detail: `pin file corrupt: ${result.detail}`,
                    });
                    sendBlock('Node9: skill pin file is corrupt — fail-closed.', {
                      blockedByLabel: 'Skill Pin Quarantine',
                      recoveryCommand: 'node9 skill pin reset',
                    });
                    return;
                  }
                  // warn mode: notify, allow
                  writeFlag({ state: 'warned', detail: `pin file corrupt: ${result.detail}` });
                  sendSkillWarn(
                    `Skill pin file is corrupt: ${result.detail}`,
                    'node9 skill pin reset'
                  );
                } else if (result.kind === 'drift') {
                  if (skillPinCfg.mode === 'block') {
                    writeFlag({ state: 'quarantined', detail: result.summary });
                    sendBlock(
                      `Node9: installed skill changed — ${result.summary}. If you updated a plugin, open a separate terminal and run: node9 skill pin update ${result.changedRootKey}`,
                      {
                        blockedByLabel: 'Skill Pin Quarantine',
                        recoveryCommand: `node9 skill pin update ${result.changedRootKey}`,
                      }
                    );
                    return;
                  }
                  // warn mode: notify, allow
                  writeFlag({ state: 'warned', detail: result.summary });
                  sendSkillWarn(result.summary, `node9 skill pin update ${result.changedRootKey}`);
                } else {
                  writeFlag({ state: 'verified' });
                }

                // Best-effort GC of session flags older than 7 days.
                try {
                  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
                  for (const name of fs.readdirSync(sessionsDir)) {
                    const p = path.join(sessionsDir, name);
                    try {
                      if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p);
                    } catch {
                      /* ignore */
                    }
                  }
                } catch {
                  /* ignore */
                }
              }
            } catch (err) {
              if (process.env.NODE9_DEBUG === '1') {
                try {
                  const dbg = path.join(os.homedir(), '.node9', 'hook-debug.log');
                  const msg = err instanceof Error ? err.message : String(err);
                  fs.appendFileSync(dbg, `[${new Date().toISOString()}] SKILL_PIN_ERROR: ${msg}\n`);
                } catch {
                  /* ignore */
                }
              }
            }
          }

          // Snapshot BEFORE the tool runs (PreToolUse) so undo can restore to
          // the state prior to this change. Snapshotting after (PostToolUse)
          // captures the changed state, making undo a no-op.
          if (shouldSnapshot(toolName, toolInput, config)) {
            await createShadowSnapshot(toolName, toolInput, config.policy.snapshot.ignorePaths);
          }

          const safeCwdForAuth =
            typeof payloadCwd === 'string' && path.isAbsolute(payloadCwd) ? payloadCwd : undefined;
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

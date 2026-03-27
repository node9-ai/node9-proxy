// src/cli/commands/log.ts
// PostToolUse hook — records executed tool calls to the audit log.
// Registered as `node9 log` by cli.ts.
import type { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { redactSecrets } from '../../audit';
import { getConfig } from '../../config';
import { shouldSnapshot } from '../../policy';
import { createShadowSnapshot } from '../../undo';

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
            args?: unknown;
            cwd?: string;
          };

          // Handle both Claude (tool_name) and Gemini (name)
          const tool = sanitize(payload.tool_name ?? payload.name ?? 'unknown');
          const rawInput = payload.tool_input ?? payload.args ?? {};

          // Audit write FIRST — before any config load that could fail.
          // A config error must never silently skip the audit entry.
          const entry = {
            ts: new Date().toISOString(),
            tool: tool,
            args: JSON.parse(redactSecrets(JSON.stringify(rawInput))),
            decision: 'allowed',
            source: 'post-hook',
          };

          const logPath = path.join(os.homedir(), '.node9', 'audit.log');
          if (!fs.existsSync(path.dirname(logPath)))
            fs.mkdirSync(path.dirname(logPath), { recursive: true });
          fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');

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

          // PostToolUse snapshot is a fallback for tools not covered by PreToolUse.
          // Uses the same configurable snapshot policy.
          if (shouldSnapshot(tool, {}, config)) {
            await createShadowSnapshot('unknown', {}, config.policy.snapshot.ignorePaths);
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

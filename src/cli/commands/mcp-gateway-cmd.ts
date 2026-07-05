// src/cli/commands/mcp-gateway-cmd.ts
// `node9 mcp gateway|ungateway|status` — the manual foundation for governing MCP
// servers: route an upstream through `node9 mcp-gateway` (so per-tool app
// permissions apply), list what's governed, and reverse it. The reconcile loop
// (daemon) calls the same engine.
import type { Command } from 'commander';
import chalk from 'chalk';
import { inventoryMcp, toGateway, fromGateway, writeMcpEntry, type McpEntry } from '../../mcp-wrap';
import { resolveMcpStatus, type McpStatusEntry } from '../../mcp-status';

// Plain state word, padded so the CONNECTED column lines up across colored rows
// (chalk-wrapped strings can't be padEnd'd — pad first, colour after).
const STATE_WORD: Record<McpEntry['state'], string> = {
  gatewayed: 'governed',
  'node9-self': 'node9',
  remote: 'remote (n/a)',
  ungoverned: 'UNGOVERNED',
};

function stateChip(state: McpEntry['state']): string {
  const w = STATE_WORD[state].padEnd(12);
  if (state === 'gatewayed') return chalk.green(w);
  if (state === 'node9-self') return chalk.gray(w);
  if (state === 'remote') return chalk.gray(w);
  return chalk.yellow(w);
}

function relativeAge(ms: number, now: number): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

// The CONNECTED column — the live signal + a fix hint for the two bad states.
function connectionChip(e: McpStatusEntry, now: number): string {
  switch (e.connection) {
    case 'connected':
      return chalk.green(
        `✓ connected${e.lastSeenAt ? ` (${relativeAge(e.lastSeenAt, now)})` : ''}`
      );
    case 'stale':
      return chalk.yellow(`⚠ stale${e.lastSeenAt ? ` (${relativeAge(e.lastSeenAt, now)})` : ''}`);
    case 'pending-launch':
      return chalk.cyan(`… pending — restart ${e.agentLabel} to connect`);
    case 'unlaunchable':
      return chalk.red(
        `✗ can't launch — ${(e.missingEnv ?? []).map((v) => `$${v}`).join(', ')} not set`
      );
    default:
      return ''; // ungoverned / node9-self / remote — stateChip already says it
  }
}

// Resolve which entries a name refers to (optionally scoped to one agent).
function resolve(name: string, agent?: string): McpEntry[] {
  return inventoryMcp().filter((e) => e.name === name && (!agent || e.agent === agent));
}

function wrapEntry(e: McpEntry): void {
  // toGateway on the RAW entry so env/type/… are preserved. Pass the config key
  // as the display name (--config-name) so the dashboard/audit show "redis-dev",
  // not the command-derived "redis".
  writeMcpEntry(e.mcpFile, e.format, e.name, toGateway(e.raw, e.name));
}

// Re-wrap an ALREADY-gatewayed server: unwrap to the original upstream, then
// wrap again WITH --config-name. Same upstream ⇒ same serverKey ⇒ no pin/rule
// loss. Used by `--rewrap` to retrofit servers wrapped before --config-name.
function rewrapEntry(e: McpEntry): void {
  const orig = fromGateway(e.raw);
  if (!orig) {
    // Corrupt/hand-edited wrapper (no parseable --upstream) — refuse rather than
    // write back a broken command.
    throw new Error("couldn't parse the original upstream (corrupt gateway entry)");
  }
  writeMcpEntry(e.mcpFile, e.format, e.name, toGateway(orig, e.name));
}

export function registerMcpGatewayCommand(mcp: Command): void {
  mcp
    .command('status')
    .description('List every MCP server across your agents + whether node9 governs it')
    .action(() => {
      const now = Date.now();
      const rows = resolveMcpStatus(undefined, process.env, now);
      if (rows.length === 0) {
        console.error(chalk.gray('No MCP servers found in any agent config.'));
        return;
      }
      for (const e of rows) {
        const conn = connectionChip(e, now);
        console.error(
          `  ${e.agentLabel.padEnd(14)} ${e.name.padEnd(24)} ${stateChip(e.state)}${conn ? ` ${conn}` : ''}`
        );
      }
      const ungoverned = rows.filter((e) => e.connection === 'ungoverned').length;
      const unlaunchable = rows.filter((e) => e.connection === 'unlaunchable').length;
      const pending = rows.filter((e) => e.connection === 'pending-launch').length;
      if (ungoverned > 0) {
        console.error(
          chalk.yellow(
            `\n${ungoverned} ungoverned — run ` +
              chalk.bold('node9 mcp gateway --all') +
              ' to govern.'
          )
        );
      }
      if (pending > 0) {
        console.error(
          chalk.cyan(`${pending} governed but not yet connected — restart the agent to activate.`)
        );
      }
      if (unlaunchable > 0) {
        console.error(
          chalk.red(
            `${unlaunchable} can't launch — set the missing env var(s) where the agent starts (a restart alone won't fix it).`
          )
        );
      }
    });

  mcp
    .command('gateway [name]')
    .description('Route an ungoverned MCP server through node9 (wrap it). --all for every one.')
    .option('--all', 'wrap every server across all agents (ungoverned, or governed with --rewrap)')
    .option('--agent <id>', 'disambiguate a server name that exists in more than one agent')
    .option(
      '--rewrap',
      're-wrap an ALREADY-governed server to refresh its display name (--config-name); serverKey + rules are preserved'
    )
    .action(
      (name: string | undefined, opts: { all?: boolean; agent?: string; rewrap?: boolean }) => {
        const inv = inventoryMcp();
        // --rewrap operates on GOVERNED servers (refresh); the default wraps UNGOVERNED.
        const targetState: McpEntry['state'] = opts.rewrap ? 'gatewayed' : 'ungoverned';
        let targets: McpEntry[];
        if (opts.all) {
          targets = inv.filter((e) => e.state === targetState);
        } else if (name) {
          const matches = resolve(name, opts.agent);
          if (matches.length === 0) {
            console.error(chalk.red(`No MCP server named "${name}" found.`));
            process.exitCode = 1;
            return;
          }
          if (matches.length > 1) {
            console.error(
              chalk.red(`"${name}" exists in ${matches.length} agents — pass --agent <id> (`) +
                matches.map((m) => m.agent).join(', ') +
                ').'
            );
            process.exitCode = 1;
            return;
          }
          targets = matches;
        } else {
          console.error(chalk.red('Pass a server name or --all. See `node9 mcp status`.'));
          process.exitCode = 1;
          return;
        }

        const doable = targets.filter((e) => e.state === targetState);
        if (doable.length === 0) {
          console.error(
            chalk.gray(
              opts.rewrap
                ? 'Nothing to do — no governed servers to refresh.'
                : 'Nothing to do — already governed (or node9-self).'
            )
          );
          return;
        }
        const agents = new Set<string>();
        let failed = 0;
        for (const e of doable) {
          try {
            // Both paths can throw if the config changed/broke since inventory (TOCTOU).
            if (opts.rewrap) rewrapEntry(e);
            else wrapEntry(e);
            agents.add(e.agentLabel);
            const verb = opts.rewrap ? 'refreshed' : 'governed';
            console.error(chalk.green(`✓ ${verb} ${e.name}`) + chalk.gray(` (${e.agentLabel})`));
          } catch (err) {
            failed++;
            const msg = err instanceof Error ? err.message : String(err);
            console.error(
              chalk.red(`✗ failed ${e.name}`) + chalk.gray(` (${e.agentLabel}): ${msg}`)
            );
          }
        }
        if (failed > 0) process.exitCode = 1;
        if (agents.size > 0) {
          console.error(
            chalk.bold(`\nRestart ${[...agents].join(', ')}`) +
              chalk.gray(' to activate. Undo any server with ') +
              chalk.cyan('node9 mcp ungateway <name>') +
              chalk.gray('.')
          );
        }
      }
    );

  mcp
    .command('ungateway <name>')
    .description('Restore an MCP server to its original (un-route it from node9)')
    .option('--agent <id>', 'disambiguate a name in more than one agent')
    .action((name: string, opts: { agent?: string }) => {
      const matches = resolve(name, opts.agent).filter((e) => e.state === 'gatewayed');
      if (matches.length === 0) {
        console.error(chalk.red(`No governed MCP server named "${name}" found.`));
        process.exitCode = 1;
        return;
      }
      if (matches.length > 1) {
        console.error(chalk.red(`"${name}" is governed in multiple agents — pass --agent <id>.`));
        process.exitCode = 1;
        return;
      }
      const e = matches[0];
      const orig = fromGateway(e.raw);
      if (!orig) {
        console.error(chalk.red(`Couldn't parse the original command for "${name}".`));
        process.exitCode = 1;
        return;
      }
      try {
        writeMcpEntry(e.mcpFile, e.format, e.name, orig);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`Failed to restore "${name}": ${msg}`));
        process.exitCode = 1;
        return;
      }
      console.error(
        chalk.green(`✓ restored ${e.name}`) +
          chalk.gray(` (${e.agentLabel}) — restart ${e.agentLabel} to apply.`)
      );
    });
}

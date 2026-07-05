// src/cli/commands/heal.ts
// `node9 heal` — the EXPLICIT, backup-first fix for an agent whose node9 hooks were
// wiped (e.g. by the agent's own update). This is the human-invoked counterpart to
// the daemon's P1 nudge: re-install node9's hooks for a governed-but-now-unwired
// agent. Attended by design, so it never fights the user the way a silent auto-loop
// could. The re-install IS setupAgent (already idempotent + self-healing) — heal
// adds a BACKUP of the agent's config first (setup's writeJson does not back up).
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { getAgentWiring, type AgentWiringRow } from '../../agent-wiring';
import { setupAgent } from '../../setup';
import { loadHookBaseline, loadNotified, saveNotified } from '../../daemon/hook-baseline';

// A restorable hook/shim surface exists (excludes MCP-only agents like Cursor,
// whose hooks array is empty and whose wireState is never 'wired').
const hasHookSurface = (a: AgentWiringRow): boolean => a.hooks.length > 0;

// Back up a config file to <file>.node9-heal-bak before setup rewrites it. Distinct
// suffix so it never clobbers the reconciler's .node9-bak. Best-effort — a backup
// failure must not block the heal.
function backupForHeal(file: string): void {
  try {
    if (file && fs.existsSync(file)) fs.copyFileSync(file, `${file}.node9-heal-bak`);
  } catch {
    /* ignore */
  }
}

/**
 * Core of `node9 heal`. Re-installs node9's hooks for governed-but-unwired agents
 * (backup-first). Returns the labels it healed (for tests / callers). Exported so
 * the logic is unit-testable without spawning the CLI.
 */
export async function runHeal(name?: string): Promise<{ healed: string[] }> {
  console.log(chalk.cyan.bold('\n🩹 Node9 Heal\n'));

  const baseline = loadHookBaseline();
  const wiring = getAgentWiring();

  // Heal candidates: agents node9 GOVERNS (in the baseline) that have a hook
  // surface, are installed, but are no longer wired. An installed-but-never-
  // governed agent is `node9 init` territory — heal never surprise-wires something
  // node9 didn't protect before.
  let candidates = wiring.filter(
    (a) => baseline[a.id] && a.installed && hasHookSurface(a) && a.wireState !== 'wired'
  );

  if (name) {
    const wanted = name.toLowerCase();
    candidates = candidates.filter(
      (a) => a.id.toLowerCase() === wanted || a.label.toLowerCase() === wanted
    );
    if (candidates.length === 0) {
      console.error(
        chalk.red(
          `Nothing to heal for "${name}" — it's either healthy, not governed by node9, or not installed.`
        )
      );
      process.exitCode = 1;
      return { healed: [] };
    }
  }

  if (candidates.length === 0) {
    console.log(chalk.green('  ✓ All governed agents are healthy — nothing to heal.'));
    // Hint about installed-but-never-governed agents (init territory, not heal).
    const wireable = wiring.filter(
      (a) => !baseline[a.id] && a.installed && hasHookSurface(a) && a.wireState !== 'wired'
    );
    if (wireable.length > 0) {
      console.log(
        chalk.gray(`  To govern ${wireable.map((a) => a.label).join(', ')}, run: `) +
          chalk.bold('node9 init')
      );
    }
    return { healed: [] };
  }

  const notified = loadNotified();
  let notifiedChanged = false;
  const healed: string[] = [];
  for (const a of candidates) {
    try {
      backupForHeal(a.settingsPath); // backup-first (setup's writeJson does not)
      await setupAgent(a.id); // re-adds hooks (idempotent) + re-records baseline
      healed.push(a.label);
      if (notified.delete(a.id)) notifiedChanged = true; // re-arm the daemon's nudge
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`  ✗ failed to heal ${a.label}: ${msg}`));
      process.exitCode = 1;
    }
  }
  if (notifiedChanged) saveNotified(notified);

  if (healed.length > 0) {
    console.log(chalk.bold(`\n✓ Re-installed node9 hooks for ${healed.join(', ')}.`));
    console.log(chalk.gray(`  Restart ${healed.join(', ')} to activate the restored protection.`));
  }
  return { healed };
}

export function registerHealCommand(program: Command): void {
  program
    .command('heal [name]')
    .description(
      "Re-install node9's hooks for a governed agent whose hooks were wiped " +
        '(e.g. by an agent update). Backup-first; restart the agent afterward.'
    )
    .action(async (name: string | undefined) => {
      await runHeal(name);
    });
}

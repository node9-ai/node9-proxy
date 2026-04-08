// src/cli/commands/shield.ts
// Shield management commands and config show.
// Registered as `node9 shield` and `node9 config show` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import {
  getShield,
  listShields,
  readActiveShields,
  writeActiveShields,
  readShieldOverrides,
  writeShieldOverride,
  clearShieldOverride,
  resolveShieldName,
  resolveShieldRule,
  isShieldVerdict,
  installShield,
} from '../../shields';
import { appendConfigAudit } from '../../audit';
import { getConfig } from '../../config';
import { httpsFetch } from '../../utils/https-fetch';

const COMMUNITY_INDEX_URL =
  'https://raw.githubusercontent.com/node9ai/node9-proxy/main/shields/community/index.json';

interface CommunityEntry {
  name: string;
  description: string;
  author: string;
  url: string;
}

export function registerShieldCommand(program: Command): void {
  // ---------------------------------------------------------------------------
  // node9 shield — manage pre-packaged security rule templates
  // ---------------------------------------------------------------------------
  // Shields are applied dynamically at getConfig() load time by reading
  // ~/.node9/shields.json and merging the catalog rules into the runtime policy.
  // enable/disable only update shields.json — config.json is never touched.

  const shieldCmd = program
    .command('shield')
    .description('Manage pre-packaged security shield templates');

  shieldCmd
    .command('enable <service>')
    .description('Enable a security shield for a specific service')
    .action((service: string) => {
      const name = resolveShieldName(service);
      if (!name) {
        console.error(chalk.red(`\n❌ Unknown shield: "${service}"\n`));
        console.log(`Run ${chalk.cyan('node9 shield list')} to see available shields.\n`);
        process.exit(1);
      }
      const shield = getShield(name!)!;

      const active = readActiveShields();
      if (active.includes(name!)) {
        console.log(chalk.yellow(`\nℹ️  Shield "${name}" is already active.\n`));
        return;
      }
      writeActiveShields([...active, name!]);

      console.log(chalk.green(`\n🛡️  Shield "${name}" enabled.`));
      console.log(chalk.gray(`   ${shield.smartRules.length} smart rules now active.`));
      if (shield.dangerousWords.length > 0)
        console.log(chalk.gray(`   ${shield.dangerousWords.length} dangerous words now active.`));
      if (name === 'filesystem') {
        console.log(
          chalk.yellow(
            `\n   ⚠️  Note: filesystem rules cover common rm -rf patterns but not all variants.\n` +
              `      Tools like unlink, find -delete, or language-level file ops are not intercepted.`
          )
        );
      }
      console.log('');
    });

  shieldCmd
    .command('disable <service>')
    .description('Disable a security shield')
    .action((service: string) => {
      const name = resolveShieldName(service);
      if (!name) {
        console.error(chalk.red(`\n❌ Unknown shield: "${service}"\n`));
        console.log(`Run ${chalk.cyan('node9 shield list')} to see available shields.\n`);
        process.exit(1);
      }

      const active = readActiveShields();
      if (!active.includes(name!)) {
        console.log(chalk.yellow(`\nℹ️  Shield "${name}" is not active.\n`));
        return;
      }

      writeActiveShields(active.filter((s) => s !== name));

      console.log(chalk.green(`\n🛡️  Shield "${name}" disabled.\n`));
    });

  shieldCmd
    .command('list')
    .description('Show available shields (add --community to browse the marketplace)')
    .option('--community', 'List shields available from the community marketplace')
    .action((opts: { community?: boolean }) => {
      if (opts.community) {
        console.log(chalk.bold('\n🛡️  Community Shield Marketplace\n'));
        console.log(chalk.gray('  Fetching index…\n'));
        httpsFetch(COMMUNITY_INDEX_URL)
          .then((body) => {
            const entries = JSON.parse(body) as CommunityEntry[];
            const installed = new Set(listShields().map((s) => s.name));
            for (const e of entries) {
              const tag = installed.has(e.name)
                ? chalk.green('installed')
                : chalk.gray('available');
              console.log(
                `  ${tag}  ${chalk.cyan(e.name.padEnd(12))} ${e.description}  ${chalk.gray(`by ${e.author}`)}`
              );
            }
            console.log('');
            console.log(
              chalk.gray(`  Install a shield: ${chalk.cyan('node9 shield install <name>')}\n`)
            );
          })
          .catch((err: unknown) => {
            console.error(chalk.red(`\n❌ Could not fetch community index: ${String(err)}\n`));
            process.exit(1);
          });
        return;
      }

      const active = new Set(readActiveShields());
      console.log(chalk.bold('\n🛡️  Available Shields\n'));
      for (const shield of listShields()) {
        const status = active.has(shield.name)
          ? chalk.green('● enabled')
          : chalk.gray('○ disabled');
        console.log(`  ${status}  ${chalk.cyan(shield.name.padEnd(12))} ${shield.description}`);
        if (shield.aliases.length > 0)
          console.log(chalk.gray(`              aliases: ${shield.aliases.join(', ')}`));
      }
      console.log('');
      console.log(
        chalk.gray(`  Browse community shields: ${chalk.cyan('node9 shield list --community')}\n`)
      );
    });

  shieldCmd
    .command('status')
    .description('Show active shields and their individual rules with verdicts')
    .action(() => {
      const active = readActiveShields();
      if (active.length === 0) {
        console.error(chalk.yellow('\nℹ️  No shields are active.\n'));
        console.error(`Run ${chalk.cyan('node9 shield list')} to see available shields.\n`);
        return;
      }
      const overrides = readShieldOverrides();
      console.error(chalk.bold('\n🛡️  Active Shields\n'));
      for (const name of active) {
        const shield = getShield(name);
        if (!shield) continue;
        console.error(`  ${chalk.green('●')} ${chalk.cyan(name)} — ${shield.description}`);
        const ruleOverrides = overrides[name] ?? {};
        for (const rule of shield.smartRules) {
          const shortName = rule.name ? rule.name.replace(`shield:${name}:`, '') : '(unnamed)';
          const overrideVerdict = rule.name ? ruleOverrides[rule.name] : undefined;
          const effectiveVerdict = overrideVerdict ?? rule.verdict;
          const verdictLabel =
            effectiveVerdict === 'block'
              ? chalk.red('block ')
              : effectiveVerdict === 'review'
                ? chalk.yellow('review')
                : chalk.green('allow ');
          const overrideNote = overrideVerdict
            ? chalk.gray(` ← overridden (was: ${rule.verdict})`)
            : '';
          console.error(
            `    ${verdictLabel}  ${shortName.padEnd(24)} ${chalk.gray(rule.reason ?? '')}${overrideNote}`
          );
        }
        if (shield.dangerousWords.length > 0) {
          console.error(chalk.gray(`    words: ${shield.dangerousWords.join(', ')}`));
        }
        console.error('');
      }
      if (Object.keys(overrides).length > 0) {
        console.error(
          chalk.gray(
            `  Tip: run ${chalk.cyan('node9 shield unset <shield> <rule>')} to remove an override.\n`
          )
        );
      }
    });

  shieldCmd
    .command('set <service> <rule> <verdict>')
    .description('Override the verdict for a specific shield rule (block, review, or allow)')
    .option('--force', 'Required when setting verdict to allow (silences a block rule)')
    .action((service: string, rule: string, verdict: string, opts: { force?: boolean }) => {
      const name = resolveShieldName(service);
      if (!name) {
        console.error(chalk.red(`\n❌ Unknown shield: "${service}"\n`));
        console.error(`Run ${chalk.cyan('node9 shield list')} to see available shields.\n`);
        process.exit(1);
      }
      if (!readActiveShields().includes(name)) {
        console.error(chalk.red(`\n❌ Shield "${name}" is not active. Enable it first:\n`));
        console.error(`  ${chalk.cyan(`node9 shield enable ${name}`)}\n`);
        process.exit(1);
      }
      if (!isShieldVerdict(verdict)) {
        console.error(
          chalk.red(`\n❌ Invalid verdict "${verdict}". Use: block, review, or allow\n`)
        );
        process.exit(1);
      }
      if (verdict === 'allow' && !opts.force) {
        console.error(
          chalk.red(`\n⚠️  Setting a verdict to "allow" silences the rule entirely.\n`) +
            chalk.yellow(
              `   This disables a shield protection. If you are sure, re-run with --force:\n`
            ) +
            chalk.cyan(`\n   node9 shield set ${service} ${rule} allow --force\n`)
        );
        process.exit(1);
      }
      const ruleName = resolveShieldRule(name, rule);
      if (!ruleName) {
        const shield = getShield(name);
        console.error(chalk.red(`\n❌ Unknown rule "${rule}" for shield "${name}".\n`));
        console.error('  Available rules:');
        for (const r of shield?.smartRules ?? []) {
          const short = r.name ? r.name.replace(`shield:${name}:`, '') : '';
          console.error(`    ${chalk.cyan(short)}`);
        }
        console.error('');
        process.exit(1);
      }
      writeShieldOverride(name, ruleName, verdict);
      if (verdict === 'allow') {
        // Security-relevant mutation: log to audit trail so silenced rules are visible
        appendConfigAudit({ event: 'shield-override-allow', shield: name, rule: ruleName });
      }
      const shortName = ruleName.replace(`shield:${name}:`, '');
      const verdictLabel =
        verdict === 'block'
          ? chalk.red('block')
          : verdict === 'review'
            ? chalk.yellow('review')
            : chalk.green('allow');
      if (verdict === 'allow') {
        console.error(
          chalk.yellow(`\n⚠️  ${name}/${shortName} → ${verdictLabel}`) +
            chalk.gray(' (rule silenced — use `node9 shield unset` to restore)\n')
        );
      } else {
        console.error(chalk.green(`\n✅  ${name}/${shortName} → ${verdictLabel}\n`));
      }
      console.error(
        chalk.gray(`   Run ${chalk.cyan('node9 shield status')} to see all active rules.\n`)
      );
    });

  shieldCmd
    .command('unset <service> <rule>')
    .description('Remove a verdict override, restoring the shield default')
    .action((service: string, rule: string) => {
      const name = resolveShieldName(service);
      if (!name) {
        console.error(chalk.red(`\n❌ Unknown shield: "${service}"\n`));
        process.exit(1);
      }
      const ruleName = resolveShieldRule(name, rule);
      if (!ruleName) {
        console.error(chalk.red(`\n❌ Unknown rule "${rule}" for shield "${name}".\n`));
        process.exit(1);
      }
      clearShieldOverride(name, ruleName);
      const shortName = ruleName.replace(`shield:${name}:`, '');
      console.error(
        chalk.green(`\n✅  Override removed — ${name}/${shortName} restored to default.\n`)
      );
    });

  shieldCmd
    .command('install <name>')
    .description('Install a shield from the community marketplace into ~/.node9/shields/')
    .action((name: string) => {
      if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        console.error(
          chalk.red(
            `\n❌ Invalid shield name "${name}": only alphanumeric characters, hyphens, and underscores are allowed\n`
          )
        );
        process.exit(1);
      }
      console.log(chalk.bold(`\n🛡️  Installing shield "${name}"…\n`));
      httpsFetch(COMMUNITY_INDEX_URL)
        .then((indexBody) => {
          const entries = JSON.parse(indexBody) as CommunityEntry[];
          const entry = entries.find((e) => e.name === name);
          if (!entry) {
            const names = entries.map((e) => chalk.cyan(e.name)).join(', ');
            console.error(
              chalk.red(`❌ Shield "${name}" not found in the community marketplace.\n`)
            );
            console.error(`  Available: ${names}\n`);
            process.exit(1);
          }
          return httpsFetch(entry.url);
        })
        .then((shieldBody) => {
          const shieldJson = JSON.parse(shieldBody) as unknown;
          installShield(name, shieldJson);
          console.log(
            chalk.green(`✅  Shield "${name}" installed to ~/.node9/shields/${name}.json`)
          );
          console.log(
            chalk.gray(`   Activate it with: ${chalk.cyan(`node9 shield enable ${name}`)}\n`)
          );
          // Log install to audit trail
          appendConfigAudit({ event: 'shield-install', shield: name });
        })
        .catch((err: unknown) => {
          console.error(chalk.red(`\n❌ Install failed: ${String(err)}\n`));
          process.exit(1);
        });
    });
}

export function registerConfigShowCommand(program: Command): void {
  program
    .command('config show')
    .description(
      'Show the full effective runtime configuration including shields and advisory rules'
    )
    .action(() => {
      const config = getConfig();
      const active = readActiveShields();
      const overrides = readShieldOverrides();

      console.error(chalk.bold('\n🔍  Node9 Effective Configuration\n'));

      // ── Mode ────────────────────────────────────────────────────────────────
      const modeLabel =
        config.settings.mode === 'audit'
          ? chalk.blue('audit')
          : config.settings.mode === 'strict'
            ? chalk.red('strict')
            : chalk.white('standard');
      console.error(`  Mode: ${modeLabel}\n`);

      // ── Active Shields ───────────────────────────────────────────────────────
      if (active.length > 0) {
        console.error(chalk.bold('  ── Active Shields ─────────────────────────────────────────'));
        for (const name of active) {
          const shield = getShield(name);
          if (!shield) continue;
          const ruleOverrides = overrides[name] ?? {};
          console.error(`\n  ${chalk.green('●')} ${chalk.cyan(name)}`);
          for (const rule of shield.smartRules) {
            const shortName = rule.name ? rule.name.replace(`shield:${name}:`, '') : '(unnamed)';
            const overrideVerdict = rule.name ? ruleOverrides[rule.name] : undefined;
            const effectiveVerdict = overrideVerdict ?? rule.verdict;
            const vLabel =
              effectiveVerdict === 'block'
                ? chalk.red('block ')
                : effectiveVerdict === 'review'
                  ? chalk.yellow('review')
                  : chalk.green('allow ');
            const note = overrideVerdict ? chalk.gray(` ← overridden`) : '';
            console.error(`    ${vLabel}  ${shortName}${note}`);
          }
        }
        console.error('');
      } else {
        console.error(chalk.gray('  No shields active. Run `node9 shield list` to see options.\n'));
      }

      // ── Built-in Rules ───────────────────────────────────────────────────────
      console.error(chalk.bold('  ── Built-in Rules (always on) ────────────────────────────'));
      for (const rule of config.policy.smartRules) {
        // Skip shield rules (already shown above) and advisory rules (shown below)
        const isShieldRule = rule.name?.startsWith('shield:');
        const isAdvisory = [
          'review-rm',
          'allow-rm-safe-paths',
          'review-drop-table-sql',
          'review-truncate-sql',
          'review-drop-column-sql',
        ].includes(rule.name ?? '');
        if (isShieldRule || isAdvisory) continue;
        const vLabel =
          rule.verdict === 'block'
            ? chalk.red('block ')
            : rule.verdict === 'review'
              ? chalk.yellow('review')
              : chalk.green('allow ');
        console.error(`    ${vLabel}  ${chalk.gray(rule.name ?? rule.tool)}`);
      }
      console.error('');

      // ── Advisory Rules ───────────────────────────────────────────────────────
      console.error(chalk.bold('  ── Safe by Default (advisory, overridable) ────────────────'));
      const advisoryNames = new Set([
        'review-rm',
        'allow-rm-safe-paths',
        'review-drop-table-sql',
        'review-truncate-sql',
        'review-drop-column-sql',
      ]);
      for (const rule of config.policy.smartRules) {
        if (!advisoryNames.has(rule.name ?? '')) continue;
        const vLabel =
          rule.verdict === 'block'
            ? chalk.red('block ')
            : rule.verdict === 'review'
              ? chalk.yellow('review')
              : chalk.green('allow ');
        console.error(`    ${vLabel}  ${chalk.gray(rule.name ?? rule.tool)}`);
      }
      console.error('');

      // ── Dangerous Words ──────────────────────────────────────────────────────
      console.error(chalk.bold('  ── Dangerous Words ────────────────────────────────────────'));
      console.error(`    ${chalk.gray(config.policy.dangerousWords.join(', '))}\n`);
    });
}

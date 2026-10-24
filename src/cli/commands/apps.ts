// src/cli/commands/apps.ts
// `node9 apps`: the apps node9 found on this machine and what protects each
// (node9Firewall#390, phase 2).
//
//   node9 apps                         list what was found, on/off, how
//   node9 apps scan                    look again now
//   node9 apps <app> on|off            turn an app's protection on or off
//   node9 apps <app> <action> <verdict>
//                                      e.g. node9 apps stripe refunds allow
//   node9 apps link <server> <app>     a server is that app (acme-billing stripe)
//   node9 apps unlink <server>
import type { Command } from 'commander';
import chalk from 'chalk';
import { APP_BY_SLUG, APP_CATALOG, ACTIONS_BY_APP } from '../../apps/catalog';
import { detectApps } from '../../apps/detect';
import { applyDetection, readAppsFile, recordUserDecision, setLink } from '../../apps/state';
import {
  readActiveShields,
  writeActiveShields,
  resolveShieldRule,
  writeShieldOverride,
} from '../../shields';
import { cliGuardPolicyWrite, isKeyedForPolicy } from '../../config/keyed-guard';
import { getConfig } from '../../config';
import { appendConfigAudit } from '../../audit';
import { isShieldVerdict } from '@node9/policy-engine';

const SIGNAL_LABEL: Record<string, string> = {
  'mcp-server': 'MCP server',
  command: 'command',
  package: 'package',
  'env-name': 'env name',
};

function fail(msg: string): void {
  console.error(chalk.red(`\n❌ ${msg}\n`));
  process.exitCode = 1;
}

function scanNow(): void {
  const found = detectApps();
  const res = applyDetection(found, { managed: isKeyedForPolicy() });
  for (const slug of res.turnedOn)
    console.log(chalk.green(`🛡️  Found ${APP_BY_SLUG.get(slug)?.label}: protected.`));
  for (const slug of res.recordedOnly)
    console.log(
      chalk.yellow(
        `ℹ️  Found ${APP_BY_SLUG.get(slug)?.label}. This machine follows the workspace: turn it on in the dashboard.`
      )
    );
}

function list(): void {
  const file = readAppsFile();
  // The shields the config applied: the workspace's on a keyed machine.
  const cfg = getConfig();
  const active = new Set(cfg.policy.appliedShields ?? readActiveShields());
  const known = (slug: string) => Object.prototype.hasOwnProperty.call(file.apps, slug);
  const rows = APP_CATALOG.filter((a) => known(a.slug) || active.has(a.shield));
  console.log('');
  if (rows.length === 0) {
    console.log(
      chalk.gray('  No apps found yet. node9 looks at what your agents use; run node9 apps scan.')
    );
    console.log('');
    return;
  }
  for (const app of rows) {
    const rec = known(app.slug) ? file.apps[app.slug] : undefined;
    const on = active.has(app.shield);
    const state = on
      ? chalk.green('protected')
      : rec?.by === 'user'
        ? chalk.yellow('off')
        : chalk.yellow('not protected');
    const how = rec?.signals.length
      ? rec.signals
          .slice(0, 3)
          .map((s) => `${SIGNAL_LABEL[s.kind] ?? s.kind} ${s.value}`)
          .join(', ')
      : 'turned on by hand';
    console.log(`  ${chalk.bold(app.label.padEnd(12))} ${state.padEnd(20)} ${chalk.gray(how)}`);
  }
  const links = Object.entries(file.links);
  if (links.length > 0) {
    console.log('');
    for (const [server, slug] of links)
      console.log(chalk.gray(`  server ${server} is ${APP_BY_SLUG.get(slug)?.label ?? slug}`));
  }
  console.log('');
  console.log(chalk.gray('  Turn one off: node9 apps <app> off'));
  console.log('');
}

function setState(slug: string, state: 'on' | 'off'): void {
  const app = APP_BY_SLUG.get(slug);
  if (!app)
    return fail(`Unknown app "${slug}". Known: ${APP_CATALOG.map((a) => a.slug).join(', ')}`);
  if (!cliGuardPolicyWrite(`apps ${slug} ${state}`)) return;
  const active = readActiveShields();
  if (state === 'on' && !active.includes(app.shield)) writeActiveShields([...active, app.shield]);
  if (state === 'off' && active.includes(app.shield))
    writeActiveShields(active.filter((s) => s !== app.shield));
  recordUserDecision(slug, state);
  appendConfigAudit({
    event: state === 'on' ? 'app-protected' : 'app-unprotected',
    app: slug,
    by: 'user',
  });
  console.log(
    state === 'on'
      ? chalk.green(`\n🛡️  ${app.label}: protected.\n`)
      : chalk.yellow(`\n${app.label}: off on this machine. node9 will not turn it back on.\n`)
  );
}

function setAction(slug: string, action: string, verdict: string, force: boolean): void {
  const app = APP_BY_SLUG.get(slug);
  if (!app) return fail(`Unknown app "${slug}".`);
  const actions = ACTIONS_BY_APP[slug];
  const rule = actions?.[action.toLowerCase()];
  if (!actions || !rule)
    return fail(
      actions
        ? `Unknown action "${action}" for ${app.label}. Actions: ${Object.keys(actions).join(', ')}`
        : `${app.label} has no per-action settings; use node9 shield set ${app.shield} <rule> <verdict>.`
    );
  if (!isShieldVerdict(verdict))
    return fail(`Invalid verdict "${verdict}". Use: block, review, or allow`);
  if (!cliGuardPolicyWrite(`apps ${slug} ${action} ${verdict}`)) return;
  if (!readActiveShields().includes(app.shield))
    return fail(`${app.label} is off. Turn it on first: node9 apps ${slug} on`);
  if (verdict === 'allow' && !force)
    return fail(
      `"allow" stops node9 asking about ${action} in ${app.label}. If you are sure: node9 apps ${slug} ${action} allow --force`
    );
  const ruleName = resolveShieldRule(app.shield, rule);
  if (!ruleName) return fail(`No rule for ${action} in ${app.label}.`);
  writeShieldOverride(app.shield, ruleName, verdict);
  appendConfigAudit({ event: 'app-action-set', app: slug, action, rule: ruleName, verdict });
  console.log(chalk.green(`\n${app.label} ${action}: ${verdict}.\n`));
}

export function registerAppsCommand(program: Command): void {
  program
    .command('apps [args...]')
    .description('The apps node9 found on this machine and what protects each')
    .option('--force', 'Required to set an action to allow')
    .action((args: string[], opts: { force?: boolean }) => {
      const [a, b, c] = args;
      if (!a) return list();
      if (a === 'scan') {
        scanNow();
        return list();
      }
      if (a === 'link') {
        if (!b || !c) return fail('Usage: node9 apps link <server> <app>');
        if (!APP_BY_SLUG.has(c)) return fail(`Unknown app "${c}".`);
        if (!cliGuardPolicyWrite(`apps link ${b}`)) return;
        setLink(b, c);
        appendConfigAudit({ event: 'app-link', server: b, app: c });
        const linked = APP_BY_SLUG.get(c)!;
        console.log(chalk.green(`\nServer ${b} is ${linked.label} now.\n`));
        // The gate honours a link only while the app is protected; until then
        // the general checks keep the server.
        if (!readActiveShields().includes(linked.shield))
          console.log(
            chalk.yellow(
              `${linked.label} is off, so node9 still asks about ${b} through the general checks. Turn it on: node9 apps ${c} on\n`
            )
          );
        return;
      }
      if (a === 'unlink') {
        if (!b) return fail('Usage: node9 apps unlink <server>');
        if (!cliGuardPolicyWrite(`apps unlink ${b}`)) return;
        setLink(b, null);
        appendConfigAudit({ event: 'app-unlink', server: b });
        console.log(chalk.green(`\nServer ${b} is no longer linked.\n`));
        return;
      }
      if (b === 'on' || b === 'off') return setState(a, b);
      if (b && c) return setAction(a, b, c, !!opts.force);
      return fail(
        'Usage: node9 apps [scan | <app> on|off | <app> <action> <verdict> | link <server> <app>]'
      );
    });
}

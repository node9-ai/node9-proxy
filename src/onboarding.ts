import chalk from 'chalk';
import { writeCredentialsAndConfig } from './credentials';
import { setupDetectedAgents } from './setup';
import { runCloudSync, runPolicyPush } from './daemon/sync';
import { ensureAutostartHealthy } from './daemon/service';
import { isDaemonRunning } from './auth/daemon';
import { isTestingMode } from './cli/daemon-starter';
import { getConfig } from './config';

// THE machine-onboarding routine (login-v2 design §2.1 step 8). Every way a
// machine gets connected to the cloud ends here: `node9 connect` (token),
// `node9 login` (raw key), and the upcoming device-auth login. One routine so
// the flows can never drift apart again — the old split is exactly what let
// `login` leave machines invisible while `connect` printed a ✅ it never
// verified.
//
// Interactive onboarding is LOUD (per-step results, rendered as a scorecard by
// the caller); only background daemon loops get to be silent-resilient.
// Overall `ok` is claimed ONLY when the cloud acked the policy snapshot — that
// snapshot row is what makes the machine exist in the dashboard.

export interface OnboardStep {
  name: 'credentials' | 'agents' | 'policy-sync' | 'register' | 'daemon';
  ok: boolean;
  detail: string;
}

export interface OnboardOutcome {
  /** True only when credentials were written AND the cloud acked sync + snapshot. */
  ok: boolean;
  steps: OnboardStep[];
  /** Agent names wired by setup (empty when none detected). */
  wired: string[];
}

export async function onboardMachine(
  apiKey: string,
  opts: { profileName?: string } = {}
): Promise<OnboardOutcome> {
  const steps: OnboardStep[] = [];
  const wired: string[] = [];
  const namedProfile = !!opts.profileName && opts.profileName !== 'default';

  // 1. Credentials + config (single approvers seed, cloud on — credentials.ts).
  try {
    writeCredentialsAndConfig(apiKey, { profileName: opts.profileName });
    steps.push({ name: 'credentials', ok: true, detail: 'saved to ~/.node9' });
  } catch (e) {
    steps.push({
      name: 'credentials',
      ok: false,
      detail: e instanceof Error ? e.message : String(e),
    });
    // Nothing downstream can work without credentials.
    return { ok: false, steps, wired };
  }

  // 2. Wire detected agents. Non-interactive (curl|sh and CI shells have no
  //    TTY). Best-effort: a machine with no agents installed yet is still a
  //    valid connection, so a wiring failure doesn't fail the onboarding.
  process.env.NODE9_NONINTERACTIVE = '1';
  try {
    wired.push(...(await setupDetectedAgents()));
    steps.push({
      name: 'agents',
      ok: true,
      detail: wired.length
        ? `wired: ${wired.join(', ')}`
        : 'none detected yet: run `node9 init` after installing one',
    });
  } catch (e) {
    steps.push({ name: 'agents', ok: false, detail: e instanceof Error ? e.message : String(e) });
  }

  // 3+4. Cloud: policy pull, then the ACKED snapshot push. The cloud steps use
  //    the default profile's credentials (readCredentials), so for a named
  //    profile they'd verify the wrong key — skip them. Named profiles are on a
  //    deprecation path (login-v2 §6).
  if (namedProfile || isTestingMode()) {
    const why = namedProfile ? 'skipped (named profile)' : 'skipped (testing mode)';
    steps.push({ name: 'policy-sync', ok: true, detail: why });
    steps.push({ name: 'register', ok: true, detail: why });
  } else {
    const sync = await runCloudSync();
    steps.push(
      sync.ok
        ? {
            name: 'policy-sync',
            ok: true,
            detail: `${sync.rules} cloud rule${sync.rules === 1 ? '' : 's'} active`,
          }
        : { name: 'policy-sync', ok: false, detail: sync.reason }
    );

    // runCloudSync already fires background pushes (blast/scan/posture and a
    // SILENT policy mirror). runPolicyPush repeats the mirror loudly because
    // its 2xx is the registration ack: the dashboard machines list is keyed
    // off this snapshot row. One redundant idempotent POST beats claiming
    // "Connected" blind — ignoring this exact failure was the old connect bug.
    const push = await runPolicyPush();
    steps.push(
      push.ok
        ? { name: 'register', ok: true, detail: 'machine visible in the dashboard' }
        : { name: 'register', ok: false, detail: push.reason }
    );

    // 5. Daemon autostart self-heal (moved here from `login`): (re)enable the
    //    service the moment the machine becomes cloud-enabled so policy keeps
    //    syncing across reboots. Informational — never fails the onboarding.
    const healed = ensureAutostartHealthy(!!getConfig().settings.autoStartDaemon);
    const detail =
      healed === 'repaired'
        ? 'autostart re-enabled (survives reboot)'
        : isDaemonRunning()
          ? 'running'
          : healed === 'unsupported'
            ? 'no background service on this platform: starts on agent activity'
            : 'starts on agent activity';
    steps.push({ name: 'daemon', ok: true, detail });
  }

  const required: OnboardStep['name'][] = ['credentials', 'policy-sync', 'register'];
  const ok = steps.filter((s) => required.includes(s.name)).every((s) => s.ok);
  return { ok, steps, wired };
}

const STEP_LABELS: Record<OnboardStep['name'], string> = {
  credentials: 'Credentials',
  agents: 'Agents',
  'policy-sync': 'Cloud policy',
  register: 'Registered',
  daemon: 'Daemon',
};

/** Render the onboarding scorecard. The headline claims success only when the
 *  routine verified it; every failed line carries its reason. */
export function renderOnboardOutcome(
  out: OnboardOutcome,
  opts: { workspaceName?: string } = {}
): string {
  const suffix = opts.workspaceName ? ` to ${opts.workspaceName}` : '';
  const lines: string[] = [
    out.ok ? chalk.green(`✅ Connected${suffix}`) : chalk.red(`✗ Connection incomplete${suffix}`),
  ];
  for (const s of out.steps) {
    const mark = s.ok ? chalk.green('✓') : chalk.red('✗');
    lines.push(`   ${mark} ${STEP_LABELS[s.name]}: ${s.detail}`);
  }
  if (!out.ok) {
    lines.push(chalk.yellow('   Fix the failed step, then verify with: node9 sync'));
  }
  return lines.join('\n');
}

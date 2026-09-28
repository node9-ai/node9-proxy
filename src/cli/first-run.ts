import fs from 'fs';
import os from 'os';
import path from 'path';
import { getCredentials } from '../config';
import { getAgentWiring } from '../agent-wiring';
import { loginViaBrowser } from '../auth/browser-login';
import { renderOnboardOutcome } from '../onboarding';
import { disconnectMachine } from './commands/logout';
import { runLocalSetup, renderSummary } from './local-setup';
import { isCI, isInteractive, isPromptCancellation } from './interactive';
import { safeMessage } from '../utils/safe-text';

export interface FirstRunEnv {
  stdinTTY: boolean;
  stdoutTTY: boolean;
  ci: boolean;
  hasConfig: boolean;
  hasCredentials: boolean;
}
export function readFirstRunEnv(): FirstRunEnv {
  return {
    stdinTTY: !!process.stdin.isTTY,
    stdoutTTY: !!process.stdout.isTTY,
    ci: isCI() || process.env.NODE9_NONINTERACTIVE === '1',
    hasConfig: fs.existsSync(path.join(os.homedir(), '.node9/config.json')),
    // Any stored profile means this is not a never-configured machine. Treat
    // malformed credential files conservatively and leave repair to explicit setup.
    hasCredentials:
      !!getCredentials() || fs.existsSync(path.join(os.homedir(), '.node9/credentials.json')),
  };
}
export function shouldOfferFirstRun(env: FirstRunEnv): boolean {
  return env.stdinTTY && env.stdoutTTY && !env.ci && !env.hasConfig && !env.hasCredentials;
}
export function unwiredAgentHint(): string {
  const unwired = getAgentWiring().filter((a) => a.installed && !a.isProtected);
  return unwired.length
    ? `\nDetected agents not configured: ${unwired.map((a) => a.label).join(', ')}. Run node9 setup.\n`
    : '';
}
export async function runSetupWizard(opts: { version: string }): Promise<void> {
  if (!isInteractive()) {
    console.log('Interactive setup needs a terminal. For scripts, run: node9 init --recommended');
    return;
  }
  try {
    const { select, confirm } = await import('@inquirer/prompts');
    const choice = await select({
      message: 'How would you like to set up Node9?',
      choices: [
        {
          name: 'Connect to dashboard',
          value: 'dashboard',
          description: 'Central policy, approvals, and cloud audit.',
        },
        {
          name: 'Protect this machine locally',
          value: 'local',
          description: 'Local protection without an account.',
        },
      ],
    });
    if (choice === 'dashboard') {
      // Device onboarding writes the default profile. Env keys and named profiles
      // would make sync operate under a different identity than the browser login.
      if (
        process.env.NODE9_API_KEY ||
        (process.env.NODE9_PROFILE && process.env.NODE9_PROFILE !== 'default')
      ) {
        console.log(
          'Unset NODE9_API_KEY and NODE9_PROFILE before browser setup. Your current connection was not changed.'
        );
        process.exitCode = 1;
        return;
      }
      let result = await loginViaBrowser({ cliVersion: opts.version });
      while (result.kind === 'partial') {
        console.log(renderOnboardOutcome(result.outcome, { workspaceName: result.workspaceName }));
        const action = await select({
          message: 'Connection is incomplete. What next?',
          choices: [
            { name: 'Retry', value: 'retry' },
            { name: 'Disconnect and continue locally', value: 'local' },
            { name: 'Keep connected, fix later', value: 'keep' },
          ],
        });
        if (action === 'retry') {
          result = await result.retry();
          continue;
        }
        if (action === 'keep') {
          console.log('Connection kept. Run node9 sync to retry.');
          return;
        }
        const disconnected = await disconnectMachine({
          resetCloudApprover: true,
          profile: 'default',
        });
        if (disconnected.outcome === 'unreachable') {
          console.log(
            `Disconnected locally. Cloud revocation was not confirmed: ${safeMessage(disconnected.detail)}. Disconnect this machine in the dashboard.`
          );
        }
        console.log(renderSummary(await runLocalSetup({ interactive: true })));
        return;
      }
      if (result.kind === 'connected') {
        console.log(renderOnboardOutcome(result.outcome, { workspaceName: result.workspaceName }));
        return;
      }
      console.log(safeMessage(result.reason));
      if (getCredentials()) {
        console.log('Your existing connection was kept. Run node9 setup to manage it.');
        return;
      }
      if (!(await confirm({ message: 'Continue with local protection?', default: true }))) return;
    }
    if (getCredentials()) {
      console.log(
        'This machine already has a connection. It will be kept; use node9 logout to disconnect. Workspace-managed policy is read-only here.'
      );
    }
    console.log(renderSummary(await runLocalSetup({ interactive: true })));
  } catch (error) {
    if (!isPromptCancellation(error)) throw error;
    console.log('Setup cancelled. Completed steps were kept; run node9 setup to continue.');
    process.exitCode = 130;
  }
}

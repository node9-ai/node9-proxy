import fs from 'fs';
import os from 'os';
import path from 'path';
import { runDeviceLogin } from './device-login';
import { onboardMachine, type OnboardOutcome } from '../onboarding';
import { _resetConfigCache } from '../config';
import { safeMessage } from '../utils/safe-text';

export type BrowserLoginOutcome =
  | { kind: 'cancelled'; reason: string }
  | { kind: 'failed'; reason: string }
  | { kind: 'connected'; workspaceName: string; outcome: OnboardOutcome }
  | {
      kind: 'partial';
      workspaceName: string;
      outcome: OnboardOutcome;
      retry: () => Promise<BrowserLoginOutcome>;
    };

/** Only the key from THIS attempt can establish partial onboarding. A previous
 * login left on disk after device-auth cancellation is never a new partial login. */
function attemptKeySaved(apiKey: string): boolean {
  try {
    const all = JSON.parse(
      fs.readFileSync(path.join(os.homedir(), '.node9/credentials.json'), 'utf8')
    );
    return all.default?.apiKey === apiKey;
  } catch {
    return false;
  }
}
export async function loginViaBrowser(opts: {
  apiUrl?: string;
  noBrowser?: boolean;
  cliVersion: string;
}): Promise<BrowserLoginOutcome> {
  const res = await runDeviceLogin(opts);
  if (!res.ok) return { kind: res.cancelled ? 'cancelled' : 'failed', reason: res.reason };
  const finish = async (): Promise<BrowserLoginOutcome> => {
    let outcome: OnboardOutcome;
    const previous = process.env.NODE9_NONINTERACTIVE;
    try {
      outcome = await onboardMachine(res.apiKey);
    } catch (error) {
      outcome = {
        ok: false,
        wired: [],
        steps: [{ name: 'policy-sync', ok: false, detail: safeMessage(error) }],
      };
    } finally {
      if (previous === undefined) delete process.env.NODE9_NONINTERACTIVE;
      else process.env.NODE9_NONINTERACTIVE = previous;
      _resetConfigCache();
    }
    if (outcome.ok) return { kind: 'connected', workspaceName: res.workspaceName, outcome };
    if (attemptKeySaved(res.apiKey))
      return { kind: 'partial', workspaceName: res.workspaceName, outcome, retry: finish };
    return {
      kind: 'failed',
      reason:
        outcome.steps
          .filter((s) => !s.ok)
          .map((s) => s.detail)
          .join('; ') || 'Could not save the connection.',
    };
  };
  return finish();
}

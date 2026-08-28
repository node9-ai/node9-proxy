import * as http from 'http';
import * as https from 'https';
import * as os from 'os';
import { URL } from 'url';
import chalk from 'chalk';
import { resolveCloudEndpoint } from './cloud-endpoints';
import { getMachineId } from '../machine-id';
import { openBrowser } from '../utils/open-browser';

// The CLI half of device-auth login (login-v2 B1). Start an authorization,
// hand the human a URL + short code, then poll until the browser approves —
// the claiming poll is the ONLY delivery of the machine key. The human never
// sees a key or token; the code on screen exists so they can match terminal
// to browser tab.

interface StartResponse {
  userCode: string;
  pollToken: string;
  verificationUrl: string;
  intervalSec: number;
  expiresInSec: number;
}

interface PollResponse {
  status: 'pending' | 'approved' | 'denied' | 'expired';
  apiKey?: string;
  workspaceId?: string;
  workspaceName?: string;
  machineName?: string;
}

export type DeviceLoginResult =
  | { ok: true; apiKey: string; workspaceName: string; machineName: string }
  | { ok: false; reason: string };

// Plain JSON POST; http for tests, https in production (same pattern as
// connect's postConnect — the URL's protocol picks the lib).
function postJson<T>(url: string, body: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const u = new URL(url);
    const lib = u.protocol === 'http:' ? http : https;
    const req = lib.request(
      {
        method: 'POST',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: u.pathname + u.search,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 15000,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          const code = res.statusCode ?? 0;
          if (code >= 200 && code < 300) {
            try {
              resolve(JSON.parse(data) as T);
            } catch {
              reject(new Error('Unexpected response from the server.'));
            }
          } else {
            reject(new Error(`Server returned HTTP ${code}.`));
          }
        });
      }
    );
    req.on('error', (e) => reject(e));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out.'));
    });
    req.write(payload);
    req.end();
  });
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Run the interactive device login. Prints the URL + code, opens the browser
 * when one is plausibly present, and polls until approved/denied/expired.
 * Returns the machine key on success — the caller feeds it to onboardMachine.
 */
export async function runDeviceLogin(
  opts: { apiUrl?: string; noBrowser?: boolean; cliVersion?: string } = {}
): Promise<DeviceLoginResult> {
  // opts.apiUrl overrides the START endpoint (tests / self-host); poll is
  // always its sibling.
  const startUrl = resolveCloudEndpoint('/device/start', opts.apiUrl);
  const pollUrl = startUrl.replace(/\/device\/start$/, '/device/poll');

  let start: StartResponse;
  try {
    start = await postJson<StartResponse>(startUrl, {
      machineId: getMachineId(),
      hostname: os.hostname(),
      platform: process.platform,
      cliVersion: opts.cliVersion,
    });
  } catch (e) {
    return {
      ok: false,
      reason: `Could not reach the node9 cloud: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  console.log('');
  console.log(`  Open this link to approve the connection:`);
  console.log(`  ${chalk.cyan.underline(start.verificationUrl)}`);
  console.log('');
  console.log(`  Code: ${chalk.bold(start.userCode)} ${chalk.gray('(match it in the browser)')}`);
  console.log('');
  const opened = opts.noBrowser ? false : openBrowser(start.verificationUrl);
  console.log(
    chalk.gray(
      opened
        ? '  Waiting for approval in your browser…'
        : '  Open the link on any device (phone works) — waiting for approval…'
    )
  );

  const deadline = Date.now() + start.expiresInSec * 1000;
  // Floor at 10ms: guards 0/NaN from a misbehaving server without flooring
  // legitimate sub-second intervals (tests use 0.01s).
  const intervalMs = Math.max(10, (Number(start.intervalSec) || 5) * 1000);
  let consecutiveErrors = 0;

  while (Date.now() < deadline) {
    await sleep(intervalMs);
    let poll: PollResponse;
    try {
      poll = await postJson<PollResponse>(pollUrl, { pollToken: start.pollToken });
      consecutiveErrors = 0;
    } catch {
      // Transient network blips must not kill a login mid-approval; give up
      // only when the failures look structural.
      consecutiveErrors += 1;
      if (consecutiveErrors >= 5) {
        return { ok: false, reason: 'Lost contact with the server while waiting for approval.' };
      }
      continue;
    }
    if (poll.status === 'pending') continue;
    if (poll.status === 'approved' && poll.apiKey) {
      return {
        ok: true,
        apiKey: poll.apiKey,
        workspaceName: poll.workspaceName ?? '',
        machineName: poll.machineName ?? os.hostname(),
      };
    }
    if (poll.status === 'denied') {
      return { ok: false, reason: 'The request was denied in the browser.' };
    }
    return { ok: false, reason: 'The code expired — run `node9 login` again.' };
  }
  return { ok: false, reason: 'Timed out waiting for approval — run `node9 login` again.' };
}

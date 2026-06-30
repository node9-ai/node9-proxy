import type { Command } from 'commander';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import chalk from 'chalk';
import { writeCredentialsAndConfig } from '../../credentials';
import { setupDetectedAgents } from '../../setup';
import { runCloudSync } from '../../daemon/sync';
import { isTestingMode } from '../daemon-starter';

// node9 connect <token> — the onboarding bridge. Exchanges a dashboard connect
// token for a workspace key (POST /cli/connect), writes credentials + config,
// wires detected agents non-interactively, and fires one sync so the machine
// shows up in the dashboard. No raw key is ever copy-pasted by the user.
const DEFAULT_CONNECT_URL = 'https://api.node9.ai/api/v1/cli/connect';

interface ConnectResponse {
  apiKey: string;
  workspaceId: string;
  workspaceName: string;
}

// --api-url wins; else derive from NODE9_API_URL (the intercept base) so a dev
// pointing the daemon at staging also connects there; else prod default.
export function resolveConnectUrl(apiUrl?: string): string {
  if (apiUrl) return apiUrl;
  const base = process.env.NODE9_API_URL;
  if (base) return base.replace(/\/intercept\/?$/, '') + '/cli/connect';
  return DEFAULT_CONNECT_URL;
}

function postConnect(url: string, token: string): Promise<ConnectResponse> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ token });
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
          'Content-Length': Buffer.byteLength(body),
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
              resolve(JSON.parse(data) as ConnectResponse);
            } catch {
              reject(new Error('Unexpected response from the server.'));
            }
          } else if (code === 400 || code === 401) {
            reject(
              new Error(
                'This connect link expired or was already used — generate a new one in the dashboard.'
              )
            );
          } else {
            reject(new Error(`Connect failed (HTTP ${code}).`));
          }
        });
      }
    );
    req.on('error', (e) => reject(e));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out.'));
    });
    req.write(body);
    req.end();
  });
}

export function registerConnectCommand(program: Command): void {
  program
    .command('connect')
    .argument('<token>', 'A connect token from the dashboard')
    .option('--profile <name>', 'Save as a named profile (default: "default")')
    .option('--api-url <url>', 'Override the connect endpoint (self-host / dev)')
    .description('Connect this machine to a node9 workspace using a dashboard token')
    .action(async (token: string, options: { profile?: string; apiUrl?: string }) => {
      let resp: ConnectResponse;
      try {
        resp = await postConnect(resolveConnectUrl(options.apiUrl), token);
      } catch (e) {
        console.error(chalk.red(`✗ ${e instanceof Error ? e.message : 'Connect failed.'}`));
        process.exitCode = 1;
        return;
      }

      // Reuse login's writer (credentials.json + config.json approvers).
      writeCredentialsAndConfig(resp.apiKey, { profileName: options.profile });

      // Wire detected agents without prompting (curl | sh has no TTY).
      process.env.NODE9_NONINTERACTIVE = '1';
      let wired: string[] = [];
      try {
        wired = await setupDetectedAgents();
      } catch {
        // Agent wiring is best-effort; the connection itself already succeeded.
      }

      // Register the machine with the cloud so the dashboard shows it. Skipped
      // under the test runner (no live cloud).
      if (!isTestingMode()) {
        try {
          await runCloudSync();
        } catch {
          // Best-effort — the first hook call will sync anyway.
        }
      }

      console.log(chalk.green(`✅ Connected to ${resp.workspaceName}`));
      if (wired.length) {
        console.log(chalk.gray(`   Wired: ${wired.join(', ')}`));
      } else {
        console.log(
          chalk.gray('   No agents detected yet — run `node9 init` after installing one.')
        );
      }
    });
}

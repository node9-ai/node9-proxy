// src/cli/commands/blast.ts
// Registered as `node9 blast` by cli.ts.
//
// Maps what an AI agent can currently reach on this machine —
// sensitive files, credentials, and environment variables.
// Read-only. No network calls. No side effects.

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanArgs } from '../../dlp';

// ---------------------------------------------------------------------------
// Sensitive path definitions
// ---------------------------------------------------------------------------

interface SensitivePath {
  label: string;
  description: string;
  score: number; // points deducted if readable
}

function buildSensitivePaths(home: string, cwd: string): Array<SensitivePath & { full: string }> {
  return [
    {
      full: path.join(home, '.ssh', 'id_rsa'),
      label: '~/.ssh/id_rsa',
      description: 'RSA private key — grants SSH access to your servers',
      score: 20,
    },
    {
      full: path.join(home, '.ssh', 'id_ed25519'),
      label: '~/.ssh/id_ed25519',
      description: 'Ed25519 private key — grants SSH access to your servers',
      score: 20,
    },
    {
      full: path.join(home, '.ssh', 'id_ecdsa'),
      label: '~/.ssh/id_ecdsa',
      description: 'ECDSA private key — grants SSH access to your servers',
      score: 20,
    },
    {
      full: path.join(home, '.aws', 'credentials'),
      label: '~/.aws/credentials',
      description: 'AWS access keys — full cloud account access',
      score: 20,
    },
    {
      full: path.join(home, '.aws', 'config'),
      label: '~/.aws/config',
      description: 'AWS configuration — account and region settings',
      score: 5,
    },
    {
      full: path.join(home, '.config', 'gcloud', 'credentials.db'),
      label: '~/.config/gcloud/credentials.db',
      description: 'Google Cloud credentials',
      score: 15,
    },
    {
      full: path.join(home, '.docker', 'config.json'),
      label: '~/.docker/config.json',
      description: 'Docker registry auth tokens',
      score: 10,
    },
    {
      full: path.join(home, '.netrc'),
      label: '~/.netrc',
      description: 'FTP/HTTP credentials in plain text',
      score: 15,
    },
    {
      full: path.join(home, '.npmrc'),
      label: '~/.npmrc',
      description: 'npm auth token — can publish packages as you',
      score: 10,
    },
    {
      full: path.join(home, '.node9', 'credentials.json'),
      label: '~/.node9/credentials.json',
      description: 'Node9 cloud API key',
      score: 10,
    },
    {
      full: path.join(cwd, '.env'),
      label: '.env  (current folder)',
      description: 'App secrets — database passwords, API keys',
      score: 20,
    },
    {
      full: path.join(cwd, '.env.local'),
      label: '.env.local  (current folder)',
      description: 'Local overrides — often contains real credentials',
      score: 15,
    },
    {
      full: path.join(cwd, '.env.production'),
      label: '.env.production  (current folder)',
      description: 'Production secrets',
      score: 20,
    },
  ];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isReadable(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function scoreLabel(score: number): string {
  if (score >= 80) return chalk.green(`${score}/100  Good`);
  if (score >= 50) return chalk.yellow(`${score}/100  Moderate risk`);
  if (score >= 25) return chalk.red(`${score}/100  High risk`);
  return chalk.red.bold(`${score}/100  Critical`);
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

export function registerBlastCommand(program: Command): void {
  program
    .command('blast')
    .description('Map what an AI agent can currently reach on this machine')
    .action(() => {
      const home = os.homedir();
      const cwd = process.cwd();
      const paths = buildSensitivePaths(home, cwd);

      console.log('');
      console.log(
        chalk.bold('  🔭  Node9 Blast Radius') +
          chalk.dim('  ·  what an AI agent can reach from here')
      );
      console.log(chalk.dim('  Running in: ') + chalk.white(cwd.replace(home, '~')));
      console.log('');

      // ── Sensitive file check ──────────────────────────────────────────────
      let scoreDeduction = 0;
      const reachable: Array<(typeof paths)[0]> = [];
      const missing: Array<(typeof paths)[0]> = [];

      for (const p of paths) {
        if (fs.existsSync(p.full) && isReadable(p.full)) {
          reachable.push(p);
          scoreDeduction += p.score;
        } else {
          missing.push(p);
        }
      }

      if (reachable.length > 0) {
        console.log('  ' + chalk.red.bold('Sensitive files reachable:'));
        for (const p of reachable) {
          console.log(
            '    ' + chalk.red('✗  ') + chalk.yellow(p.label.padEnd(38)) + chalk.dim(p.description)
          );
        }
        console.log('');
      }

      // ── Environment variable check ────────────────────────────────────────
      const envFindings: Array<{ key: string; patternName: string }> = [];
      for (const [key, value] of Object.entries(process.env)) {
        if (!value) continue;
        const match = scanArgs({ [key]: value });
        if (match) {
          envFindings.push({ key, patternName: match.patternName });
          scoreDeduction += 10;
        }
      }

      if (envFindings.length > 0) {
        console.log('  ' + chalk.red.bold('Secrets in active environment:'));
        for (const f of envFindings) {
          console.log(
            '    ' + chalk.red('✗  ') + chalk.yellow(f.key.padEnd(38)) + chalk.dim(f.patternName)
          );
        }
        console.log('');
      }

      // ── Score ─────────────────────────────────────────────────────────────
      const score = Math.max(0, 100 - scoreDeduction);
      console.log('  ' + chalk.dim('─'.repeat(70)));

      if (reachable.length === 0 && envFindings.length === 0) {
        console.log('  ' + chalk.green('✅  No sensitive files or environment secrets found.'));
        console.log('  Security Score: ' + scoreLabel(score));
      } else {
        console.log(
          '  Security Score: ' +
            scoreLabel(score) +
            chalk.dim(
              `  (${reachable.length} file${reachable.length !== 1 ? 's' : ''}, ` +
                `${envFindings.length} env var${envFindings.length !== 1 ? 's' : ''})`
            )
        );
        console.log('');
        console.log(
          chalk.dim(
            '  Every AI agent you start can read the files and env vars listed above.\n' +
              '  Run `node9 shield enable project-jail` to restrict agent file access.\n' +
              '  Run `node9 mask` to redact secrets from existing session history.'
          )
        );
      }

      console.log('');
    });
}

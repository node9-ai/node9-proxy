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
import { homeCredentialFiles } from '../../credential-files';

// ---------------------------------------------------------------------------
// Sensitive path definitions
// ---------------------------------------------------------------------------

interface SensitivePath {
  label: string;
  description: string;
  score: number; // points deducted if readable
}

function buildSensitivePaths(home: string, cwd: string): Array<SensitivePath & { full: string }> {
  // The home files come from the one list posture reads too (fw#408).
  const homeFiles = homeCredentialFiles(home).map(({ full, label, description, score }) => ({
    full,
    label,
    description,
    score,
  }));
  return [
    ...homeFiles,
    {
      full: path.join(cwd, '.env'),
      label: '.env  (current folder)',
      description: 'App secrets: database passwords, API keys',
      score: 20,
    },
    {
      full: path.join(cwd, '.env.local'),
      label: '.env.local  (current folder)',
      description: 'Local overrides: often contains real credentials',
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

export function scoreLabel(score: number): string {
  if (score >= 80) return chalk.green(`${score}/100  Good`);
  if (score >= 50) return chalk.yellow(`${score}/100  Moderate risk`);
  if (score >= 25) return chalk.red(`${score}/100  High risk`);
  return chalk.red.bold(`${score}/100  Critical`);
}

// ---------------------------------------------------------------------------
// Core logic — exported so node9 scan can embed the results
// ---------------------------------------------------------------------------

export interface BlastFinding {
  full: string;
  label: string;
  description: string;
  score: number;
}

export interface BlastResult {
  reachable: BlastFinding[];
  envFindings: Array<{ key: string; patternName: string }>;
  score: number;
}

export function runBlast(): BlastResult {
  const home = os.homedir();
  const cwd = process.cwd();
  const paths = buildSensitivePaths(home, cwd);

  let scoreDeduction = 0;
  const reachable: BlastFinding[] = [];

  for (const p of paths) {
    if (fs.existsSync(p.full) && isReadable(p.full)) {
      reachable.push(p);
      scoreDeduction += p.score;
    }
  }

  const envFindings: Array<{ key: string; patternName: string }> = [];
  for (const [key, value] of Object.entries(process.env)) {
    if (!value) continue;
    const match = scanArgs({ [key]: value });
    if (match) {
      envFindings.push({ key, patternName: match.patternName });
      scoreDeduction += 10;
    }
  }

  return { reachable, envFindings, score: Math.max(0, 100 - scoreDeduction) };
}

/** Width of the label column: 38 unless a label needs more (fw#421 item 2:
 *  `~/.config/gcloud/application_default_credentials.json` glued to its text). */
export function labelColumnWidth(labels: string[]): number {
  return Math.max(38, ...labels.map((l) => l.length + 2));
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
      const { reachable, envFindings, score } = runBlast();
      const width = labelColumnWidth([
        ...reachable.map((p) => p.label),
        ...envFindings.map((f) => f.key),
      ]);

      console.log('');
      console.log(
        chalk.bold('  🔭  Node9 Blast Radius') +
          chalk.dim('  ·  what an AI agent can reach from here')
      );
      console.log(chalk.dim('  Running in: ') + chalk.white(cwd.replace(home, '~')));
      console.log('');

      if (reachable.length > 0) {
        console.log('  ' + chalk.red.bold('Sensitive files reachable:'));
        for (const p of reachable) {
          console.log(
            '    ' +
              chalk.red('✗  ') +
              chalk.yellow(p.label.padEnd(width)) +
              chalk.dim(p.description)
          );
        }
        console.log('');
      }

      if (envFindings.length > 0) {
        console.log('  ' + chalk.red.bold('Secrets in active environment:'));
        for (const f of envFindings) {
          console.log(
            '    ' + chalk.red('✗  ') + chalk.yellow(f.key.padEnd(width)) + chalk.dim(f.patternName)
          );
        }
        console.log('');
      }

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

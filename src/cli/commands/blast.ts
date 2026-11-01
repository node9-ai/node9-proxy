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
import { runPosture } from '../../posture';
import { renderPostureSection } from '../../posture/render';

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

/** Alias of `node9 posture` (fw#421 P3): the Secrets section, no score. */
export function registerBlastCommand(program: Command): void {
  program
    .command('blast')
    .description('Alias of `node9 posture` (Secrets section): what an AI agent can read here')
    .action(async () => {
      const result = await runPosture();
      console.log(renderPostureSection(result, 'Secrets'));
      console.log(
        chalk.dim('  Full scorecard: ') +
          chalk.cyan('node9 posture') +
          chalk.dim(' (score, every category, what to fix first)')
      );
      console.log('');
    });
}

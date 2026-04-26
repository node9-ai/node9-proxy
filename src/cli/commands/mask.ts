// src/cli/commands/mask.ts
// Registered as `node9 mask` by cli.ts.
//
// Scans Claude/Gemini session history files on disk and redacts any plaintext
// secrets found in them. Cleans local storage only — secrets already sent to
// AI provider servers during active sessions cannot be recalled.

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { redactText } from '../../dlp';

function findJsonlFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...findJsonlFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.jsonl')) results.push(full);
  }
  return results;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Walk every value in a parsed JSON object and apply redactText to strings.
// Returns { modified: boolean, found: string[] }.
function redactJson(obj: unknown): { value: unknown; modified: boolean; found: string[] } {
  if (typeof obj === 'string') {
    const { result, found } = redactText(obj);
    return { value: result, modified: result !== obj, found };
  }
  if (Array.isArray(obj)) {
    let modified = false;
    const found: string[] = [];
    const value = obj.map((item) => {
      const r = redactJson(item);
      if (r.modified) modified = true;
      r.found.forEach((f) => {
        if (!found.includes(f)) found.push(f);
      });
      return r.value;
    });
    return { value, modified, found };
  }
  if (obj !== null && typeof obj === 'object') {
    let modified = false;
    const found: string[] = [];
    const value: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      const r = redactJson(v);
      value[k] = r.value;
      if (r.modified) modified = true;
      r.found.forEach((f) => {
        if (!found.includes(f)) found.push(f);
      });
    }
    return { value, modified, found };
  }
  return { value: obj, modified: false, found: [] };
}

function processFile(
  filePath: string,
  dryRun: boolean
): { redactedLines: number; patterns: string[] } {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return { redactedLines: 0, patterns: [] };
  }

  const lines = raw.split('\n');
  let redactedLines = 0;
  const patterns: string[] = [];
  const newLines: string[] = [];

  for (const line of lines) {
    if (!line.trim()) {
      newLines.push(line);
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      newLines.push(line);
      continue;
    }

    const { value, modified, found } = redactJson(parsed);
    if (modified) {
      redactedLines++;
      found.forEach((f) => {
        if (!patterns.includes(f)) patterns.push(f);
      });
      newLines.push(JSON.stringify(value));
    } else {
      newLines.push(line);
    }
  }

  if (!dryRun && redactedLines > 0) {
    fs.writeFileSync(filePath, newLines.join('\n'), 'utf-8');
  }

  return { redactedLines, patterns };
}

// Processes a plain JSON file (e.g. Gemini session files).
function processJsonFile(
  filePath: string,
  dryRun: boolean
): { redactedLines: number; patterns: string[] } {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return { redactedLines: 0, patterns: [] };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { redactedLines: 0, patterns: [] };
  }

  const { value, modified, found } = redactJson(parsed);
  if (!modified) return { redactedLines: 0, patterns: [] };

  if (!dryRun) {
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf-8');
  }
  return { redactedLines: 1, patterns: found };
}

function findJsonFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...findJsonFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.json')) results.push(full);
  }
  return results;
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

export function registerMaskCommand(program: Command): void {
  program
    .command('mask')
    .description('Redact plaintext secrets from local AI session history files')
    .option('--dry-run', 'show what would be redacted without making changes')
    .option('--all', 'scan all history (default: last 30 days)')
    .action(async (options: { dryRun?: boolean; all?: boolean }) => {
      const dryRun = !!options.dryRun;
      const home = os.homedir();

      // Find session files — Claude (JSONL) and Gemini (JSON)
      const claudeDir = path.join(home, '.claude', 'projects');
      const geminiDir = path.join(home, '.gemini', 'tmp');
      const allFiles: Array<{ path: string; type: 'jsonl' | 'json' }> = [
        ...findJsonlFiles(claudeDir).map((p) => ({ path: p, type: 'jsonl' as const })),
        ...findJsonFiles(geminiDir).map((p) => ({ path: p, type: 'json' as const })),
      ];

      // Date filter (default last 30 days)
      const cutoff = options.all ? null : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

      const filtered = cutoff
        ? allFiles.filter((f) => {
            try {
              return fs.statSync(f.path).mtime >= cutoff;
            } catch {
              return false;
            }
          })
        : allFiles;

      if (filtered.length === 0) {
        console.log(chalk.yellow('  No session files found.'));
        return;
      }

      console.log('');
      if (dryRun) {
        console.log(chalk.dim('  Dry run — no files will be modified.\n'));
      }

      let totalFiles = 0;
      let totalLines = 0;
      const totalPatterns: string[] = [];

      for (const file of filtered) {
        const shortPath = file.path.replace(home, '~');
        const { redactedLines, patterns } =
          file.type === 'jsonl'
            ? processFile(file.path, dryRun)
            : processJsonFile(file.path, dryRun);

        if (redactedLines > 0) {
          totalFiles++;
          totalLines += redactedLines;
          patterns.forEach((p) => {
            if (!totalPatterns.includes(p)) totalPatterns.push(p);
          });

          const verb = dryRun ? 'Would redact' : 'Redacted';
          console.log(
            '  ' +
              chalk.dim(shortPath.slice(0, 60).padEnd(62)) +
              chalk.red(`${verb}: `) +
              chalk.yellow(patterns.join(', ')) +
              chalk.dim(` (${redactedLines} line${redactedLines !== 1 ? 's' : ''})`)
          );
        }
      }

      console.log('');
      if (totalFiles === 0) {
        console.log(chalk.green('  No secrets found in session history.'));
      } else {
        const verb = dryRun ? 'would be modified' : 'modified';
        console.log(
          chalk.bold(`  ${totalFiles} file${totalFiles !== 1 ? 's' : ''} ${verb}`) +
            chalk.dim(`, ${totalLines} line${totalLines !== 1 ? 's' : ''} redacted`)
        );
        console.log('  Patterns: ' + chalk.yellow(totalPatterns.join(', ')));
        if (!dryRun) {
          console.log('');
          console.log(
            chalk.dim(
              '  Note: secrets were already sent to the AI provider during the active session.\n' +
                '        This cleans your local disk only. Rotate any exposed keys.'
            )
          );
        }
      }
      console.log('');
    });
}

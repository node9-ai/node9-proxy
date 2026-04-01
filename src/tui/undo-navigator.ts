// src/tui/undo-navigator.ts
// Interactive snapshot navigator for `node9 undo`.
// Arrow keys browse history; Enter restores the selected snapshot.
import readline from 'readline';
import chalk from 'chalk';
import { SnapshotEntry, applyUndo, computeUndoDiff } from '../undo.js';

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const RESET = '\x1B[0m';
const BOLD = '\x1B[1m';
const CLEAR_SCREEN = '\x1B[2J\x1B[H';

// 60s gap between snapshots = treat as a new session boundary
const SESSION_GAP_MS = 60_000;

export interface NavigatorResult {
  restored: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatAge(timestamp: number): string {
  const age = Math.round((Date.now() - timestamp) / 1000);
  if (age < 60) return `${age}s ago`;
  if (age < 3600) return `${Math.round(age / 60)}m ago`;
  if (age < 86400) return `${Math.round(age / 3600)}h ago`;
  return `${Math.round(age / 86400)}d ago`;
}

function renderDiff(raw: string): void {
  const lines = raw
    .split('\n')
    .filter(
      (l) => !l.startsWith('diff --git') && !l.startsWith('index ') && !l.startsWith('Binary')
    );
  for (const line of lines) {
    if (line.startsWith('+++') || line.startsWith('---')) {
      process.stdout.write(chalk.bold(line) + '\n');
    } else if (line.startsWith('+')) {
      process.stdout.write(chalk.green(line) + '\n');
    } else if (line.startsWith('-')) {
      process.stdout.write(chalk.red(line) + '\n');
    } else if (line.startsWith('@@')) {
      process.stdout.write(chalk.cyan(line) + '\n');
    } else {
      process.stdout.write(chalk.gray(line) + '\n');
    }
  }
}

function isSessionBoundary(entries: SnapshotEntry[], idx: number): boolean {
  if (idx <= 0) return false;
  return entries[idx - 1].timestamp - entries[idx].timestamp > SESSION_GAP_MS;
}

/** Returns the index of the oldest entry in the same session as idx. */
function sessionStart(entries: SnapshotEntry[], idx: number): number {
  let i = idx;
  while (i > 0 && !isSessionBoundary(entries, i)) i--;
  return i;
}

function render(entries: SnapshotEntry[], idx: number): void {
  // entries are newest-first
  const entry = entries[idx];
  const total = entries.length;
  const step = idx + 1;

  process.stdout.write(CLEAR_SCREEN);

  // ── Header ────────────────────────────────────────────────────────────────
  process.stdout.write(
    chalk.magenta.bold(`⏪  Node9 Undo`) +
      chalk.gray(`  ──  step ${step} of ${total}`) +
      (entry.files?.length
        ? chalk.gray(
            `  ──  ${entry.files.slice(0, 2).join(', ')}${entry.files.length > 2 ? ` +${entry.files.length - 2} more` : ''}`
          )
        : '') +
      '\n\n'
  );

  // ── Snapshot info ─────────────────────────────────────────────────────────
  process.stdout.write(
    `  ${BOLD}Tool:${RESET}  ${chalk.cyan(entry.tool)}` +
      (entry.argsSummary ? chalk.gray('  →  ' + entry.argsSummary) : '') +
      '\n'
  );
  process.stdout.write(`  ${BOLD}When:${RESET}  ${chalk.gray(formatAge(entry.timestamp))}\n`);
  process.stdout.write(`  ${BOLD}Dir: ${RESET}  ${chalk.gray(entry.cwd)}\n`);

  if (entry.files && entry.files.length > 0) {
    process.stdout.write(`  ${BOLD}Files:${RESET} ${chalk.gray(entry.files.join(', '))}\n`);
  }

  // ── Session boundary label ────────────────────────────────────────────────
  if (idx < total - 1 && isSessionBoundary(entries, idx + 1)) {
    process.stdout.write(chalk.gray('\n  ── session boundary above ──\n'));
  }

  process.stdout.write('\n');

  // ── Diff ──────────────────────────────────────────────────────────────────
  const diff = entry.diff ?? computeUndoDiff(entry.hash, entry.cwd);
  if (diff) {
    renderDiff(diff);
  } else {
    process.stdout.write(
      chalk.gray('  (no diff — working tree may already match this snapshot)\n')
    );
  }

  // ── Footer ────────────────────────────────────────────────────────────────
  process.stdout.write('\n');
  process.stdout.write(
    chalk.gray('  ') +
      (idx < total - 1 ? chalk.white('[←] older') : chalk.gray('[←] older')) +
      chalk.gray('   ') +
      (idx > 0 ? chalk.white('[→] newer') : chalk.gray('[→] newer')) +
      chalk.gray('   ') +
      chalk.green('[↵] restore here') +
      chalk.gray('   ') +
      chalk.yellow('[s] session start') +
      chalk.gray('   ') +
      chalk.gray('[q] quit') +
      '\n'
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function runUndoNavigator(entries: SnapshotEntry[]): Promise<NavigatorResult> {
  if (entries.length === 0) return { restored: false };

  // Display newest first
  const display = [...entries].reverse();
  let idx = 0; // 0 = most recent

  if (!process.stdout.isTTY || !process.stdin.isTTY) {
    // Non-interactive fallback: just show the most recent entry
    render(display, idx);
    return { restored: false };
  }

  readline.emitKeypressEvents(process.stdin);

  return new Promise((resolve) => {
    let done = false;

    render(display, idx);

    try {
      process.stdin.setRawMode(true);
    } catch {
      resolve({ restored: false });
      return;
    }

    process.stdin.resume();

    const cleanup = () => {
      process.stdin.removeListener('keypress', onKeypress);
      try {
        process.stdin.setRawMode(false);
      } catch {
        /* ignore */
      }
      process.stdin.pause();
    };

    const onKeypress = (_str: string, key: { name?: string; ctrl?: boolean }) => {
      if (done) return;
      const name = key?.name ?? '';

      if (name === 'left' || name === 'h') {
        // Older
        if (idx < display.length - 1) {
          idx++;
          render(display, idx);
        }
      } else if (name === 'right' || name === 'l') {
        // Newer
        if (idx > 0) {
          idx--;
          render(display, idx);
        }
      } else if (name === 's') {
        // Jump to session start (oldest in current session group)
        const start = sessionStart(display, idx);
        if (start !== idx) {
          idx = start;
          render(display, idx);
        }
      } else if (name === 'return' || name === 'y') {
        // Restore
        done = true;
        cleanup();
        process.stdout.write(CLEAR_SCREEN);
        const entry = display[idx];
        process.stdout.write(chalk.magenta.bold('\n⏪  Restoring snapshot...\n\n'));
        if (applyUndo(entry.hash, entry.cwd)) {
          process.stdout.write(chalk.green('✅  Reverted successfully.\n\n'));
          resolve({ restored: true });
        } else {
          process.stdout.write(chalk.red('❌  Undo failed.\n\n'));
          resolve({ restored: false });
        }
      } else if (name === 'q' || (key?.ctrl && name === 'c')) {
        // Quit
        done = true;
        cleanup();
        process.stdout.write(CLEAR_SCREEN);
        process.stdout.write(chalk.gray('\nCancelled.\n\n'));
        resolve({ restored: false });
      }
    };

    process.stdin.on('keypress', onKeypress);
  });
}

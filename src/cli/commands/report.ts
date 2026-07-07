// src/cli/commands/report.ts
// Registered as `node9 report` by cli.ts.
//
// Reads ~/.node9/audit.log via aggregateReportFromAudit (in cli/aggregate/)
// and renders a summary dashboard for a chosen period. The aggregation step
// is shared with the Report [2] view in `node9 monitor` — this command is
// just the terminal renderer wrapped around it.

import type { Command } from 'commander';
import chalk from 'chalk';
import { aggregateReportFromAudit, type ResponseDlpEntry } from '../aggregate/report-audit';
import {
  buildReportJson,
  type BuildReportJsonInput,
  type ReportPeriod,
} from '../render/report-json';

// ---------------------------------------------------------------------------
// Display helpers (rendering only — no I/O, no aggregation)
// ---------------------------------------------------------------------------

const BLOCK_REASON_LABELS: Record<string, string> = {
  timeout: 'Approval timeout',
  'smart-rule-block': 'Smart rule',
  'observe-mode-dlp-would-block': 'DLP (observe)',
  'persistent-deny': 'Persistent deny',
  'local-decision': 'User denied',
  'dlp-block': 'DLP block',
  'loop-detected': 'Loop detected',
  // Report UI v2 · P0 — these were leaking as raw checkedBy strings in
  // Top Blocks (no label) despite the audit already recording them.
  'taint-egress-block': 'Egress blocked',
  'observe-mode-taint-egress-would-block': 'Egress (observe)',
  'app-permission-block': 'MCP tool blocked',
  'app-permission-review': 'MCP tool (review)',
  'observe-mode-pii-would-block': 'PII (observe)',
  'pii-block': 'PII block',
};

function humanBlockReason(reason: string): string {
  return BLOCK_REASON_LABELS[reason] ?? reason;
}

/** Plain bar string — no chalk so padEnd works on the raw string. */
function barStr(value: number, max: number, width: number): string {
  if (max === 0 || width <= 0) return '░'.repeat(width);
  const filled = Math.max(1, Math.round((value / max) * width));
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function colorBar(value: number, max: number, width: number): string {
  const s = barStr(value, max, width);
  const filled = Math.max(1, Math.round(max > 0 ? (value / max) * width : 0));
  return chalk.cyan(s.slice(0, filled)) + chalk.dim(s.slice(filled));
}

function fmtDate(d: Date | string): string {
  const date = typeof d === 'string' ? new Date(d + 'T12:00:00') : d;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function num(n: number): string {
  return n.toLocaleString();
}

function fmtCost(usd: number): string {
  if (usd < 0.001) return '< $0.001';
  if (usd < 1) return '$' + usd.toFixed(4);
  return '$' + usd.toFixed(2);
}

// ---------------------------------------------------------------------------
// Main command
// ---------------------------------------------------------------------------

export function registerReportCommand(program: Command): void {
  program
    .command('report')
    .description('Activity and security report — what Claude did, what was blocked')
    .option('--period <period>', 'today | 7d | 30d | month', '7d')
    .option('--no-tests', 'exclude test runner calls (npm test, vitest, pytest…) from stats')
    .option('--json', 'Emit machine-readable JSON to stdout (suppresses renderer)')
    .action((options: { period: string; tests: boolean; json?: boolean }) => {
      const period: ReportPeriod = (['today', '7d', '30d', '90d', 'month'] as const).includes(
        options.period as ReportPeriod
      )
        ? (options.period as ReportPeriod)
        : '7d';

      const excludeTests = options.tests === false;
      const { data, hasAuditFile, responseDlpEntries } = aggregateReportFromAudit(period, {
        excludeTests,
      });

      // Top-of-output unacked-DLP banner — lifetime count, not period-scoped
      if (data.unackedDlp > 0 && !options.json) {
        console.log('');
        console.log(
          chalk.bgRed.white.bold(
            ` ⚠️  DLP ALERT: ${data.unackedDlp} secret${data.unackedDlp !== 1 ? 's' : ''} found in Claude response text `
          ) +
            '  ' +
            chalk.yellow('→ run: node9 dlp')
        );
      }

      if (!hasAuditFile && !options.json) {
        console.log(
          chalk.yellow('\n  No audit data found. Run node9 with Claude Code to generate entries.\n')
        );
        return;
      }

      // ── JSON output mode ────────────────────────────────────────────────
      // Emits one valid JSON object to stdout and returns. The unacked-DLP
      // banner above is gated on !options.json so stdout stays clean for
      // CI gates and external integrations.
      if (options.json) {
        const envelope = buildReportJson(data);
        process.stdout.write(JSON.stringify(envelope, null, 2) + '\n');
        return;
      }

      if (data.total === 0) {
        console.log(chalk.yellow(`\n  No activity for period "${period}".\n`));
        return;
      }

      renderTerminalReport(data, responseDlpEntries, excludeTests);
    });
}

// ---------------------------------------------------------------------------
// Terminal renderer
// ---------------------------------------------------------------------------

function renderTerminalReport(
  data: BuildReportJsonInput,
  responseDlpEntries: ResponseDlpEntry[],
  excludeTests: boolean
): void {
  const {
    period,
    start,
    end,
    total,
    excludedTests,
    userApproved,
    userDenied,
    timedOut,
    hardBlocked,
    dlpBlocked,
    observeDlp,
    loopHits,
    testPasses,
    testFails,
    priorBlockRate,
    cost: {
      claudeUSD,
      codexUSD,
      geminiUSD,
      inputTokens: costInputTokens,
      outputTokens: costOutputTokens,
      cacheWriteTokens: costCacheWrite,
      cacheReadTokens: costCacheRead,
      byDay: costByDay,
      byModel: costByModel,
    },
    toolMap,
    blockMap,
    agentMap,
    mcpMap,
    dailyMap,
    hourMap,
    dimensions,
  } = data;

  const costUSD = claudeUSD + codexUSD + geminiUSD;

  const topTools = [...toolMap.entries()].sort((a, b) => b[1].calls - a[1].calls).slice(0, 8);
  const topBlocks = [...blockMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const dailyList = [...dailyMap.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-14);

  const maxTool = Math.max(...topTools.map(([, v]) => v.calls), 1);
  const maxBlock = Math.max(...topBlocks.map(([, v]) => v), 1);
  const maxDaily = Math.max(...dailyList.map(([, v]) => v.calls), 1);

  // --- Layout ---
  const W = Math.min(process.stdout.columns || 80, 100);
  const INNER = W - 4;
  const COL = Math.floor(INNER / 2) - 1;
  const LABEL = 24;
  const BAR = Math.max(6, Math.min(14, COL - LABEL - 8));
  const TOOL_COUNT_W = Math.max(...topTools.map(([, v]) => num(v.calls).length), 1);
  const BLOCK_COUNT_W = Math.max(...topBlocks.map(([, v]) => num(v).length), 1);

  const line = chalk.dim('─'.repeat(W - 2));

  // ── Header ──
  const periodLabel: Record<ReportPeriod, string> = {
    today: 'Today',
    '7d': 'Last 7 Days',
    '30d': 'Last 30 Days',
    '90d': 'Last 90 Days',
    month: 'This Month',
  };
  console.log('');
  console.log(
    '  ' +
      chalk.bold.cyan('🛡 node9 Report') +
      chalk.dim('  ·  ') +
      chalk.white(periodLabel[period]) +
      chalk.dim(`  ${fmtDate(start)} – ${fmtDate(end)}`) +
      chalk.dim(`  ${num(total)} events`) +
      (excludeTests ? chalk.dim(`  –tests (–${excludedTests})`) : '')
  );
  console.log('  ' + line);

  // ── Protection Summary ──
  const totalBlocked = timedOut + hardBlocked + dlpBlocked + loopHits + userDenied;
  const currentRate = total > 0 ? totalBlocked / total : 0;
  const trendLabel = (() => {
    if (priorBlockRate === null) return '';
    const delta = Math.round((currentRate - priorBlockRate) * 100);
    if (delta === 0) return '';
    return (
      '  ' +
      (delta > 0 ? chalk.red(`▲${delta}%`) : chalk.green(`▼${Math.abs(delta)}%`)) +
      chalk.dim(' vs prior')
    );
  })();

  const reads = toolMap.get('Read')?.calls ?? 0;
  const edits = (toolMap.get('Edit')?.calls ?? 0) + (toolMap.get('Write')?.calls ?? 0);
  const ratioLabel =
    reads > 0 ? chalk.dim(`edit/read ${(edits / reads).toFixed(1)}`) : chalk.dim('edit/read –');
  const testLabel =
    testPasses + testFails > 0
      ? chalk.dim('tests ') +
        chalk.green(`${testPasses}✓`) +
        (testFails > 0 ? ' ' + chalk.red(`${testFails}✗`) : '')
      : chalk.dim('tests –');

  console.log('');
  console.log('  ' + chalk.bold('Protection Summary'));
  console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
  console.log(
    '  ' + chalk.dim('Intercepted') + '  ' + chalk.white(num(total)) + chalk.dim(' tool calls')
  );
  console.log('');

  const COL1 = 18;
  const summaryRow = (
    icon: string,
    label: string,
    count: number,
    note?: string,
    colorFn: (s: string) => string = (s) => s
  ) => {
    const countStr = colorFn(num(count));
    const noteStr = note ? chalk.dim('   ' + note) : '';
    console.log('    ' + icon + '  ' + chalk.white(label.padEnd(COL1)) + countStr + noteStr);
  };

  summaryRow(
    userApproved > 0 ? chalk.green('✅') : chalk.dim('✅'),
    'User approved',
    userApproved,
    userApproved === 0 ? 'no popups this period' : undefined,
    userApproved > 0 ? (s) => chalk.green(s) : (s) => chalk.dim(s)
  );
  summaryRow(
    userDenied > 0 ? chalk.red('🚫') : chalk.dim('🚫'),
    'User denied',
    userDenied,
    undefined,
    userDenied > 0 ? (s) => chalk.red(s) : (s) => chalk.dim(s)
  );
  summaryRow(
    timedOut > 0 ? chalk.yellow('⏱') : chalk.dim('⏱'),
    'Timed out',
    timedOut,
    timedOut > 0 ? 'no approval response' : undefined,
    timedOut > 0 ? (s) => chalk.yellow(s) : (s) => chalk.dim(s)
  );
  summaryRow(
    hardBlocked > 0 ? chalk.red('🛑') : chalk.dim('🛑'),
    'Auto-blocked',
    hardBlocked,
    undefined,
    hardBlocked > 0 ? (s) => chalk.red(s) : (s) => chalk.dim(s)
  );
  summaryRow(
    dlpBlocked > 0 ? chalk.yellow('🚨') : chalk.dim('🚨'),
    'DLP blocked',
    dlpBlocked,
    undefined,
    dlpBlocked > 0 ? (s) => chalk.yellow(s) : (s) => chalk.dim(s)
  );
  summaryRow(
    observeDlp > 0 ? chalk.blue('👁') : chalk.dim('👁'),
    'DLP (observe)',
    observeDlp,
    observeDlp > 0 ? 'would-block in strict mode' : undefined,
    observeDlp > 0 ? (s) => chalk.blue(s) : (s) => chalk.dim(s)
  );
  summaryRow(
    loopHits > 0 ? chalk.yellow('🔄') : chalk.dim('🔄'),
    'Loops detected',
    loopHits,
    undefined,
    loopHits > 0 ? (s) => chalk.yellow(s) : (s) => chalk.dim(s)
  );

  if (trendLabel || ratioLabel || testPasses + testFails > 0) {
    console.log('');
    console.log('  ' + ratioLabel + '   ' + testLabel + trendLabel);
  }
  console.log('');

  // ── By dimension (Report UI v2 · P0) ──
  // The control plane governs six dimensions; show "what happened" in each,
  // from the same audit rows. A zero dimension renders dimmed (measured, not
  // hidden) so an empty section never reads as "nothing to see".
  {
    const d = dimensions;
    console.log('  ' + chalk.bold('By dimension') + chalk.dim('   what fired, per governed area'));
    console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
    const dimRow = (icon: string, label: string, active: boolean, detail: string) => {
      const l = active ? chalk.white(label.padEnd(14)) : chalk.dim(label.padEnd(14));
      const v = active ? detail : chalk.dim(detail);
      console.log('    ' + (active ? icon : chalk.dim(icon)) + '  ' + l + v);
    };
    dimRow('🌐', 'Network', d.network.blocked > 0, `${num(d.network.blocked)} egress blocked`);
    dimRow(
      '🔒',
      'Data',
      d.data.blocked + d.data.observed > 0,
      `${num(d.data.blocked)} blocked · ${num(d.data.observed)} observed (DLP/PII)`
    );
    dimRow(
      '✋',
      'Approvals',
      d.approvals.approved + d.approvals.denied + d.approvals.timedOut > 0,
      `${num(d.approvals.approved)} approved · ${num(d.approvals.denied)} denied · ${num(d.approvals.timedOut)} timed-out→deny`
    );
    dimRow('📁', 'Files', d.files.blocked > 0, `${num(d.files.blocked)} jail-path reads blocked`);
    dimRow(
      '🛠',
      'Tool rules',
      d.toolRules.blocked + d.toolRules.mcp + d.toolRules.loops > 0,
      `${num(d.toolRules.blocked)} shields/rules · ${num(d.toolRules.mcp)} MCP · ${num(d.toolRules.loops)} loops`
    );
    dimRow('💰', 'Cost', d.cost.totalUSD > 0, `${fmtCost(d.cost.totalUSD)} this period`);
  }
  console.log('');

  // ── Top Tools | Top Blocks ──
  const toolHeaderRaw = 'Top Tools';
  const blockHeaderRaw = 'Top Blocks';
  console.log(
    '  ' +
      chalk.bold(toolHeaderRaw) +
      ' '.repeat(COL - toolHeaderRaw.length) +
      '  ' +
      chalk.bold(blockHeaderRaw)
  );
  console.log('  ' + chalk.dim('─'.repeat(COL)) + '  ' + chalk.dim('─'.repeat(COL)));

  const rows = Math.max(topTools.length, topBlocks.length, 1);
  for (let i = 0; i < rows; i++) {
    let leftStyled = ' '.repeat(COL);
    if (i < topTools.length) {
      const [tool, { calls }] = topTools[i];
      const label = tool.length > LABEL - 1 ? tool.slice(0, LABEL - 2) + '…' : tool;
      const countStr = num(calls).padStart(TOOL_COUNT_W);
      const b = colorBar(calls, maxTool, BAR);
      const rawLen = LABEL + BAR + 1 + TOOL_COUNT_W;
      const pad = Math.max(0, COL - rawLen);
      leftStyled =
        chalk.white(label.padEnd(LABEL)) + b + ' ' + chalk.white(countStr) + ' '.repeat(pad);
    }

    let rightStyled = '';
    if (i < topBlocks.length) {
      const [reason, count] = topBlocks[i];
      const readable = humanBlockReason(reason);
      const label = readable.length > LABEL - 1 ? readable.slice(0, LABEL - 2) + '…' : readable;
      const countStr = num(count).padStart(BLOCK_COUNT_W);
      const b = colorBar(count, maxBlock, BAR);
      rightStyled = chalk.white(label.padEnd(LABEL)) + b + ' ' + chalk.red(countStr);
    }

    console.log('  ' + leftStyled + '  ' + rightStyled);
  }

  if (topBlocks.length === 0) {
    console.log('  ' + ' '.repeat(COL) + '  ' + chalk.dim('nothing blocked ✓'));
  }

  // ── Agent breakdown ──
  if (agentMap.size >= 1) {
    console.log('');
    console.log('  ' + chalk.bold('Agents'));
    console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
    const maxAgent = Math.max(...agentMap.values(), 1);
    for (const [agent, count] of [...agentMap.entries()].sort((a, b) => b[1] - a[1])) {
      const label = agent.slice(0, LABEL - 1);
      const b = colorBar(count, maxAgent, BAR);
      console.log('  ' + chalk.white(label.padEnd(LABEL)) + b + ' ' + chalk.white(num(count)));
    }
  }

  // ── MCP Servers ──
  if (mcpMap.size > 0) {
    console.log('');
    console.log('  ' + chalk.bold('MCP Servers'));
    console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
    const maxMcp = Math.max(...mcpMap.values(), 1);
    for (const [server, count] of [...mcpMap.entries()].sort((a, b) => b[1] - a[1])) {
      const label = server.slice(0, LABEL - 1).padEnd(LABEL);
      const b = colorBar(count, maxMcp, BAR);
      console.log('  ' + chalk.white(label) + b + ' ' + chalk.white(num(count)));
    }
  }

  // ── Hour of Day ──
  if (hourMap.size > 0) {
    const BLOCKS = ' ▁▂▃▄▅▆▇█';
    const maxHour = Math.max(...hourMap.values(), 1);
    const bar = Array.from({ length: 24 }, (_, h) => {
      const v = hourMap.get(h) ?? 0;
      return BLOCKS[Math.round((v / maxHour) * 8)];
    }).join('');
    console.log('');
    console.log('  ' + chalk.bold('Hour of Day') + chalk.dim('  (local, 0h – 23h)'));
    console.log('  ' + chalk.cyan(bar));
    console.log('  ' + chalk.dim('0h' + ' '.repeat(10) + '12h' + ' '.repeat(7) + '23h'));
  }

  // ── Daily Activity ──
  if (dailyList.length > 1) {
    console.log('');
    console.log('  ' + chalk.bold('Daily Activity'));
    console.log('  ' + chalk.dim('─'.repeat(W - 2)));
    const DAY_BAR = Math.max(8, Math.min(30, W - 36));
    for (const [dateKey, { calls, blocked: db }] of dailyList) {
      const label = fmtDate(dateKey).padEnd(10);
      const b = colorBar(calls, maxDaily, DAY_BAR);
      const dayCost = costByDay.get(dateKey);
      const costNote = dayCost ? chalk.magenta(`  ${fmtCost(dayCost)}`) : '';
      const blockNote = db > 0 ? chalk.red(`  ${db} blocked`) : '';
      console.log(
        '  ' + chalk.dim(label) + '  ' + b + '  ' + chalk.white(num(calls)) + blockNote + costNote
      );
    }
  }

  // ── Tokens ──
  const totalTokens = costInputTokens + costOutputTokens + costCacheWrite + costCacheRead;
  if (totalTokens > 0) {
    const cacheHitPct =
      costInputTokens + costCacheRead > 0
        ? Math.round((costCacheRead / (costInputTokens + costCacheRead)) * 100)
        : 0;
    console.log('');
    console.log('  ' + chalk.bold('Tokens') + '  ' + chalk.dim(`${num(totalTokens)} total`));
    console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
    const TOK_BAR = Math.max(6, Math.min(20, W - 30));
    const TOK_LABEL = 14;
    const maxNonCache = Math.max(costInputTokens, costOutputTokens, costCacheWrite, 1);
    const nonCacheRows: Array<[string, number, string]> = [
      ['Input', costInputTokens, chalk.cyan(num(costInputTokens))],
      ['Output', costOutputTokens, chalk.white(num(costOutputTokens))],
      ['Cache write', costCacheWrite, chalk.yellow(num(costCacheWrite))],
    ];
    for (const [label, count, colored] of nonCacheRows) {
      if (count === 0) continue;
      const b = colorBar(count, maxNonCache, TOK_BAR);
      console.log('  ' + chalk.white(label.padEnd(TOK_LABEL)) + b + '  ' + colored);
    }
    if (costCacheRead > 0) {
      const cacheBar = colorBar(costCacheRead, costCacheRead, TOK_BAR);
      const pct = cacheHitPct > 0 ? chalk.dim(`  ${cacheHitPct}% hit rate`) : '';
      console.log(
        '  ' +
          chalk.white('Cache read'.padEnd(TOK_LABEL)) +
          cacheBar +
          '  ' +
          chalk.green(num(costCacheRead)) +
          pct
      );
    }
  }

  // ── Cost ──
  if (costUSD > 0) {
    const periodDays = Math.max(1, Math.ceil((end.getTime() - start.getTime()) / 86400000));
    const avgPerDay = costUSD / periodDays;
    const cacheHitPct =
      costInputTokens + costCacheRead > 0
        ? Math.round((costCacheRead / (costInputTokens + costCacheRead)) * 100)
        : 0;

    const costHeaderRight = [
      chalk.yellow(fmtCost(costUSD)),
      chalk.dim(`avg ${fmtCost(avgPerDay)}/day`),
      cacheHitPct > 0 ? chalk.dim(`${cacheHitPct}% cache hit`) : null,
    ]
      .filter(Boolean)
      .join(chalk.dim('  ·  '));

    console.log('');
    console.log('  ' + chalk.bold('Cost') + '  ' + costHeaderRight);
    console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));

    if (codexUSD > 0)
      costByModel.set('codex (openai)', (costByModel.get('codex (openai)') ?? 0) + codexUSD);
    if (geminiUSD > 0)
      costByModel.set('gemini (google)', (costByModel.get('gemini (google)') ?? 0) + geminiUSD);
    const modelList = [...costByModel.entries()].sort((a, b) => b[1] - a[1]);
    const maxModelCost = Math.max(...modelList.map(([, v]) => v), 1e-9);
    const MODEL_LABEL = 22;
    const MODEL_BAR = Math.max(6, Math.min(20, W - MODEL_LABEL - 12));
    for (const [model, cost] of modelList) {
      const label = model.length > MODEL_LABEL - 1 ? model.slice(0, MODEL_LABEL - 2) + '…' : model;
      const b = colorBar(cost, maxModelCost, MODEL_BAR);
      console.log(
        '  ' + chalk.white(label.padEnd(MODEL_LABEL)) + b + '  ' + chalk.yellow(fmtCost(cost))
      );
    }
  }

  // ── Response DLP ──
  if (responseDlpEntries.length > 0) {
    console.log('');
    console.log(
      '  ' +
        chalk.red.bold('⚠️  Response DLP') +
        chalk.dim('  ·  ') +
        chalk.red(
          `${responseDlpEntries.length} secret${responseDlpEntries.length !== 1 ? 's' : ''} found in Claude response text`
        )
    );
    console.log('  ' + chalk.dim('─'.repeat(Math.min(60, W - 4))));
    console.log(
      '  ' + chalk.yellow('These were NOT blocked — Claude included them in response prose.')
    );
    console.log('  ' + chalk.yellow('Rotate affected keys immediately.'));
    for (const e of responseDlpEntries.slice(0, 5)) {
      const ts = chalk.dim(fmtDate(e.ts) + '  ');
      const pattern = chalk.red(e.dlpPattern ?? 'DLP');
      const sample = chalk.gray(e.dlpSample ?? '');
      console.log(`    ${ts}${pattern}  ${sample}`);
    }
    if (responseDlpEntries.length > 5) {
      console.log(chalk.dim(`    … and ${responseDlpEntries.length - 5} more`));
    }
  }

  // ── Footer ──
  console.log('');
  console.log(
    '  ' +
      chalk.dim('node9 audit --deny') +
      chalk.dim('  ·  ') +
      chalk.dim('node9 report --period today|7d|30d|month  --no-tests')
  );
  console.log('');
}

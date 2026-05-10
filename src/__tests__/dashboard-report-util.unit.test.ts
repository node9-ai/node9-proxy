/**
 * Unit tests for the Report [2] panel utility helpers in
 * src/tui/dashboard/views/report/util.ts. These are pure formatters
 * the panels depend on; component-level rendering tests come later if
 * we add ink-testing-library.
 */
import { describe, it, expect } from 'vitest';
import {
  fitLabel,
  fmtCost,
  fmtShortDate,
  humanBlockReason,
  num,
  renderBar,
  sparkline,
} from '../tui/dashboard/views/report/util';

describe('renderBar', () => {
  it('renders all empty cells when value is 0', () => {
    expect(renderBar(0, 10, 5)).toBe('░░░░░');
  });

  it('renders all full cells when value equals max', () => {
    expect(renderBar(10, 10, 5)).toBe('█████');
  });

  it('renders proportional fill', () => {
    // 5 of 10 across 4 cells → round(0.5 * 4) = 2
    expect(renderBar(5, 10, 4)).toBe('██░░');
  });

  it('renders at least one cell when value > 0 (visibility floor)', () => {
    // Tiny ratio shouldn't disappear visually
    expect(renderBar(1, 1000, 10)).toBe('█░░░░░░░░░');
  });

  it('returns empty string when width <= 0', () => {
    expect(renderBar(5, 10, 0)).toBe('');
    expect(renderBar(5, 10, -3)).toBe('');
  });

  it('returns all-empty when max is 0', () => {
    expect(renderBar(0, 0, 4)).toBe('░░░░');
  });
});

describe('humanBlockReason', () => {
  it('maps known checkedBy values to human strings', () => {
    expect(humanBlockReason('timeout')).toBe('Popup timeout');
    expect(humanBlockReason('smart-rule-block')).toBe('Smart rule');
    expect(humanBlockReason('dlp-block')).toBe('DLP block');
    expect(humanBlockReason('loop-detected')).toBe('Loop detected');
  });

  it('passes through unmapped values unchanged', () => {
    expect(humanBlockReason('shield:project-jail:block-read-ssh')).toBe(
      'shield:project-jail:block-read-ssh'
    );
  });
});

describe('fmtCost', () => {
  it('renders zero as $0', () => {
    expect(fmtCost(0)).toBe('$0');
  });

  it('renders < $0.01 below the cent threshold', () => {
    expect(fmtCost(0.005)).toBe('< $0.01');
  });

  it('renders 3-digit precision below $1', () => {
    expect(fmtCost(0.42)).toBe('$0.420');
  });

  it('renders 2-digit precision $1–$99.99', () => {
    expect(fmtCost(4.23)).toBe('$4.23');
    expect(fmtCost(99.99)).toBe('$99.99');
  });

  it('renders rounded thousands above $100', () => {
    expect(fmtCost(1101.31)).toBe('$1,101');
    expect(fmtCost(11678.76)).toBe('$11,679');
  });
});

describe('fmtShortDate', () => {
  it('formats YYYY-MM-DD strings as Mon D', () => {
    expect(fmtShortDate('2026-05-10')).toBe('May 10');
  });

  it('formats Date objects as Mon D', () => {
    expect(fmtShortDate(new Date('2026-05-10T12:00:00'))).toBe('May 10');
  });
});

describe('fitLabel', () => {
  it('right-pads short labels to width', () => {
    expect(fitLabel('rm', 6)).toBe('rm    ');
  });

  it('truncates with ellipsis when too long', () => {
    expect(fitLabel('shield:project-jail:block-read-ssh', 10)).toBe('shield:pr…');
  });

  it('returns exactly width chars even when input is exact length', () => {
    expect(fitLabel('exactly10!', 10)).toBe('exactly10!');
  });
});

describe('num', () => {
  it('formats integers with thousand separators', () => {
    expect(num(0)).toBe('0');
    expect(num(1234)).toBe('1,234');
    expect(num(1234567)).toBe('1,234,567');
  });
});

describe('sparkline', () => {
  it('returns empty string for empty input', () => {
    expect(sparkline([])).toBe('');
  });

  it('renders one cell per value', () => {
    expect(sparkline([1, 2, 3, 4]).length).toBe(4);
  });

  it('renders the highest value as the full block', () => {
    const out = sparkline([1, 5, 10]);
    expect(out[2]).toBe('█'); // 10/10 → idx 8
  });

  it('renders zero values as a space (lowest cell)', () => {
    const out = sparkline([0, 8, 0]);
    expect(out[0]).toBe(' ');
    expect(out[2]).toBe(' ');
  });

  it('rounds to the nearest 1/8 step', () => {
    // values 0..8 of max=8 → block index 0..8
    const out = sparkline([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    expect(out).toBe(' ▁▂▃▄▅▆▇█');
  });

  it('handles single-value input (max becomes that value, full block)', () => {
    expect(sparkline([42])).toBe('█');
  });
});

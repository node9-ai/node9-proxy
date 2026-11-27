// src/mcp-gateway/definition-scan.ts
// The scan of an MCP server's tool definitions before the agent sees them
// (node9Firewall#342; add-ons plan phase 4, check C). The gateway passes every
// `tools/list` answer through here, on first connection and on every later
// one: a definition is text the model reads as instructions, and a pin made
// before this scan existed is not a pass.
//
// Pure over its input: no file, no network, no stdout. What it returns carries
// rule ids, counts and tool NAMES cut to a safe shape; never a description,
// a schema value or a matched secret.

import { scanText, scanToolDefinitionText, MAX_DEFINITION_CHARS } from '@node9/policy-engine';

export type DefinitionRule =
  | 'mcp.definition-injection'
  | 'mcp.definition-suspicious'
  | 'mcp.definition-secret'
  | 'mcp.definition-incomplete';

export interface DefinitionFinding {
  rule: DefinitionRule;
  severity: 'high' | 'medium';
  /** How many tools of the catalog carry it. */
  tools: number;
}

/** Why a catalog is refused under `block`, in the order checked. */
export type DefinitionBlockReason =
  'definition-injection' | 'definition-secret' | 'catalog-inspection-incomplete';

export interface CatalogScan {
  findings: DefinitionFinding[];
  /** Set when the catalog must not be trusted under `block`. */
  blockReason?: DefinitionBlockReason;
  /** Names of the tools behind `blockReason`, for the operator's terminal. */
  toolNames: string[];
  scanned: number;
}

/** Bounds from the content-gate design (mcp-content-gate/design.md, section 2).
 *  Past any of them the catalog is "incomplete", never "clean". */
const MAX_TOOLS = 2000;
const MAX_DEPTH = 32;
/** Per tool: one definition past this is incomplete, the others are still
 *  read. A catalog-wide budget would call a large honest server (hundreds of
 *  tools, enum-heavy schemas) incomplete as a whole. */
const MAX_NODES = 10_000;
/** The whole catalog: what one `tools/list` may cost to read at most. */
const MAX_CATALOG_NODES = 400_000;

const SAFE_NAME = /[^A-Za-z0-9_.:/-]/g;
function safeName(name: unknown): string {
  return typeof name === 'string' && name ? name.replace(SAFE_NAME, '?').slice(0, 64) : '(unnamed)';
}

class Budget {
  nodes = 0;
  exceeded = false;
}

/** Every string and every key under `v`, in order. Own properties only. */
function texts(v: unknown, out: string[], budget: Budget, depth = 0): void {
  if (budget.exceeded) return;
  if (depth > MAX_DEPTH || ++budget.nodes > MAX_NODES) {
    budget.exceeded = true;
    return;
  }
  if (typeof v === 'string') {
    out.push(v);
  } else if (Array.isArray(v)) {
    for (const x of v) texts(x, out, budget, depth + 1);
  } else if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) {
      out.push(k);
      texts((v as Record<string, unknown>)[k], out, budget, depth + 1);
    }
  }
}

/**
 * Scan one `tools/list` result. Injection is graded per tool, so two innocent
 * tools never add up to a finding. Secrets are looked for in each tool's text.
 *
 *   high-confidence injection  -> mcp.definition-injection (high), blocks
 *   medium-confidence          -> mcp.definition-suspicious (medium), recorded only
 *   a secret                   -> mcp.definition-secret (high), blocks
 *   past a bound               -> mcp.definition-incomplete (medium), blocks
 */
export function scanToolCatalog(tools: unknown): CatalogScan {
  const count: Record<DefinitionRule, number> = {
    'mcp.definition-injection': 0,
    'mcp.definition-suspicious': 0,
    'mcp.definition-secret': 0,
    'mcp.definition-incomplete': 0,
  };
  const names: Record<DefinitionBlockReason, string[]> = {
    'definition-injection': [],
    'definition-secret': [],
    'catalog-inspection-incomplete': [],
  };
  const list = Array.isArray(tools) ? tools : [];
  let catalogNodes = 0;
  let scanned = 0;
  if (!Array.isArray(tools) || list.length > MAX_TOOLS) {
    count['mcp.definition-incomplete']++;
    names['catalog-inspection-incomplete'].push('(catalog)');
  }
  for (const tool of list.slice(0, MAX_TOOLS)) {
    const name = safeName((tool as { name?: unknown } | null)?.name);
    const parts: string[] = [];
    const budget = new Budget();
    texts(tool, parts, budget);
    catalogNodes += budget.nodes;
    const text = parts.join('\n');
    if (budget.exceeded || text.length > MAX_DEFINITION_CHARS) {
      count['mcp.definition-incomplete']++;
      names['catalog-inspection-incomplete'].push(name);
      continue;
    }
    if (catalogNodes > MAX_CATALOG_NODES) {
      // Nothing from here on is read: the catalog as a whole is incomplete.
      count['mcp.definition-incomplete']++;
      names['catalog-inspection-incomplete'].push('(catalog)');
      break;
    }
    scanned++;
    const inj = scanToolDefinitionText(text);
    if (inj?.confidence === 'high') {
      count['mcp.definition-injection']++;
      names['definition-injection'].push(name);
    } else if (inj?.confidence === 'medium') {
      count['mcp.definition-suspicious']++;
    }
    if (scanText(text)) {
      count['mcp.definition-secret']++;
      names['definition-secret'].push(name);
    }
  }
  const findings: DefinitionFinding[] = [];
  const add = (rule: DefinitionRule, severity: 'high' | 'medium') => {
    if (count[rule] > 0) findings.push({ rule, severity, tools: count[rule] });
  };
  add('mcp.definition-injection', 'high');
  add('mcp.definition-secret', 'high');
  add('mcp.definition-incomplete', 'medium');
  add('mcp.definition-suspicious', 'medium');
  const blockReason: DefinitionBlockReason | undefined =
    names['definition-injection'].length > 0
      ? 'definition-injection'
      : names['definition-secret'].length > 0
        ? 'definition-secret'
        : names['catalog-inspection-incomplete'].length > 0
          ? 'catalog-inspection-incomplete'
          : undefined;
  return {
    findings,
    ...(blockReason ? { blockReason } : {}),
    toolNames: blockReason ? names[blockReason].slice(0, 10) : [],
    scanned,
  };
}

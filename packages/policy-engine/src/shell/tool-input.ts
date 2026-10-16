import { getNestedValue, matchesPattern } from '../rules';

export type ToolInspectionEntry = string | { kind: 'shell'; field: string };
export type ToolInspection = Record<string, ToolInspectionEntry>;
export type ShellInputResolution =
  | { kind: 'not-shell' }
  | { kind: 'uninspectable'; reason: string }
  | { kind: 'shell'; command: string; fieldPath: string };

export const BASH_TOOL_NAMES = new Set([
  'bash',
  'execute_bash',
  'run_shell_command',
  'shell',
  'exec_command',
]);
const MCP_EXECUTORS = new Set([...BASH_TOOL_NAMES, 'exec', 'run_command', 'terminal']);

export function isBashTool(tool: string): boolean {
  return BASH_TOOL_NAMES.has(tool.toLowerCase());
}

export function inspectionEntry(
  tool: string,
  inspection: ToolInspection = {}
): ToolInspectionEntry | undefined {
  const pattern = Object.keys(inspection).find((p) => matchesPattern(tool, p));
  return pattern === undefined ? undefined : inspection[pattern];
}

function shellFields(tool: string, inspection: ToolInspection): string[] | null {
  // Native adapters normalize their executable field to command. Configuration
  // must not redirect inspection of a native Bash call to a harmless decoy.
  if (isBashTool(tool)) return ['command'];
  const entry = inspectionEntry(tool, inspection);
  if (typeof entry === 'object') return [entry.field];
  if (entry !== undefined) return entry === 'command' ? [entry] : null;
  const name = tool.toLowerCase().replace(/^mcp__[a-z0-9_-]+?__/, '');
  return MCP_EXECUTORS.has(name) ? ['command', 'cmd', 'script'] : null;
}

export function isShellShapedTool(tool: string, inspection: ToolInspection = {}): boolean {
  return shellFields(tool, inspection) !== null;
}

export function resolveShellInput(
  tool: string,
  args: unknown,
  inspection: ToolInspection = {}
): ShellInputResolution {
  const fields = shellFields(tool, inspection);
  if (!fields) return { kind: 'not-shell' };
  const values = fields
    .map((fieldPath) => ({ fieldPath, value: getNestedValue(args, fieldPath) }))
    .filter(({ value }) => value !== undefined && value !== null && value !== '');
  if (!values.length || values.some(({ value }) => typeof value !== 'string')) {
    return { kind: 'uninspectable', reason: 'Shell command field is missing or is not a string' };
  }
  if (new Set(values.map(({ value }) => value)).size !== 1) {
    return { kind: 'uninspectable', reason: 'Multiple shell command fields disagree' };
  }
  return { kind: 'shell', command: values[0].value as string, fieldPath: values[0].fieldPath };
}

/** Only Bash-scoped rules receive the canonical projection. Caller data is never mutated. */
export function shellRuleArgs(
  tool: string,
  args: unknown,
  ruleTool: string | string[] | undefined,
  inspection: ToolInspection = {}
): unknown {
  if (!ruleTool || !matchesPattern('bash', ruleTool) || matchesPattern(tool, ruleTool)) return args;
  const resolved = resolveShellInput(tool, args, inspection);
  return resolved.kind === 'shell' && args && typeof args === 'object'
    ? { ...args, command: resolved.command }
    : args;
}

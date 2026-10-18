import { getNestedValue, matchesPattern } from '../rules';

export type ToolInspectionEntry = string | { kind: 'shell'; field: string };
export type ToolInspection = Record<string, ToolInspectionEntry>;
/**
 * Inspection mappings by provenance. `trusted` is the shipped defaults plus the
 * user's own and the workspace's entries, with full authority. `project` is a
 * repository-carried config file, which an agent can write in-session: it may
 * add a shell tool or a shell field, never turn a recognized executor into a
 * non-shell tool or point its inspection at a decoy field (fw#338, review 3).
 */
export interface InspectionLayers {
  trusted: ToolInspection;
  project?: ToolInspection;
}
/** A plain map is read as trusted with no project layer. */
export type InspectionInput = ToolInspection | InspectionLayers;
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
// Exact names only: `run` and `execute` also name SQL and workflow tools and
// need an explicit mapping.
const MCP_EXECUTORS = new Set([
  ...BASH_TOOL_NAMES,
  'exec',
  'run_command',
  'terminal',
  'execute_command',
  'execute_shell',
  'execute_shell_command',
  'shell_execute',
  'run_shell',
  'run_terminal_command',
  'start_process',
]);
const BUILTIN_FIELDS = ['command', 'cmd', 'script'];
const ARGV_FIELDS = ['args', 'argv'];
/** A word the shell reads literally; anything else is single-quoted. `=` stays quoted so a leading word is not read as an assignment. */
const BARE_WORD = /^[A-Za-z0-9_./+:@%,-]+$/;
/**
 * Joined argv beyond this is held for review instead of parsed: the AST is
 * markedly slower on megabytes of quoted words than on a native command of the
 * same size, and a hook past Claude Code's timeout fails open (review 3).
 */
export const MAX_ARGV_CHARACTERS = 262_144;

export function isBashTool(tool: string): boolean {
  return BASH_TOOL_NAMES.has(tool.toLowerCase());
}

/** The merged policy's maps as layers; the host keeps the project layer apart. */
export function inspectionLayers(policy: {
  toolInspection: ToolInspection;
  projectToolInspection?: ToolInspection;
}): InspectionLayers {
  return { trusted: policy.toolInspection, project: policy.projectToolInspection };
}

function isShellEntry(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { kind?: unknown }).kind === 'shell' &&
    typeof (value as { field?: unknown }).field === 'string' &&
    Object.keys(value).length === 2
  );
}

function isInspectionLayers(input: InspectionInput): input is InspectionLayers {
  // A map entry is a string or exactly `{ kind: 'shell', field }`; the layers
  // wrapper's `trusted` is a map, which is neither.
  const trusted = (input as InspectionLayers).trusted;
  return typeof trusted === 'object' && trusted !== null && !isShellEntry(trusted);
}

function layersOf(input: InspectionInput): Required<InspectionLayers> {
  return isInspectionLayers(input)
    ? { trusted: input.trusted, project: input.project ?? {} }
    : { trusted: input, project: {} };
}

function entryOf(tool: string, inspection: ToolInspection): ToolInspectionEntry | undefined {
  const pattern = Object.keys(inspection).find((p) => matchesPattern(tool, p));
  return pattern === undefined ? undefined : inspection[pattern];
}

/** The first matching entry, trusted layer first. For legacy (SQL, explain) lookups. */
export function inspectionEntry(
  tool: string,
  inspection: InspectionInput = {}
): ToolInspectionEntry | undefined {
  const { trusted, project } = layersOf(inspection);
  return entryOf(tool, trusted) ?? entryOf(tool, project);
}

/**
 * The tool's own name. For `mcp__<server>__<tool>` that is the text after the
 * last `__`: a server name may itself contain `__` or end in `_` (Claude Code
 * maps a `.` in the server name to `_`).
 */
function executorName(tool: string): string {
  const name = tool.toLowerCase();
  if (!name.startsWith('mcp__')) return name;
  const at = name.lastIndexOf('__');
  return at >= 'mcp__'.length ? name.slice(at + 2) : name;
}

function entryFields(entry: ToolInspectionEntry): string[] | null {
  if (typeof entry === 'object') return [entry.field];
  return entry === 'command' ? ['command'] : null;
}

function shellFields(tool: string, inspection: InspectionInput): string[] | null {
  // Native adapters normalize their executable field to command. Configuration
  // must not redirect inspection of a native Bash call to a harmless decoy.
  if (isBashTool(tool)) return ['command'];
  const { trusted, project } = layersOf(inspection);
  const trustedEntry = entryOf(tool, trusted);
  if (trustedEntry !== undefined) return entryFields(trustedEntry);
  const builtin = MCP_EXECUTORS.has(executorName(tool)) ? BUILTIN_FIELDS : null;
  const projectEntry = entryOf(tool, project);
  if (projectEntry === undefined) return builtin;
  const added = entryFields(projectEntry);
  // A repository file only adds inspection. On a recognized executor its shell
  // field joins the built-in ones (a decoy then disagrees and is held), and a
  // non-shell mapping is ignored.
  if (!builtin) return added;
  if (!added) return builtin;
  return [...new Set([...builtin, ...added])];
}

export function isShellShapedTool(tool: string, inspection: InspectionInput = {}): boolean {
  return shellFields(tool, inspection) !== null;
}

/** POSIX single quoting: nothing expands inside, so the joined line means what `spawn(command, args)` runs. */
function shellWord(word: string): string {
  if (BARE_WORD.test(word)) return word;
  return word === '' ? "''" : `'${word.replace(/'/g, `'\\''`)}'`;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

type CommandLine = { command: string; fieldPath: string } | { reason: string };

/**
 * The command line the executor runs for the value at `fieldPath`. A sibling
 * `args` / `argv` array of strings is joined onto a string command, and the
 * field itself may be the argv array; any other shape cannot be read. A native
 * Bash alias keeps its adapter-normalized string `command` and joins only a
 * string-array sibling: any other extra field is the agent's own and must not
 * hold every native call. The gateway authorizes upstream tools by their bare
 * name, so a server tool called `shell` or `bash` takes this path too.
 */
function commandLine(
  args: unknown,
  fieldPath: string,
  value: unknown,
  native: boolean
): CommandLine {
  const missing = { reason: 'Shell command field is missing or is not a string' };
  const unreadable = { reason: 'Shell command arguments could not be read' };
  if (typeof value !== 'string' && (native || !Array.isArray(value))) return missing;
  const dot = fieldPath.lastIndexOf('.');
  const parent = dot === -1 ? args : getNestedValue(args, fieldPath.slice(0, dot));
  const siblings = ARGV_FIELDS.map((key) => ({
    key,
    value:
      parent && typeof parent === 'object' ? (parent as Record<string, unknown>)[key] : undefined,
  })).filter(({ value }) => value !== undefined && value !== null);
  let argv: { key: string; value: unknown } | undefined = siblings[0];
  if (native) argv = siblings.find(({ value: v }) => isStringArray(v));
  else if (
    siblings.length === 2 &&
    JSON.stringify(siblings[0].value) !== JSON.stringify(siblings[1].value)
  )
    return { reason: 'Shell command arguments disagree' };
  let command: string;
  let source = fieldPath;
  if (Array.isArray(value)) {
    if (argv || !value.length || !isStringArray(value)) return unreadable;
    command = value.map(shellWord).join(' ');
  } else if (!argv) {
    return { command: value, fieldPath };
  } else {
    if (!isStringArray(argv.value)) return unreadable;
    if (!argv.value.length) return { command: value, fieldPath };
    command = `${value} ${argv.value.map(shellWord).join(' ')}`;
    source = `${fieldPath}+${argv.key}`;
  }
  if (command.length > MAX_ARGV_CHARACTERS)
    return { reason: 'Shell command arguments exceed the inspectable size' };
  return { command, fieldPath: source };
}

export function resolveShellInput(
  tool: string,
  args: unknown,
  inspection: InspectionInput = {}
): ShellInputResolution {
  const fields = shellFields(tool, inspection);
  if (!fields) return { kind: 'not-shell' };
  const values = fields
    .map((fieldPath) => ({ fieldPath, value: getNestedValue(args, fieldPath) }))
    .filter(({ value }) => value !== undefined && value !== null && value !== '');
  if (!values.length) {
    return { kind: 'uninspectable', reason: 'Shell command field is missing or is not a string' };
  }
  const native = isBashTool(tool);
  const lines = values.map(({ fieldPath, value }) => commandLine(args, fieldPath, value, native));
  const failed = lines.find((line): line is { reason: string } => 'reason' in line);
  if (failed) return { kind: 'uninspectable', reason: failed.reason };
  const commands = lines.filter(
    (line): line is { command: string; fieldPath: string } => 'command' in line
  );
  if (new Set(commands.map(({ command }) => command)).size !== 1) {
    return { kind: 'uninspectable', reason: 'Multiple shell command fields disagree' };
  }
  return { kind: 'shell', ...commands[0] };
}

/** Only Bash-scoped rules receive the canonical projection. Caller data is never mutated. */
export function shellRuleArgs(
  tool: string,
  args: unknown,
  ruleTool: string | string[] | undefined,
  inspection: InspectionInput = {}
): unknown {
  if (!ruleTool || !matchesPattern('bash', ruleTool) || matchesPattern(tool, ruleTool)) return args;
  const resolved = resolveShellInput(tool, args, inspection);
  return resolved.kind === 'shell' && args && typeof args === 'object'
    ? { ...args, command: resolved.command }
    : args;
}

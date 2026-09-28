import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, getCredentials, _resetConfigCache } from '../config';
import { patchConfig } from '../config/patch';
import { isKeyedForPolicy } from '../config/keyed-guard';
import { readActiveShields, writeActiveShields, migrateRenamedRuleKeys } from '../shields';
import { setEgress } from '../auth/egress-config';
import { isDaemonRunning } from '../auth/daemon';
import { getAgentWiring } from '../agent-wiring';
import {
  installDaemonService,
  uninstallDaemonService,
  isDaemonServiceInstalled,
  isDaemonServiceEnabled,
} from '../daemon/service';
import { atomicWriteSync } from '../utils/atomic-write';
import { safeMessage } from '../utils/safe-text';
import { autoStartDaemonAndWait, isTestingMode } from './daemon-starter';
import { askTelemetry, ensureConfig, wireDetectedAgents } from './commands/init';
import { invalidConfig, isCI, isInteractive, mayChangeService, SetupError } from './interactive';

export const DEFAULT_SHIELDS = ['bash-safe', 'filesystem', 'project-jail'];
export type ChecklistKey = 'shields' | 'dlp' | 'egress' | 'service';
export type SettingState = 'on' | 'off' | 'partial';
export interface LocalState {
  fresh: boolean;
  managed: boolean;
  shields: SettingState;
  dlp: SettingState;
  egressEnabled: boolean;
  serviceInstalled: boolean;
  serviceEnabled: boolean;
  mode: string;
}
export interface ChecklistItem {
  key: ChecklistKey;
  label: string;
  hint: string;
  checked: boolean;
  partial: boolean;
  disabled?: string;
}
export interface LocalChange {
  key: ChecklistKey;
  from: SettingState;
  to: boolean;
}
export interface AppliedChange {
  key: string;
  ok: boolean;
  detail: string;
}
export interface SetupSummary {
  agents: Array<{ name: string; wired: boolean; file: string }>;
  applied: AppliedChange[];
  state: LocalState;
  serviceRunning: boolean;
  cloud: 'none' | 'configured';
}
function configPath(): string {
  return path.join(os.homedir(), '.node9', 'config.json');
}
function combined(values: boolean[]): SettingState {
  return values.every(Boolean) ? 'on' : values.some(Boolean) ? 'partial' : 'off';
}
export function readLocalState(opts: { replaceConfig?: boolean } = {}): LocalState {
  const file = configPath();
  // Do not hide malformed user configuration behind getConfig's tolerant loader.
  if (fs.existsSync(file) && !opts.replaceConfig) {
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      raw = undefined;
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw invalidConfig();
  }
  // Global state only: getConfig skips the project layer for a directory with
  // no node9.config.json, and ~/.node9 never holds one.
  const config = getConfig(path.join(os.homedir(), '.node9'));
  const active = readActiveShields();
  const installed = isDaemonServiceInstalled();
  return {
    fresh: !fs.existsSync(file),
    managed: config.policySource === 'workspace',
    shields: combined(DEFAULT_SHIELDS.map((s) => active.includes(s))),
    dlp: combined([config.policy.dlp.enabled, config.policy.dlp.pii !== 'off']),
    egressEnabled: config.policy.egress.enabled,
    serviceInstalled: installed,
    serviceEnabled: installed && isDaemonServiceEnabled(),
    mode: config.settings.mode,
  };
}
function actual(state: LocalState, key: ChecklistKey): SettingState {
  if (key === 'shields' || key === 'dlp') return state[key];
  return (key === 'egress' ? state.egressEnabled : state.serviceInstalled && state.serviceEnabled)
    ? 'on'
    : 'off';
}
export function buildChecklist(state: LocalState): ChecklistItem[] {
  const labels: Record<ChecklistKey, [string, string]> = {
    shields: [
      'Recommended shields',
      'bash-safe, filesystem, project-jail; other protections stay separate',
    ],
    dlp: ['DLP and PII', 'Inspect tool arguments for credentials and personal data'],
    egress: ['Egress', 'Review unknown destinations (node9 egress watch)'],
    service: [
      'Background service',
      'Keeps approval prompts and policy sync available without an open terminal; uncheck to remove autostart',
    ],
  };
  return (Object.keys(labels) as ChecklistKey[]).map((key) => ({
    key,
    label: labels[key][0],
    hint: labels[key][1],
    checked: state.fresh && !state.managed ? key !== 'egress' : actual(state, key) === 'on',
    partial: actual(state, key) === 'partial',
    ...(state.managed && key !== 'service' ? { disabled: 'managed by your workspace' } : {}),
  }));
}
/** Partial rows stay unchanged unless the user explicitly chooses all on/off. */
export function diffChoices(
  state: LocalState,
  selected: ChecklistKey[],
  partial: Partial<Record<ChecklistKey, boolean>> = {}
): LocalChange[] {
  return buildChecklist(state).flatMap((item) => {
    if (item.disabled) return [];
    const from = actual(state, item.key);
    if (from === 'partial' && partial[item.key] === undefined && !selected.includes(item.key))
      return [];
    const to = partial[item.key] ?? selected.includes(item.key);
    return from === (to ? 'on' : 'off') ? [] : [{ key: item.key, from, to }];
  });
}
function setAutostart(enabled: boolean): void {
  const file = configPath();
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (raw.settings?.autoStartDaemon === enabled) return;
  raw.settings = { ...raw.settings, autoStartDaemon: enabled };
  atomicWriteSync(file, JSON.stringify(raw, null, 2) + '\n', { mode: 0o600 });
}
export async function applyChanges(changes: LocalChange[]): Promise<AppliedChange[]> {
  const applied: AppliedChange[] = [];
  for (const change of changes) {
    try {
      if (change.key !== 'service' && isKeyedForPolicy())
        throw new Error('Policy is managed by your workspace');
      if (change.key === 'shields') {
        const active = readActiveShields();
        writeActiveShields(
          change.to
            ? [...new Set([...active, ...DEFAULT_SHIELDS])]
            : active.filter((s) => !DEFAULT_SHIELDS.includes(s))
        );
      } else if (change.key === 'dlp') {
        patchConfig(configPath(), {
          type: 'dlp',
          enabled: change.to,
          pii: change.to ? 'block' : 'off',
        });
      } else if (change.key === 'egress') {
        setEgress({ enabled: change.to, mode: change.to ? 'review' : 'off' });
      } else {
        if (isTestingMode()) {
          applied.push({
            key: change.key,
            ok: true,
            detail: 'Service operation skipped (testing mode)',
          });
          continue;
        }
        const result = change.to ? installDaemonService() : uninstallDaemonService();
        if (!result.ok) throw new Error(result.reason);
        setAutostart(change.to);
        _resetConfigCache();
        if (change.to && !(await autoStartDaemonAndWait()))
          throw new Error(
            'Service installed, but the daemon is not ready. Run node9 daemon status.'
          );
      }
      applied.push({ key: change.key, ok: true, detail: change.to ? 'enabled' : 'disabled' });
    } catch (error) {
      applied.push({ key: change.key, ok: false, detail: safeMessage(error) });
    }
    _resetConfigCache();
  }
  return applied;
}
export function renderSummary(s: SetupSummary): string {
  const lines = [s.applied.some((a) => !a.ok) ? 'Setup needs attention' : 'Setup complete'];
  if (!s.agents.some((a) => a.wired))
    lines.push('  No agents wired yet. Run node9 setup <target> after installing your agent.');
  for (const a of s.agents)
    lines.push(`  ${a.name}: ${a.wired ? 'configured' : 'not configured'} (${a.file})`);
  lines.push(`  Mode: ${s.state.mode}`);
  lines.push(
    `  Recommended shields: ${s.state.managed ? 'managed by your workspace' : s.state.shields}`
  );
  lines.push(
    `  DLP and PII: ${s.state.dlp}${s.state.managed ? ' (managed by your workspace)' : ''}`
  );
  lines.push(
    `  Egress: ${s.state.egressEnabled ? 'on' : s.state.managed ? 'off (managed by your workspace)' : 'off (turn on: node9 egress watch)'}`
  );
  lines.push(
    `  Service: ${s.serviceRunning ? 'running' : 'not running'}; ${s.state.serviceEnabled ? 'starts on login' : 'autostart not enabled'}`
  );
  lines.push(`  Dashboard: ${s.cloud}`);
  for (const a of s.applied)
    if (!a.ok || a.detail.includes('skipped')) lines.push(`  ${a.key}: ${a.detail}`);
  lines.push('', 'Remove Node9 integrations: node9 uninstall', 'Watch live: node9 monitor');
  return lines.join('\n');
}
export function collectSummary(applied: AppliedChange[]): SetupSummary {
  const state = readLocalState();
  return {
    applied,
    state,
    serviceRunning: isDaemonRunning(),
    cloud: getCredentials() ? 'configured' : 'none',
    agents: getAgentWiring()
      .filter((a) => a.installed || a.present)
      .map((a) => ({
        name: a.label,
        wired: a.isProtected,
        file: a.settingsPath,
      })),
  };
}
export async function runLocalSetup(opts: {
  interactive: boolean;
  recommended?: boolean;
  mode?: string;
  force?: boolean;
  skipSetup?: boolean;
}): Promise<SetupSummary> {
  const interactive = opts.interactive && isInteractive() && !opts.recommended;
  let state = readLocalState({ replaceConfig: opts.force });
  if (state.managed && (opts.force || opts.mode || opts.recommended)) {
    throw new SetupError('Policy is managed by your workspace. Change it in the dashboard.');
  }
  if (opts.mode && !['standard', 'strict', 'audit', 'observe'].includes(opts.mode.toLowerCase())) {
    throw new SetupError('Mode must be standard, strict, audit, or observe.');
  }
  const firstInstall = state.fresh;
  const items = buildChecklist(state).filter((i) => !opts.skipSetup || i.key !== 'service');
  let selected = items.filter((i) => i.checked).map((i) => i.key);
  const partial: Partial<Record<ChecklistKey, boolean>> = {};
  if (interactive) {
    const { checkbox, select } = await import('@inquirer/prompts');
    selected = await checkbox<ChecklistKey>({
      message: 'Choose protection for this machine',
      choices: items.map((i) => ({
        name: `${i.label}${i.partial ? ' (partly on)' : ''}`,
        value: i.key,
        description: i.hint,
        checked: i.checked,
        disabled: i.disabled || (i.partial ? 'choose below; currently partly on' : false),
      })),
    });
    for (const item of items.filter((i) => i.partial && !i.disabled)) {
      const choice = await select({
        message: `${item.label} is partly on`,
        choices: [
          { name: 'Keep current settings', value: 'keep' },
          { name: 'Enable all', value: 'on' },
          { name: 'Disable all', value: 'off' },
        ],
      });
      if (choice !== 'keep') partial[item.key] = choice === 'on';
    }
  } else if (!state.fresh) {
    selected = items.filter((i) => actual(state, i.key) === 'on').map((i) => i.key);
  }
  if (opts.recommended && !state.managed) {
    if (!selected.includes('shields')) selected.push('shields');
    partial.shields = true;
  }
  // Explicit mode wins; otherwise selecting recommended shields requests standard.
  const enableShields = selected.includes('shields') || partial.shields === true;
  const mode = state.managed
    ? undefined
    : (opts.mode?.toLowerCase() ??
      (state.fresh || opts.recommended || (enableShields && state.shields !== 'on')
        ? 'standard'
        : undefined));
  // No mutation occurs until every configuration question has been answered.
  if (!state.managed) {
    ensureConfig(mode, opts.force);
    for (const m of migrateRenamedRuleKeys())
      console.log(`Rule renamed: ${m.oldKey} -> ${m.newKey}`);
  }
  // --force resets the config: compare choices with that new actual state.
  if (opts.force) state = readLocalState();
  // Filter the changes, not the selection: an unselected service on an existing
  // machine would otherwise read as "remove it". CI, Docker builds, pipes and
  // agents never install or remove a login service (the pre-wizard init gate).
  const serviceAllowed = mayChangeService({
    stdoutTTY: !!process.stdout.isTTY,
    ci: isCI(),
    skipSetup: opts.skipSetup,
  });
  const planned = diffChoices(state, selected, partial);
  const changes = planned.filter((c) => c.key !== 'service' || serviceAllowed);
  const applied = await applyChanges(changes);
  if (!opts.skipSetup && planned.some((c) => c.key === 'service' && c.to && !serviceAllowed)) {
    applied.push({
      key: 'service',
      ok: true,
      detail: 'skipped without a terminal. Install it later: node9 daemon install',
    });
  }
  let agents: string[] = [];
  if (!opts.skipSetup) {
    try {
      agents = await wireDetectedAgents();
    } catch (error) {
      applied.push({ key: 'agents', ok: false, detail: safeMessage(error) });
    }
  }
  if (applied.some((a) => !a.ok)) process.exitCode = 1;
  if (interactive && !state.managed && !opts.skipSetup) await askTelemetry(agents, firstInstall);
  return collectSummary(applied);
}

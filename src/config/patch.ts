// src/config/patch.ts
// Config patcher: adds a smart rule or an ignored tool, or sets the DLP
// switches, in a project or global config file. Goes through the one config
// writer (write.ts), so the file keeps its format and the write is locked
// and atomic.
import path from 'path';
import os from 'os';
import type { SmartRule } from './index.js';
import { writeConfigFile } from './write';

export type ConfigPatch =
  | { type: 'smartRule'; rule: SmartRule }
  | { type: 'ignoredTool'; toolName: string }
  | { type: 'dlp'; enabled: boolean; pii: 'off' | 'block' };

export const GLOBAL_CONFIG_PATH = path.join(os.homedir(), '.node9', 'config.json');

/**
 * Apply a patch to a config file. Creates the file (and parent dirs) if it
 * does not exist. A file that cannot be read is never overwritten.
 */
export function patchConfig(configPath: string, patch: ConfigPatch): void {
  try {
    writeConfigFile(configPath, (config) => {
      const policy = (config.policy ??= {});
      if (patch.type === 'smartRule') {
        const rules = (policy.smartRules ??= []);
        // Deduplicate by name: never add the same rule twice.
        if (patch.rule.name && rules.some((r) => r.name === patch.rule.name)) return;
        rules.push(patch.rule as (typeof rules)[number]);
      } else if (patch.type === 'dlp') {
        policy.dlp = { ...(policy.dlp ?? {}), enabled: patch.enabled, pii: patch.pii };
      } else {
        const ignored = (policy.ignoredTools ??= []);
        if (!ignored.includes(patch.toolName)) ignored.push(patch.toolName);
      }
    });
  } catch (err) {
    if (/not valid JSON|not a JSON object/.test((err as Error).message))
      throw new Error(`Cannot read config at ${configPath} — file may be corrupted`);
    throw err;
  }
}

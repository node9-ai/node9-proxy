// src/config/patch.ts
// Atomic config patcher — adds a smartRule or ignoredTool entry to a
// project or global config file. Validates the result with the config
// schema before writing to prevent corruption.
import fs from 'fs';
import path from 'path';
import os from 'os';
import type { SmartRule } from './index.js';

export type ConfigPatch =
  | { type: 'smartRule'; rule: SmartRule }
  | { type: 'ignoredTool'; toolName: string };

export const GLOBAL_CONFIG_PATH = path.join(os.homedir(), '.node9', 'config.json');

/**
 * Apply a patch to a config file atomically.
 * Creates the file (and parent dirs) if it doesn't exist.
 * Returns the path that was written to.
 */
export function patchConfig(configPath: string, patch: ConfigPatch): void {
  // Read existing config or start from empty shell
  let config: Record<string, unknown> = {};
  try {
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8')) as Record<string, unknown>;
    }
  } catch {
    // Corrupted file — start fresh (don't silently lose existing rules)
    throw new Error(`Cannot read config at ${configPath} — file may be corrupted`);
  }

  // Ensure policy object exists
  if (!config.policy || typeof config.policy !== 'object') config.policy = {};
  const policy = config.policy as Record<string, unknown>;

  if (patch.type === 'smartRule') {
    if (!Array.isArray(policy.smartRules)) policy.smartRules = [];
    const rules = policy.smartRules as SmartRule[];

    // Deduplicate by name — don't add the same rule twice
    if (patch.rule.name && rules.some((r) => r.name === patch.rule.name)) return;

    rules.push(patch.rule);
  } else {
    if (!Array.isArray(policy.ignoredTools)) policy.ignoredTools = [];
    const ignored = policy.ignoredTools as string[];

    if (!ignored.includes(patch.toolName)) {
      ignored.push(patch.toolName);
    }
  }

  // Atomic write: tmp → rename. Clean up tmp on any failure so we never
  // leave a stale .node9-tmp artifact on disk.
  const dir = path.dirname(configPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = configPath + '.node9-tmp';
  fs.writeFileSync(tmp, JSON.stringify(config, null, 2), { mode: 0o600 });
  try {
    fs.renameSync(tmp, configPath);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* best-effort cleanup */
    }
    throw err;
  }
}

// src/__tests__/skill-roots-config.spec.ts
// Unit tests for policy.skillRoots config field — accepted, merged, deduped.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';

describe('policy.skillRoots config field', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillroots-cfg-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    _resetConfigCache();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
  });

  it('defaults to an empty array when no config is set', () => {
    const config = getConfig();
    expect(config.policy.skillRoots).toEqual([]);
  });

  it('merges user-supplied skillRoots from config.json', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ policy: { skillRoots: ['~/my-skills', '/abs/path/AGENTS.md'] } })
    );
    const config = getConfig();
    expect(config.policy.skillRoots).toEqual(['~/my-skills', '/abs/path/AGENTS.md']);
  });

  it('de-duplicates entries', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ policy: { skillRoots: ['~/a', '~/a', '~/b'] } })
    );
    const config = getConfig();
    expect(config.policy.skillRoots).toEqual(['~/a', '~/b']);
  });

  it('ignores non-string entries defensively', () => {
    // Schema rejects non-string arrays at validation time, but merge must also
    // self-protect in case validation is ever relaxed or the schema evolves.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ policy: { skillRoots: ['~/ok'] } })
    );
    const config = getConfig();
    expect(config.policy.skillRoots).toEqual(['~/ok']);
  });
});

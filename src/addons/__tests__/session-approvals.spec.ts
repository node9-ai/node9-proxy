// One ask per add-on per session in the agent hook (node9Firewall#376 item 6).
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { addonApprovedForSession, approveAddonForSession } from '../session-approvals';

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});
function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-addon-sessions-'));
  homes.push(h);
  return h;
}

describe('add-on approvals per session', () => {
  it('holds for the session it was given in, for that add-on only', () => {
    const h = home();
    expect(addonApprovedForSession('s1', 'addon:skill:deploy', h)).toBe(false);
    approveAddonForSession('s1', 'addon:skill:deploy', h);
    expect(addonApprovedForSession('s1', 'addon:skill:deploy', h)).toBe(true);
    expect(addonApprovedForSession('s1', 'addon:skill:other', h)).toBe(false);
    expect(addonApprovedForSession('s2', 'addon:skill:deploy', h)).toBe(false);
  });

  it('ignores a session id that is not a plain name, and follows no planted link', () => {
    const h = home();
    approveAddonForSession('../escape', 'addon:skill:x', h);
    expect(fs.existsSync(path.join(h, '.node9', 'addon-sessions'))).toBe(false);
    // ~/.node9/addon-sessions planted as a link to somewhere else.
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-elsewhere-'));
    homes.push(elsewhere);
    fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
    fs.symlinkSync(elsewhere, path.join(h, '.node9', 'addon-sessions'));
    approveAddonForSession('s1', 'addon:skill:x', h);
    expect(fs.readdirSync(elsewhere)).toEqual([]);
  });
});

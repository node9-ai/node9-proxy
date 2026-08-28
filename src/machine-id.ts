import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// The machine's durable local identity (login-v2 B1): a UUID minted once and
// kept in ~/.node9/machine-id. The cloud upserts the machine row by
// (workspaceId, machineId), so as long as this file survives, re-logins and
// reinstalls keep the same dashboard identity instead of minting ghosts.
// Deliberately NOT hostname-derived: hostnames change, collide, and are
// PII-adjacent — this file ships nothing about the machine by itself.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function getMachineId(homeDir: string = os.homedir()): string {
  const file = path.join(homeDir, '.node9', 'machine-id');
  try {
    const existing = fs.readFileSync(file, 'utf-8').trim();
    if (UUID_RE.test(existing)) return existing;
    // Corrupt content falls through to re-mint — a stable-but-garbage id
    // would collide across machines that copied the same broken file.
  } catch {
    // Missing — first run.
  }
  const id = crypto.randomUUID();
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, id + '\n', { mode: 0o600 });
  } catch {
    // Unwritable home: still return a usable id for this session. The next
    // login mints a fresh one, which the server treats as a new machine —
    // imperfect, but never blocks the login itself.
  }
  return id;
}

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// Shared credential + config writer — used by both `node9 login` and the
// onboarding `node9 connect`. Writes ~/.node9/credentials.json (profile-merged,
// 0o600) and, for the default profile, the ~/.node9/config.json approvers block.
// Returns the effective cloud state so callers can print the right message.
const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept';

export function writeCredentialsAndConfig(
  apiKey: string,
  opts: { profileName?: string; isLocal?: boolean; homeDir?: string } = {}
): { profileName: string; effectiveCloud: boolean | null } {
  const profileName = opts.profileName || 'default';
  const home = opts.homeDir ?? os.homedir();

  const credPath = path.join(home, '.node9', 'credentials.json');
  if (!fs.existsSync(path.dirname(credPath))) {
    fs.mkdirSync(path.dirname(credPath), { recursive: true });
  }
  let existingCreds: Record<string, unknown> = {};
  try {
    if (fs.existsSync(credPath)) {
      const raw = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
      // Migrate the legacy single-key shape into the profile map.
      existingCreds = raw.apiKey
        ? { default: { apiKey: raw.apiKey, apiUrl: raw.apiUrl || DEFAULT_API_URL } }
        : raw;
    }
  } catch {
    // Corrupt creds file — overwrite rather than fail the login/connect.
  }
  existingCreds[profileName] = { apiKey, apiUrl: DEFAULT_API_URL };
  fs.writeFileSync(credPath, JSON.stringify(existingCreds, null, 2), {
    mode: 0o600,
  });

  // The approvers block lives on the default profile only.
  let effectiveCloud: boolean | null = null;
  if (profileName === 'default') {
    const configPath = path.join(home, '.node9', 'config.json');
    let config: Record<string, unknown> = {};
    try {
      if (fs.existsSync(configPath)) {
        config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
      }
    } catch {
      // Corrupt config — start fresh.
    }
    if (!config.settings || typeof config.settings !== 'object') {
      config.settings = {};
    }
    const s = config.settings as Record<string, unknown>;
    const approvers = (s.approvers as Record<string, unknown>) || {
      native: true,
      browser: true,
      cloud: true,
      terminal: true,
    };
    // Only force cloud off when --local is explicit; otherwise preserve the
    // user's prior choice (re-running login to refresh a key must not silently
    // re-enable cloud approvals for someone who turned them off).
    if (opts.isLocal) {
      approvers.cloud = false;
    }
    s.approvers = approvers;
    if (!fs.existsSync(path.dirname(configPath))) {
      fs.mkdirSync(path.dirname(configPath), { recursive: true });
    }
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), {
      mode: 0o600,
    });
    effectiveCloud = approvers.cloud === true;
  }

  return { profileName, effectiveCloud };
}

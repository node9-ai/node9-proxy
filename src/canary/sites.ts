// The three plant sites. Each names a primary and a fallback path, and node9
// creates a NEW file at whichever is absent, never touching an existing one
// (rule zero, design 4.3). Paths are computed per call from the home given.
import fs from 'fs';
import path from 'path';
import type { CanaryKind } from './registry';
import {
  generateAwsProfile,
  generateEnvFile,
  generateSshKey,
  type GeneratedSite,
} from './generate';

export interface Site {
  kind: CanaryKind;
  primary: (home: string) => string;
  fallback: (home: string) => string;
  /** H20: on this machine the primary would be a file real tools parse even
   *  though it is absent now; use the fallback. */
  preferFallback?: (home: string) => boolean;
  /** Mode for a parent directory node9 has to create. */
  dirMode: number;
  generate: () => GeneratedSite;
}

export const SITES: Record<CanaryKind, Site> = {
  'aws-profile': {
    kind: 'aws-profile',
    primary: (h) => path.join(h, '.aws', 'credentials'),
    fallback: (h) => path.join(h, '.aws', 'credentials.bak'),
    // SSO / profile-only / credential_process setups have ~/.aws/config and no
    // credentials file; the SDK and CLI then parse ~/.aws/credentials on every
    // profile lookup. A planted primary would be a file real tools read.
    preferFallback: (h) => fs.existsSync(path.join(h, '.aws', 'config')),
    dirMode: 0o700,
    generate: generateAwsProfile,
  },
  'env-file': {
    kind: 'env-file',
    primary: (h) => path.join(h, '.env.bak'),
    fallback: (h) => path.join(h, '.env.local.bak'),
    dirMode: 0o755,
    generate: generateEnvFile,
  },
  'ssh-key': {
    kind: 'ssh-key',
    primary: (h) => path.join(h, '.ssh', 'id_rsa_backup'),
    fallback: (h) => path.join(h, '.ssh', 'id_rsa.old'),
    // ssh refuses a group-writable ~/.ssh for config / known_hosts reads.
    dirMode: 0o700,
    generate: generateSshKey,
  },
};

export const ALL_KINDS: readonly CanaryKind[] = ['aws-profile', 'env-file', 'ssh-key'];
export const isKind = (s: string): s is CanaryKind => (ALL_KINDS as readonly string[]).includes(s);

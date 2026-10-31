// The credential files an agent on this machine can reach: ONE list, read by
// `node9 blast` and by posture's Secrets check (fw#408). Before, blast kept 13
// paths and posture 6, and each report named different files (blast listed
// gcloud `credentials.db`, posture `application_default_credentials.json`).
//
// `kind: 'credential'` is key or token material; `kind: 'config'` is account
// configuration that blast weighs lightly and posture does not report.

import path from 'path';

export interface CredentialFile {
  /** Absolute path under the given home. */
  full: string;
  /** Home-relative label for display; never the absolute path. */
  label: string;
  description: string;
  /** Points blast deducts when the file is readable. */
  score: number;
  kind: 'credential' | 'config';
}

export function homeCredentialFiles(home: string): CredentialFile[] {
  const f = (
    parts: string[],
    description: string,
    score: number,
    kind: CredentialFile['kind'] = 'credential'
  ): CredentialFile => ({
    full: path.join(home, ...parts),
    label: '~/' + parts.join('/'),
    description,
    score,
    kind,
  });
  return [
    f(['.ssh', 'id_rsa'], 'RSA private key: grants SSH access to your servers', 20),
    f(['.ssh', 'id_ed25519'], 'Ed25519 private key: grants SSH access to your servers', 20),
    f(['.ssh', 'id_ecdsa'], 'ECDSA private key: grants SSH access to your servers', 20),
    f(['.ssh', 'id_dsa'], 'DSA private key: grants SSH access to your servers', 20),
    f(['.aws', 'credentials'], 'AWS access keys: full cloud account access', 20),
    f(['.aws', 'config'], 'AWS configuration: account and region settings', 5, 'config'),
    f(['.config', 'gcloud', 'credentials.db'], 'Google Cloud credentials', 15),
    f(
      ['.config', 'gcloud', 'application_default_credentials.json'],
      'Google Cloud application default credentials',
      15
    ),
    f(['.docker', 'config.json'], 'Docker registry auth tokens', 10),
    f(['.netrc'], 'FTP/HTTP credentials in plain text', 15),
    f(['.npmrc'], 'npm auth token: can publish packages as you', 10),
  ];
}

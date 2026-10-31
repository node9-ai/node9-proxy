// Two project-jail rules were over the runtime's 256-character regex cap
// (node9Firewall#390, design section 20): the runtime read them as no match.
// The file-access twins (`-any-tool`) kept the gate right, so these tests
// judge each bash rule ON ITS OWN, which is what failed before the fix.
import { describe, it, expect } from 'vitest';
import { BUILTIN_SHIELDS } from './index';
import { evaluateSmartConditions } from '../rules';
import { validateRegex } from '../utils/regex';

const jail = BUILTIN_SHIELDS['project-jail'];
const rule = (name: string) => jail.smartRules.find((r) => r.name === name)!;
const meets = (name: string, command: string) => evaluateSmartConditions({ command }, rule(name));

// The patterns as they were (too long for the runtime), to prove the short
// ones say the same thing. Compiled here with no cap.
const PROGRAMS =
  '(cat|less|head|tail|bat|more|open|print|nano|vim|vi|emacs|code|type|grep|egrep|fgrep|rg|ag|ack|awk|gawk|sed|cut|tr|jq|yq|od|xxd|hexdump|strings|base64|sort|uniq|tac|nl|dd)';
const OLD_ENV = new RegExp(
  PROGRAMS +
    '\\s+.*?\\.env(\\.(local|production|staging|development|production\\.local|staging\\.local|development\\.local))?(?=\\s|$|[;&|>)<])',
  'i'
);
const OLD_CREDENTIALS = new RegExp(
  PROGRAMS +
    '\\s+.*(credentials\\.json|\\.netrc|\\.npmrc|\\.docker[\\/\\\\]config\\.json|gcloud[\\/\\\\]credentials)',
  'i'
);

const ENV_COMMANDS = [
  'cat .env',
  'cat ./.env',
  'cat .env.production',
  'cat .env.staging.local',
  'grep KEY .env.local',
  'vi .env',
  'vim .env.development',
  'egrep -n TOKEN .env; echo done',
  'gawk 1 .env | head',
  'jq . .env',
  'cat .env.example',
  'cat .envrc',
  'cat README.md',
  'echo .env',
  'node .env',
];
const CREDENTIAL_COMMANDS = [
  'cat ~/.netrc',
  'cat ~/.npmrc',
  'cat ~/.docker/config.json',
  'less credentials.json',
  'head ~/.config/gcloud/credentials.db',
  'yq . ~/.config/gcloud/credentials',
  'cat package.json',
  'echo ~/.netrc',
];

describe('project-jail: the two rules that were over the cap', () => {
  it('each regex passes the runtime check', () => {
    for (const name of [
      'shield:project-jail:block-read-env',
      'shield:project-jail:review-read-credentials',
    ])
      for (const c of rule(name).conditions)
        expect(validateRegex(String(c.value)), name).toBeNull();
  });

  it('block-read-env meets an env read on its own', () => {
    for (const command of [
      'cat .env',
      'cat .env.production',
      'grep KEY .env.local',
      'vim .env.development',
    ])
      expect(meets('shield:project-jail:block-read-env', command), command).toBe(true);
    for (const command of ['cat .env.example', 'cat .envrc', 'echo .env'])
      expect(meets('shield:project-jail:block-read-env', command), command).toBe(false);
  });

  it('review-read-credentials meets a credentials read on its own', () => {
    for (const command of ['cat ~/.netrc', 'cat ~/.docker/config.json', 'less credentials.json'])
      expect(meets('shield:project-jail:review-read-credentials', command), command).toBe(true);
    for (const command of ['cat package.json', 'echo ~/.netrc'])
      expect(meets('shield:project-jail:review-read-credentials', command), command).toBe(false);
  });

  it('the short patterns say what the long ones said', () => {
    const env = new RegExp(
      String(rule('shield:project-jail:block-read-env').conditions[0].value),
      'i'
    );
    for (const c of ENV_COMMANDS) expect(env.test(c), c).toBe(OLD_ENV.test(c));
    const cred = new RegExp(
      String(rule('shield:project-jail:review-read-credentials').conditions[0].value),
      'i'
    );
    for (const c of CREDENTIAL_COMMANDS) expect(cred.test(c), c).toBe(OLD_CREDENTIALS.test(c));
  });
});

describe('every shipped shield regex is one the runtime runs', () => {
  it('passes validateRegex (length cap, syntax, ReDoS)', () => {
    for (const shield of Object.values(BUILTIN_SHIELDS))
      for (const r of shield.smartRules)
        for (const c of r.conditions ?? [])
          if ((c.op === 'matches' || c.op === 'notMatches') && c.value)
            expect(validateRegex(c.value), `${shield.name} ${r.name}`).toBeNull();
  });
});

// node9Firewall#414: the bash rules read the command as a file access, so a
// read written inside a stdin code body still meets them (fw#407 strips that
// body for the shell-syntax rules only).
describe('project-jail bash rules read a stdin code body', () => {
  it.each([
    ['block-read-ssh', `python3 - <<'PY'\nimport os\nos.system("cat ~/.ssh/id_rsa")\nPY`],
    ['block-read-aws', `python3 - <<'PY'\nimport os\nos.system("cat ~/.aws/credentials")\nPY`],
    ['block-read-env', `node - <<'JS'\nrequire('child_process').execSync('cat .env | head')\nJS`],
  ])('%s meets %s', (name, command) => {
    expect(meets(`shield:project-jail:${name}`, command)).toBe(true);
  });

  it('a script that names no credential file does not', () => {
    expect(meets('shield:project-jail:block-read-ssh', `python3 - <<'PY'\nprint("hi")\nPY`)).toBe(
      false
    );
  });

  it('a program run by its path is not a read of it', () => {
    expect(meets('shield:project-jail:block-read-ssh', 'cat ~/.ssh/config')).toBe(true);
    expect(meets('shield:project-jail:block-read-ssh', '/usr/bin/cat ~/.ssh/config')).toBe(true);
  });
});

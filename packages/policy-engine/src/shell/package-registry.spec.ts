// node9Firewall#415 item 4: the registry an install names on its own command
// line. Rows from the package managers' documented flags and variables.
import { describe, it, expect } from 'vitest';
import { extractRegistryOverrides, isPublicRegistryHost, registryHost } from './package-registry';

const hosts = (command: string) => extractRegistryOverrides(command).map((o) => o.host);

describe('extractRegistryOverrides', () => {
  it.each([
    ['npm --registry', 'npm install --registry https://r.example.test left-pad'],
    ['npm --registry=', 'npm i --registry=https://r.example.test:4873/ x'],
    ['the flag before the verb', 'npm --registry https://r.example.test install x'],
    ['npx', 'npx --registry https://r.example.test cowsay'],
    ['pnpm', 'pnpm add x --registry https://r.example.test'],
    ['yarn add', 'yarn add x --registry https://r.example.test'],
    ['a bare yarn install', 'yarn --registry https://r.example.test'],
    ['bun', 'bun add x --registry https://r.example.test'],
    ['npm ci with the variable', 'npm_config_registry=https://r.example.test npm ci'],
    ['the variable through env', 'env npm_config_registry=https://r.example.test npm install'],
    ['a variable assigned first', 'R=https://r.example.test; npm i --registry "$R" x'],
    ['pip -i', 'pip install -i https://r.example.test/simple requests'],
    ['python -m pip', 'python3 -m pip install --extra-index-url https://r.example.test/simple x'],
    ['pip by variable', 'PIP_INDEX_URL=https://r.example.test/simple pip install x'],
    ['uv pip', 'uv pip install --index-url https://r.example.test/simple x'],
    ['uv add with a named index', 'uv add --index mine=https://r.example.test/simple x'],
    ['uv tool install', 'uv tool install --index-url https://r.example.test/simple x'],
    ['pipenv', 'pipenv install -i https://r.example.test/simple x'],
    // Release review: pip's short flags with the URL attached.
    ['pip -i attached', 'pip install -ihttps://r.example.test/simple requests'],
    ['pip -f attached', 'pip install -fhttps://r.example.test/wheels x'],
    ['inside sh -c', 'sh -c "npm i --registry https://r.example.test x"'],
    ['behind sudo', 'sudo npm i -g --registry https://r.example.test x'],
    [
      'behind sudo -u with a user named like the manager',
      'sudo -u npm npm i --registry https://r.example.test x',
    ],
    // Second review: a manager's own value flag before the verb.
    [
      'npm --prefix before the verb',
      'npm --prefix ./app install x --registry https://r.example.test',
    ],
    ['npm -w before the verb', 'npm -w pkg install x --registry https://r.example.test'],
    ['pnpm -C before the verb', 'pnpm -C ./app add x --registry https://r.example.test'],
    [
      'pip --python before the verb',
      'pip --python python3 install -i https://r.example.test/simple x',
    ],
    [
      'pnpm dlx with the flag before the package',
      'pnpm dlx --registry https://r.example.test create-thing',
    ],
  ])('%s', (_label, command) => {
    expect(hosts(command)).toEqual(['r.example.test']);
  });

  it.each([
    ['no registry', 'npm install left-pad'],
    ['not an install', 'npm view x --registry https://r.example.test'],
    ['a publish', 'npm publish --registry https://r.example.test'],
    ['a config write', 'npm config set registry https://r.example.test'],
    ['a value that stays dynamic', 'npm i --registry "$REG" x'],
    ['pipx -f is --force', 'pipx install -f x'],
    ['the word in text', 'echo "npm install --registry https://r.example.test x"'],
    // Code review: after the package, a runner's words are the package's own.
    [
      'an argument of the package npx runs',
      'npx create-thing my-app --registry https://r.example.test',
    ],
    ['an argument after pnpm dlx', 'pnpm dlx create-thing app --registry https://r.example.test'],
    ['an argument after --', 'npm exec create-thing -- --registry https://r.example.test'],
  ])('none: %s', (_label, command) => {
    expect(hosts(command)).toEqual([]);
  });
});

describe('registryHost and isPublicRegistryHost', () => {
  it('reads the host of a URL, with or without credentials and port', () => {
    expect(registryHost('https://u:p@R.Example.test:8443/simple')).toBe('r.example.test');
    expect(registryHost('name=https://r.example.test/simple')).toBe('r.example.test');
    expect(registryHost('./wheels')).toBeNull();
  });

  it('the public registries and this machine are known; test.pypi.org is not', () => {
    for (const h of [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      'pypi.org',
      'localhost',
      '127.0.0.1',
    ]) {
      expect(isPublicRegistryHost(h)).toBe(true);
    }
    expect(isPublicRegistryHost('test.pypi.org')).toBe(false);
    expect(isPublicRegistryHost('r.example.test')).toBe(false);
  });
});

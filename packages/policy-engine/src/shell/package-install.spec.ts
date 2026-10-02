import { describe, it, expect } from 'vitest';
import { extractPackageInstalls, normalizePyPiName } from './package-install';

const names = (cmd: string) => extractPackageInstalls(cmd).map((r) => r.name);
const one = (cmd: string) => {
  const rows = extractPackageInstalls(cmd);
  expect(rows, cmd).toHaveLength(1);
  return rows[0];
};

describe('extractPackageInstalls — npm family', () => {
  it.each([
    ['npm install left-pad', 'npm', 'left-pad', undefined],
    ['npm i left-pad@1.3.0', 'npm', 'left-pad', '1.3.0'],
    ['npm add -D @types/node@22.1.0', 'npm', '@types/node', '22.1.0'],
    ['npm install --save left-pad@^1.0.0', 'npm', 'left-pad', undefined],
    ['npm install left-pad@latest', 'npm', 'left-pad', undefined],
    ['npm install lp@npm:left-pad@1.3.0', 'npm', 'left-pad', '1.3.0'],
    ['pnpm add left-pad@1.3.0', 'pnpm', 'left-pad', '1.3.0'],
    ['pnpm i --save-dev left-pad', 'pnpm', 'left-pad', undefined],
    ['yarn add left-pad@1.3.0', 'yarn', 'left-pad', '1.3.0'],
    ['yarn global add left-pad', 'yarn', 'left-pad', undefined],
    ['bun add left-pad', 'bun', 'left-pad', undefined],
    ['bun install left-pad@1.3.0', 'bun', 'left-pad', '1.3.0'],
    ['npx cowsay hello', 'npx', 'cowsay', undefined],
    ['npx -y cowsay@1.5.0 hello', 'npx', 'cowsay', '1.5.0'],
    ['npx --yes create-react-app my-app', 'npx', 'create-react-app', undefined],
    ['npm exec cowsay -- hi', 'npm exec', 'cowsay', undefined],
    ['npm x -- cowsay hi', 'npm exec', 'cowsay', undefined],
    ['pnpm dlx cowsay', 'pnpm dlx', 'cowsay', undefined],
    ['yarn dlx cowsay', 'yarn dlx', 'cowsay', undefined],
    ['bunx cowsay', 'bunx', 'cowsay', undefined],
    ['bun x cowsay', 'bunx', 'cowsay', undefined],
  ])('%s', (cmd, manager, name, version) => {
    const r = one(cmd);
    expect(r.ecosystem).toBe('npm');
    expect(r.manager).toBe(manager);
    expect(r.name).toBe(name);
    expect(r.version).toBe(version);
  });

  it('npx -p names the packages; the bare operand is then the command', () => {
    expect(names('npx -p typescript -p ts-node ts-node script.ts')).toEqual([
      'typescript',
      'ts-node',
    ]);
    expect(names('npx --package=typescript tsc --init')).toEqual(['typescript']);
  });
  it('several packages in one install, in order', () => {
    expect(names('npm i react react-dom@18.2.0 @scope/pkg')).toEqual([
      'react',
      'react-dom',
      '@scope/pkg',
    ]);
  });
  it('a bare install (lockfile) yields nothing', () => {
    expect(names('npm install')).toEqual([]);
    expect(names('npm ci')).toEqual([]);
    expect(names('yarn install')).toEqual([]);
    expect(names('pnpm install --frozen-lockfile')).toEqual([]);
  });
  it('skips paths, tarballs, git and URL specs', () => {
    expect(names('npm i ./local-pkg ../other /abs/pkg ~/x pkg.tgz')).toEqual([]);
    expect(names('npm i git+https://github.com/o/r.git github:o/r https://x.y/p.tgz')).toEqual([]);
    expect(names('npm i file:../lib workspace:*')).toEqual([]);
  });
  it('flags with operands do not become packages', () => {
    expect(names('npm i --registry https://r.example left-pad')).toEqual(['left-pad']);
    expect(names('pnpm add --filter web left-pad')).toEqual(['left-pad']);
  });
});

describe('extractPackageInstalls — PyPI', () => {
  it.each([
    ['pip install requests', 'pip', 'requests', undefined],
    ['pip3 install requests==2.31.0', 'pip3', 'requests', '2.31.0'],
    ['pip install "requests>=2.0"', 'pip', 'requests', undefined],
    ['pip install requests[security]==2.31.0', 'pip', 'requests', '2.31.0'],
    ['pip install --upgrade Django', 'pip', 'django', undefined],
    ['python -m pip install Pillow==10.0.0', 'pip', 'pillow', '10.0.0'],
    ['python3 -m pip install -U ruamel.yaml', 'pip', 'ruamel-yaml', undefined],
    ['uv add httpx', 'uv add', 'httpx', undefined],
    ['uv add "httpx==0.27.0"', 'uv add', 'httpx', '0.27.0'],
    ['uv pip install rich', 'uv pip', 'rich', undefined],
    ['uv tool install ruff', 'uv tool', 'ruff', undefined],
    ['uvx ruff check .', 'uvx', 'ruff', undefined],
    ['uv tool run ruff check .', 'uvx', 'ruff', undefined],
    ['poetry add rich', 'poetry', 'rich', undefined],
    ['poetry add rich==13.7.0', 'poetry', 'rich', '13.7.0'],
    ['pipx install black', 'pipx', 'black', undefined],
    ['pipx run cowsay moo', 'pipx run', 'cowsay', undefined],
    ['pipenv install requests', 'pipenv', 'requests', undefined],
  ])('%s', (cmd, manager, name, version) => {
    const r = one(cmd);
    expect(r.ecosystem).toBe('PyPI');
    expect(r.manager).toBe(manager);
    expect(r.name).toBe(name);
    expect(r.version).toBe(version);
  });
  it('-r / -c operands and URLs are not packages', () => {
    expect(names('pip install -r requirements.txt')).toEqual([]);
    expect(names('pip install -r requirements.txt requests')).toEqual(['requests']);
    expect(names('pip install https://x.y/p.whl ./dist/p.tar.gz -e .')).toEqual([]);
    expect(names('pip install "pkg @ https://x.y/pkg.whl"')).toEqual([]);
  });
  it('PEP 503 normalisation', () => {
    expect(normalizePyPiName('Ruamel.YAML')).toBe('ruamel-yaml');
    expect(normalizePyPiName('zope__interface')).toBe('zope-interface');
  });
});

describe('extractPackageInstalls — shell structure', () => {
  it('finds installs behind wrappers, in pipelines, lists and subshells', () => {
    expect(names('sudo npm i -g left-pad')).toEqual(['left-pad']);
    expect(names('env CI=1 npm install left-pad')).toEqual(['left-pad']);
    expect(names('cd app && npm i evil-pkg | tee log')).toEqual(['evil-pkg']);
    expect(names('(pip install requests); npm i left-pad')).toEqual(['requests', 'left-pad']);
    expect(names('timeout 30 pip install requests')).toEqual(['requests']);
  });
  it('dynamic package names are skipped, literal siblings kept', () => {
    expect(names('npm i $PKG left-pad')).toEqual(['left-pad']);
    expect(names('npx $(cat name)')).toEqual([]);
  });
  it('a quoted install inside echo is not an install', () => {
    expect(names('echo "npm install evil"')).toEqual([]);
  });
  it('unrelated commands and unparsable input yield nothing', () => {
    expect(names('ls -la && git status')).toEqual([]);
    expect(names('npm run build')).toEqual([]);
    expect(names('pip freeze')).toEqual([]);
    expect(names('npm i "unterminated')).toEqual([]);
    expect(names('')).toEqual([]);
  });
  it('deduplicates the same package named twice', () => {
    expect(names('npm i left-pad && npm i left-pad')).toEqual(['left-pad']);
  });
});

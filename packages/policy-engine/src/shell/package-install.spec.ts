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

// /code-review: each row was a silent bypass — the package was never extracted,
// so the install ran with no check and no recorded miss.
describe('extractPackageInstalls — review regressions', () => {
  it('global flags before the subcommand', () => {
    expect(names('npm --prefix app install evil-pkg@1.0.0')).toEqual(['evil-pkg']);
    expect(names('npm -g i evil-pkg')).toEqual(['evil-pkg']);
    expect(names('npm --registry=https://r.example install evil-pkg')).toEqual(['evil-pkg']);
    expect(names('pnpm -C web add evil-pkg')).toEqual(['evil-pkg']);
    expect(names('yarn --cwd web add evil-pkg')).toEqual(['evil-pkg']);
    expect(names('bun --cwd web add evil-pkg')).toEqual(['evil-pkg']);
    expect(names('pip -q install evil-py')).toEqual(['evil-py']);
    expect(names('pip --proxy http://p:1 install evil-py')).toEqual(['evil-py']);
    expect(names('python3 -I -m pip --disable-pip-version-check install evil-py')).toEqual([
      'evil-py',
    ]);
    expect(names('uv --quiet add evil-py')).toEqual(['evil-py']);
    expect(names('uv --directory app pip install evil-py')).toEqual(['evil-py']);
    expect(names('poetry -C app add evil-py')).toEqual(['evil-py']);
  });
  it('a flag that is boolean in pnpm does not swallow the package', () => {
    expect(names('pnpm add -w evil-pkg')).toEqual(['evil-pkg']);
    expect(names('pnpm add -D -w evil-pkg')).toEqual(['evil-pkg']);
  });
  it('npx value flags do not become the package', () => {
    expect(names('npx --cache /tmp/c evil-pkg')).toEqual(['evil-pkg']);
    expect(names('npx --registry https://r.example evil-pkg')).toEqual(['evil-pkg']);
    expect(names('npx -y --prefix /tmp evil-pkg arg')).toEqual(['evil-pkg']);
  });
  it('wrapper flags with a non-numeric value', () => {
    expect(names('sudo -u deploy npm i -g evil-pkg')).toEqual(['evil-pkg']);
    expect(names('doas -u root pip install evil-py')).toEqual(['evil-py']);
    expect(names('sudo npm i evil-pkg')).toEqual(['evil-pkg']);
  });
  it('installs inside sh -c / bash -lc / eval are re-read', () => {
    expect(names('bash -lc "npm install evil-pkg@1.0.0"')).toEqual(['evil-pkg']);
    expect(names("sh -c 'cd x && pip install evil-py'")).toEqual(['evil-py']);
    expect(names('eval "npx evil-pkg"')).toEqual(['evil-pkg']);
    expect(names('bash -c "bash -c \\"npm i evil-pkg\\""')).toEqual(['evil-pkg']);
    expect(names('bash script.sh')).toEqual([]);
  });
  it('uvx --from / --with and pipx --spec name the installed packages', () => {
    expect(names('uvx --from evil-py tool-cmd')).toEqual(['evil-py']);
    expect(names('uvx --with extra-py ruff check')).toEqual(['ruff', 'extra-py']);
    expect(names('pipx run --spec evil-py cmd')).toEqual(['evil-py']);
  });
});

// /code-review round 2.
describe('extractPackageInstalls — review round 2', () => {
  it('yarn workspace <name> add', () => {
    expect(names('yarn workspace web add evil-pkg')).toEqual(['evil-pkg']);
    expect(names('yarn workspace @app/web add -D evil-pkg@1.0.0')).toEqual(['evil-pkg']);
  });
  it('uv run --with installs the package', () => {
    expect(names('uv run --with evil-py main.py')).toEqual(['evil-py']);
    expect(names('uv run --with=evil-py --with other-py python -c x')).toEqual([
      'evil-py',
      'other-py',
    ]);
    expect(names('uv run main.py')).toEqual([]);
  });
  it('python interpreter flags with a value before -m pip', () => {
    expect(names('python -W ignore -m pip install evil-py')).toEqual(['evil-py']);
    expect(names('python3 -X dev -u -m pip install evil-py')).toEqual(['evil-py']);
  });
  it('shell long options with a value before -c', () => {
    expect(names('bash --rcfile /dev/null -c "npm i evil-pkg"')).toEqual(['evil-pkg']);
    expect(names('bash -o pipefail -c "pip install evil-py"')).toEqual(['evil-py']);
  });
});

// /code-review round 3.
describe('extractPackageInstalls — review round 3', () => {
  it('versioned interpreters and pip front-ends', () => {
    expect(names('python3.12 -m pip install evil-py')).toEqual(['evil-py']);
    expect(names('/usr/bin/python3.11 -m pip install evil-py')).toEqual(['evil-py']);
    expect(names('pip3.12 install evil-py')).toEqual(['evil-py']);
    expect(names('python3.12 script.py')).toEqual([]);
  });
  it('+o / +O shell options before -c', () => {
    expect(names('bash +O extglob -c "npm i evil-pkg"')).toEqual(['evil-pkg']);
    expect(names('bash +o posix -c "npm i evil-pkg"')).toEqual(['evil-pkg']);
  });
  it('comma-separated --with lists', () => {
    expect(names('uv run --with requests,evil-py main.py')).toEqual(['requests', 'evil-py']);
    expect(names('uvx --with=a-py,b-py ruff')).toEqual(['ruff', 'a-py', 'b-py']);
  });
});

describe('local execution context', () => {
  it.each([
    'npm -wother exec eslint',
    'npx -g eslint',
    'env npm exec eslint',
    'bash -c "npx eslint"',
    'cd "$TARGET" && npx eslint',
    'cd app; npx eslint',
  ])('does not assume the hook directory for %s', (command) => {
    expect(one(command).localCwd).toBeNull();
  });
  it.each(['npx eslint', 'bunx eslint', 'npm exec eslint'])(
    'keeps a plain local run eligible: %s',
    (command) => {
      expect(one(command).localCwd).toBeUndefined();
    }
  );
  it('preserves directory steps for a literal successful chain', () => {
    expect(one('cd app && cd frontend && npx eslint').localCwd).toEqual(['app', 'frontend']);
  });
});

describe('extractPackageInstalls — beyond npm and PyPI (node9Firewall#360)', () => {
  it.each([
    ['gem install example-gem', 'RubyGems', 'gem', 'example-gem', undefined],
    ['gem install example-gem -v 1.2.3', 'RubyGems', 'gem', 'example-gem', '1.2.3'],
    ['gem i example-gem --version=1.2.3', 'RubyGems', 'gem', 'example-gem', '1.2.3'],
    ['gem install example-gem:1.2.3', 'RubyGems', 'gem', 'example-gem', '1.2.3'],
    ["gem install example-gem -v '~> 1.2'", 'RubyGems', 'gem', 'example-gem', undefined],
    ['gem install example-gem -v 1.0.0.pre', 'RubyGems', 'gem', 'example-gem', undefined],
    [
      'gem install example-gem -- --with-opt-dir=/opt/x',
      'RubyGems',
      'gem',
      'example-gem',
      undefined,
    ],
    ['bundle add example-gem', 'RubyGems', 'bundle add', 'example-gem', undefined],
    [
      'bundle add example-gem --version 2.0.0 --group test',
      'RubyGems',
      'bundle add',
      'example-gem',
      '2.0.0',
    ],
    ['cargo add example-crate', 'crates.io', 'cargo add', 'example-crate', undefined],
    ['cargo add example-crate@1.2.3', 'crates.io', 'cargo add', 'example-crate', '1.2.3'],
    ['cargo add example-crate@=1.2.3', 'crates.io', 'cargo add', 'example-crate', '1.2.3'],
    ['cargo add example-crate@^1.2', 'crates.io', 'cargo add', 'example-crate', undefined],
    ['cargo add example-crate -F derive', 'crates.io', 'cargo add', 'example-crate', undefined],
    [
      'cargo add -p member example-crate --dev',
      'crates.io',
      'cargo add',
      'example-crate',
      undefined,
    ],
    ['cargo +nightly add example-crate', 'crates.io', 'cargo add', 'example-crate', undefined],
    [
      'cargo install example-crate --version 0.4.0',
      'crates.io',
      'cargo install',
      'example-crate',
      '0.4.0',
    ],
    ['cargo install example-crate@0.4.0', 'crates.io', 'cargo install', 'example-crate', '0.4.0'],
    ['go get example.test/owner/mod@v1.2.3', 'Go', 'go get', 'example.test/owner/mod', '1.2.3'],
    ['go get example.test/owner/mod@latest', 'Go', 'go get', 'example.test/owner/mod', undefined],
    ['go get -u example.test/owner/mod', 'Go', 'go get', 'example.test/owner/mod', undefined],
    ['go get example.test/owner/mod/...', 'Go', 'go get', 'example.test/owner/mod', undefined],
    [
      'go install example.test/owner/mod/cmd/tool@latest',
      'Go',
      'go install',
      'example.test/owner/mod/cmd/tool',
      undefined,
    ],
    [
      'go run example.test/owner/tool@v0.1.0 -flag',
      'Go',
      'go run',
      'example.test/owner/tool',
      '0.1.0',
    ],
    [
      'dotnet add package Example.Package',
      'NuGet',
      'dotnet add package',
      'Example.Package',
      undefined,
    ],
    [
      'dotnet add package Example.Package --version 1.2.3',
      'NuGet',
      'dotnet add package',
      'Example.Package',
      '1.2.3',
    ],
    [
      'dotnet add src/App/App.csproj package Example.Package -v 1.2.3',
      'NuGet',
      'dotnet add package',
      'Example.Package',
      '1.2.3',
    ],
    [
      'dotnet tool install -g example-tool --version 8.0.0',
      'NuGet',
      'dotnet tool',
      'example-tool',
      '8.0.0',
    ],
    [
      'nuget install Example.Package -Version 1.0.0',
      'NuGet',
      'nuget install',
      'Example.Package',
      '1.0.0',
    ],
    [
      'mvn dependency:get -Dartifact=org.example:widget:1.2.3',
      'Maven',
      'mvn dependency:get',
      'org.example:widget',
      '1.2.3',
    ],
    [
      './mvnw dependency:get -Dartifact=org.example:widget:LATEST',
      'Maven',
      'mvn dependency:get',
      'org.example:widget',
      undefined,
    ],
    [
      'mvn -q dependency:get -DgroupId=org.example -DartifactId=widget -Dversion=2.0',
      'Maven',
      'mvn dependency:get',
      'org.example:widget',
      '2.0',
    ],
    ['composer require acme/widget', 'Packagist', 'composer require', 'acme/widget', undefined],
    ['composer require acme/widget:1.2.3', 'Packagist', 'composer require', 'acme/widget', '1.2.3'],
    [
      'composer require "acme/widget:^1.2"',
      'Packagist',
      'composer require',
      'acme/widget',
      undefined,
    ],
    [
      'composer global require acme/installer',
      'Packagist',
      'composer require',
      'acme/installer',
      undefined,
    ],
    [
      'composer create-project acme/skeleton app 3.0.0',
      'Packagist',
      'composer create-project',
      'acme/skeleton',
      '3.0.0',
    ],
    [
      'code --install-extension acme.widget',
      'VSCode',
      'code --install-extension',
      'acme.widget',
      undefined,
    ],
    [
      'code --install-extension acme.widget@1.2.3',
      'VSCode',
      'code --install-extension',
      'acme.widget',
      '1.2.3',
    ],
    [
      'codium --install-extension=acme.widget',
      'VSCode',
      'code --install-extension',
      'acme.widget',
      undefined,
    ],
    [
      'cursor --install-extension acme.widget --force',
      'VSCode',
      'code --install-extension',
      'acme.widget',
      undefined,
    ],
  ] as const)('%s', (cmd, ecosystem, manager, name, version) => {
    const r = one(cmd);
    expect(r.ecosystem).toBe(ecosystem);
    expect(r.manager).toBe(manager);
    expect(r.name).toBe(name);
    expect(r.version).toBe(version);
  });

  it('every name of a multi-package command, and repeated --install-extension', () => {
    expect(names('gem install a-gem b-gem -v 1.0')).toEqual(['a-gem', 'b-gem']);
    expect(extractPackageInstalls('gem install a-gem b-gem -v 1.0').map((r) => r.version)).toEqual([
      '1.0',
      '1.0',
    ]);
    expect(names('cargo add crate-a crate-b@2.0.0')).toEqual(['crate-a', 'crate-b']);
    expect(names('code --install-extension a.one --install-extension b.two@1.0.0')).toEqual([
      'a.one',
      'b.two',
    ]);
  });

  it.each([
    'gem install ./vendor/example.gem',
    'gem install example.gem',
    'bundle add example-gem --git https://git.example.test/x',
    'bundle add example-gem --path ../x',
    'cargo add example-crate --git https://git.example.test/x',
    'cargo add --path ../local-crate',
    'cargo add example-crate --registry internal',
    'go get -u ./...',
    'go get .',
    'go get example.test/owner/mod@none',
    'go run main.go',
    'go run ./cmd/tool',
    'go run example.test/owner/tool',
    'go build ./...',
    'dotnet add reference ../Lib/Lib.csproj',
    'dotnet restore',
    'nuget install packages.config',
    'mvn clean install',
    'mvn -Dartifact=org.example:widget:1.0 test',
    'composer require php ext-json',
    'composer install',
    'code --install-extension ./dist/widget.vsix',
    'code --install-extension widget.vsix',
    'code --list-extensions',
  ])('not a registry install: %s', (cmd) => {
    expect(extractPackageInstalls(cmd)).toEqual([]);
  });

  it('reaches the new managers through wrappers and nested shells', () => {
    expect(names('sudo -u deploy gem install example-gem')).toEqual(['example-gem']);
    expect(names("bash -c 'cargo add example-crate'")).toEqual(['example-crate']);
    expect(names('env FOO=1 dotnet add package Example.Package')).toEqual(['Example.Package']);
    expect(names('cd app && composer require acme/widget')).toEqual(['acme/widget']);
  });
});

describe('look-alike names are still packages', () => {
  // OSV lists malicious NuGet ids that swap Latin letters for Cyrillic ones;
  // a name shape that refuses them would skip exactly the attack.
  const cyr = (s: string) => s.replace(/e/g, 'е').replace(/o/g, 'о');
  it.each([
    [`dotnet add package ${cyr('Example.Logger')} --version 1.0.0`, 'NuGet'],
    [`gem install ${cyr('example-gem')}`, 'RubyGems'],
    [`cargo add ${cyr('example-crate')}`, 'crates.io'],
    [`code --install-extension ${cyr('acme.widget')}`, 'VSCode'],
    [`composer require ${cyr('acme/widget')}`, 'Packagist'],
    [`go get ${cyr('example.test/owner/mod')}`, 'Go'],
  ])('%s', (cmd, ecosystem) => {
    const r = one(cmd);
    expect(r.ecosystem).toBe(ecosystem);
    expect(/[Ѐ-ӿ]/.test(r.name)).toBe(true);
  });
});

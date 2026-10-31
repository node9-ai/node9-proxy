// The git checks read from the parsed command (node9Firewall#413, part 1).
//
// Corpus before code: every row below is written from the CATEGORIES in the
// issue (an indirect spelling crossed with a destructive form; the ordinary
// commands the regex stopped), never from a benchmark case. The legitimate
// rows are shapes agents run every day; each must stay clean.
import { describe, it, expect } from 'vitest';
import { analyzeGit, gitInvocations } from './git';

const rules = (cmd: string): string[] => analyzeGit(cmd).findings.map((f) => f.ruleName);

describe('git invocations resolved from the AST', () => {
  it.each([
    ['git reset --hard HEAD~1', 'reset', ['--hard', 'HEAD~1']],
    ['git -C ../app reset --hard', 'reset', ['--hard']],
    ['git --git-dir=.git --work-tree=. reset --hard', 'reset', ['--hard']],
    ['git -c core.pager=cat log', 'log', []],
    ['git --no-pager -p status', 'status', []],
    ['/usr/bin/git status', 'status', []],
    ['command git status', 'status', []],
    ['env GIT_DIR=.git git status', 'status', []],
    ['timeout 30 git fetch', 'fetch', []],
    ['nice -n 10 git gc', 'gc', []],
    ["g''it st\\atus", 'status', []],
    ['cmd="reset --hard"; git $cmd', 'reset', ['--hard']],
    ['sub=reset; git $sub --hard', 'reset', ['--hard']],
    ['cmd="reset --hard" && git $cmd', 'reset', ['--hard']],
    ['export cmd="reset --hard"; git $cmd', 'reset', ['--hard']],
    ['G=git; $G reset --hard', 'reset', ['--hard']],
    ['git $(echo reset) --hard', 'reset', ['--hard']],
  ])('%s -> %s %j', (cmd, sub, args) => {
    const inv = gitInvocations(cmd);
    expect(inv.map((i) => [i.sub, i.args])).toContainEqual([sub, args]);
  });

  it('a quoted expansion stays one word', () => {
    const inv = gitInvocations('cmd="reset --hard"; git "$cmd"');
    expect(inv.map((i) => i.sub)).toEqual(['reset --hard']);
  });

  it('a variable assigned after the call is unknown at the call', () => {
    const inv = gitInvocations('git $cmd; cmd=status');
    expect(inv.map((i) => i.sub)).toEqual([null]);
  });

  it('a config option before the subcommand is kept', () => {
    const [inv] = gitInvocations('git -c core.hooksPath=/dev/null commit -m x');
    expect(inv.sub).toBe('commit');
    expect(inv.config.get('core.hookspath')).toBe('/dev/null');
  });

  it('a prefix assignment and env assignments reach the call', () => {
    expect(gitInvocations('HUSKY=0 git commit -m x')[0].env.get('HUSKY')).toBe('0');
    expect(gitInvocations('env HUSKY=0 git commit -m x')[0].env.get('HUSKY')).toBe('0');
  });

  it('a function body is judged at its call with the arguments bound', () => {
    const inv = gitInvocations('g() { git "$@"; }; g reset --hard');
    expect(inv.map((i) => [i.sub, i.args])).toContainEqual(['reset', ['--hard']]);
  });

  it('a wrapper function declared and never called is not a dynamic subcommand', () => {
    expect(gitInvocations('g() { git "$@"; }')).toEqual([]);
    expect(gitInvocations('g() { git "$1" "$2"; }')).toEqual([]);
  });
});

describe('commands.git-destructive: indirect forms are findings', () => {
  it.each([
    // the direct forms the regex caught, still caught
    'git push --force',
    'git push --force-with-lease origin main',
    'git push --force-if-includes',
    'git push origin main -f',
    'git push -fu origin main',
    'git push origin +main',
    'git push --mirror backup',
    'git reset --hard HEAD',
    'git reset --hard',
    'git clean -fd',
    'git clean -fdx',
    'git clean -f -d',
    'git clean --force',
    'git branch -D old-feat',
    'git branch -d -f old-feat',
    'git branch -df old-feat',
    'git branch --delete --force old-feat',
    'git tag -d v1.0',
    'git tag --delete v1.0',
    // global options and spellings
    'git -C ../app reset --hard',
    'git -C /srv/repo push -f origin main',
    'git --git-dir=/srv/repo/.git --work-tree=/srv/repo reset --hard',
    'git -c user.name=x reset --hard',
    'git --no-pager reset --hard',
    '/usr/bin/git reset --hard',
    'command git reset --hard',
    "g''it reset --hard",
    'git re\\set --hard',
    // wrappers
    'env GIT_DIR=.git git reset --hard',
    'env -i git reset --hard',
    'sudo git reset --hard',
    'timeout 30 git reset --hard',
    'nice git clean -fd',
    'nohup git push -f origin main &',
    'xargs git branch -D < branches.txt',
    'echo old-feat | xargs git branch -D',
    'echo main | xargs -I{} git push -f origin {}',
    'find . -name .git -execdir git reset --hard \\;',
    // variables and substitutions
    'cmd="reset --hard"; git $cmd',
    'cmd="reset --hard" && git $cmd',
    'export FLAGS="--hard"; git reset $FLAGS',
    'sub=push; git $sub -f origin main',
    'G=/usr/bin/git; $G reset --hard',
    'git $(echo reset) --hard',
    'f=-f; git push $f origin main',
    'git push $(printf "%s" --force) origin main',
    // nested shells
    "sh -c 'git reset --hard'",
    'bash -lc "git push -f origin main"',
    'eval "git reset --hard"',
    'eval git reset --hard',
    "sudo sh -c 'git clean -fd'",
    'sh -c \'sh -c "git reset --hard"\'',
    "bash <<'EOF'\ngit reset --hard\nEOF",
    'bash <<EOF\ncd app\ngit push -f\nEOF',
    'cmd=\'git reset --hard\'; sh -c "$cmd"',
    // functions
    'g() { git "$@"; }; g reset --hard',
    'nuke() { git reset --hard; }; nuke',
    'function wipe { git clean -fd; }\nwipe',
    // aliases defined in the same command
    "git config alias.x 'reset --hard' && git x",
    "git config --global alias.x 'reset --hard'; git x",
    "git config --local alias.fp 'push --force' && git fp origin main",
    "git config set alias.x 'reset --hard' && git x",
    'git -c alias.x="reset --hard" x',
    "git config alias.x '!git reset --hard' && git x",
    "git config alias.a 'reset'; git config alias.b 'a --hard'; git b",
    // the definition alone, judged by its value (the use may come next call)
    "git config alias.x 'reset --hard'",
    "git config --global alias.nuke 'clean -fdx'",
    "git config alias.x '!git push -f origin main'",
    // a subcommand nobody can read
    'git $cmd',
    'git $cmd --hard',
    'git -C app $sub',
    'cat ops.txt | xargs git',
    'git $(cat cmd.txt)',
    // a command substitution bash runs, wherever it sits
    'echo "$(git reset --hard)"',
    'node -e "const c = `git push --force origin main`; console.log(c)"',
    'cd app && for c in status "reset --hard"; do git $c; done',
    'for r in a b; do git -C $r push -f; done',
    // clean without -f when the call itself switches the safety off
    'git -c clean.requireForce=false clean -d',
    'git -c clean.requireforce=false clean',
    // chains
    'git stash && git reset --hard && git stash pop',
    'git fetch && git reset --hard origin/main',
    'git rebase -i HEAD~3 && git push --force',
  ])('%s', (cmd) => {
    expect(rules(cmd).length, `${cmd} should be a finding`).toBeGreaterThan(0);
  });

  it('names the force push and the destructive op by the rule the audit knows', () => {
    expect(rules('git push -f')).toEqual(['review-force-push']);
    expect(rules('git reset --hard')).toEqual(['review-git-destructive']);
    expect(rules("sh -c 'git push -f' && git reset --hard")).toEqual([
      'review-force-push',
      'review-git-destructive',
    ]);
  });

  it('shows the resolved invocation in the reason', () => {
    const [f] = analyzeGit('cmd="reset --hard"; git $cmd').findings;
    expect(f.reason).toContain('git reset --hard');
    const [a] = analyzeGit("git config alias.x 'reset --hard' && git x").findings;
    expect(a.reason).toContain('alias x');
  });
});

describe('commands.git-destructive: ordinary commands stay clean', () => {
  it.each([
    // the four false positives of the regex rule
    'git push --dry-run --force origin main',
    'git push -n -f origin main',
    'git push --force --dry-run',
    'git clean -fn',
    'git clean -n -f',
    'git clean -fdn',
    'git clean --dry-run -f',
    'git branch -d feature/x',
    'git branch --delete feature/x',
    'git stash push -m wip && git rebase origin/main',
    'git rebase main',
    'git rebase -i HEAD~3',
    'git rebase --onto main feature~3 feature',
    'git rebase --abort',
    'git rebase --continue',
    'git pull --rebase origin main',
    // everyday work
    'git status',
    'git add src/index.ts && git commit -m "fix: reset --hard handling"',
    'git commit -m "git push --force is now reviewed"',
    'git commit -am "clean -fd docs"',
    'git log --oneline -5',
    'git diff HEAD~1',
    'git push origin main',
    'git push -u origin feature/x',
    'git push --force-with-lease=main:abc --dry-run',
    'git reset HEAD~1',
    'git reset --soft HEAD~1',
    'git reset --mixed',
    'git reset --keep',
    'git reset -- src/index.ts',
    'git checkout -b feature/x',
    'git switch -c feature/x',
    'git branch -m old new',
    'git branch -u origin/main',
    'git branch --set-upstream-to=origin/main',
    'git branch -a',
    'git tag v1.0',
    'git tag -a v1.0 -m "release"',
    'git tag -l',
    'git clean -i',
    'git clean -n',
    'git clean -d',
    'git stash',
    'git stash pop',
    'git fetch --prune',
    'git merge --no-ff feature/x',
    'git cherry-pick abc123',
    'git describe --tags',
    'git rev-parse HEAD',
    'git remote -v',
    'git config user.name',
    'git config --get core.hooksPath',
    'git config alias.st status',
    'git config --global alias.st',
    'git config alias.co',
    'git config alias.co checkout && git co main',
    'git config --global alias.lg "log --oneline --graph"',
    "git config alias.pf 'push --force-with-lease --dry-run'",
    'git -C ../app status',
    'git --no-pager log -3',
    'git -c core.pager=cat diff',
    'env GIT_DIR=.git git status',
    'timeout 30 git fetch',
    "sh -c 'git status'",
    "bash <<'EOF'\ngit status\ngit log -1\nEOF",
    'g() { git "$@"; }; g status',
    'g() { git "$@"; }',
    'for d in */; do git -C "$d" pull; done',
    'for c in status "log -1"; do git $c; done',
    'for c in status "log -1"; do git -C app "$c"; done',
    'G=/srv/repo/.git; git --git-dir=$G log -1',
    'git --git-dir=$G log -1',
    'git -C $dir status',
    'git -C$dir status',
    // git as a word, not a command
    'echo git reset --hard',
    'echo "run git push --force to publish"',
    'grep -rn "git reset --hard" docs/',
    'cat > notes.md <<EOF\ngit reset --hard HEAD\nEOF',
    'node -e "const c = \'git push --force\'; console.log(c)"',
    'python3 -c "print(\'git clean -fd\')"',
    'which git',
    'git --version',
    'git help push',
    'git push -h',
    // not git
    'ls -la',
    'npm test',
    'rm -rf node_modules',
    'legit --force',
    'digit reset --hard',
  ])('%s', (cmd) => {
    // Part 3's opt-in finding (`commit -am`) is not destruction.
    const destructive = rules(cmd).filter((r) => r !== 'review-git-stage-all');
    expect(destructive, `${cmd} should be clean`).toEqual([]);
  });
});

describe('a command that does not parse', () => {
  it('reports parsed: false and no finding, so the regex rule keeps speaking', () => {
    const r = analyzeGit('git reset --hard $(');
    expect(r.parsed).toBe(false);
    expect(r.findings).toEqual([]);
  });

  it('a command with no git in it is clean without a parse', () => {
    expect(analyzeGit('ls -la')).toEqual({ parsed: true, findings: [] });
  });
});

describe('bounds', () => {
  it('a deep nest of shells terminates and still finds the call', () => {
    let cmd = 'git reset --hard';
    for (let i = 0; i < 6; i++) cmd = `sh -c ${JSON.stringify(cmd)}`;
    expect(rules(cmd)).toEqual(['review-git-destructive']);
  });

  it('an alias loop terminates', () => {
    expect(() => analyzeGit('git config alias.a b; git config alias.b a; git a')).not.toThrow();
  });

  it('a long command with many git calls stays fast', () => {
    const cmd = Array.from({ length: 200 }, (_, i) => `git -C r${i} status`).join(' && ');
    const t = Date.now();
    expect(rules(cmd)).toEqual([]);
    expect(Date.now() - t).toBeLessThan(5_000);
  });
});

// ── Part 2: commands.git-hooks-bypass ────────────────────────────────────────

const hooks = (cmd: string): boolean => rules(cmd).includes('review-git-hooks-bypass');

describe('commands.git-hooks-bypass: the agent disarms the hooks', () => {
  it.each([
    // --no-verify and its short form on commit
    'git commit --no-verify -m "wip"',
    'git commit -n -m "wip"',
    'git commit -nm "wip"',
    'git commit -anm "wip"',
    'git commit -a --no-verify -m wip',
    'git commit -m "msg" --no-verify',
    'git push --no-verify origin main',
    'git merge --no-verify feature/x',
    'git rebase --no-verify main',
    'git am --no-verify patch.mbox',
    // the hook path pointed elsewhere
    'git -c core.hooksPath=/dev/null commit -m x',
    'git -c core.hookspath=/tmp/empty push',
    'git config core.hooksPath /dev/null',
    'git config --local core.hooksPath /tmp/empty',
    'git config --global core.hooksPath ~/nohooks',
    'git config set core.hooksPath /dev/null',
    'git config --unset core.hooksPath',
    'GIT_CONFIG_PARAMETERS="\'core.hooksPath=/dev/null\'" git commit -m x',
    'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x',
    // outside the tree, empty or unreadable (node9Firewall#413 follow-up)
    'git config core.hooksPath ../hooks',
    'git config core.hooksPath hooks/../../elsewhere',
    'git config core.hooksPath ""',
    'git config core.hooksPath "$EMPTY"',
    'git -c core.hooksPath= commit -m x',
    'git -c core.hooksPath=~/x commit -m x',
    'git config core.hooksPath C:\\nohooks',
    'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=../x git commit -m x',
    // the root of the tree or the git directory hold no hook files (code review)
    'git -c core.hooksPath=. commit -m x',
    'git config core.hooksPath ./',
    'git config core.hooksPath sub/..',
    'git config core.hooksPath .git',
    'git config core.hooksPath ./.git/',
    'git config --unset-all core.hooksPath',
    // the hook managers' kill switches, on the git call
    'HUSKY=0 git commit -m x',
    'HUSKY=0 git push',
    'env HUSKY=0 git commit -m x',
    'export HUSKY=0; git commit -m x',
    'export HUSKY=0 && git commit -m x',
    'HUSKY_SKIP_HOOKS=1 git commit -m x',
    'LEFTHOOK=0 git commit -m x',
    'SKIP=eslint git commit -m x',
    'SKIP=lint,test git commit -m x',
    // indirect spellings, through the part-1 walk
    'git -C ../app commit --no-verify -m x',
    'sudo git commit -n -m x',
    "sh -c 'git commit --no-verify -m x'",
    'f=--no-verify; git commit $f -m x',
    "git config alias.c 'commit --no-verify' && git c -m x",
    "git config alias.c 'commit --no-verify'",
    // a hook file disabled from the shell
    'chmod -x .git/hooks/pre-commit',
    'chmod a-x .husky/pre-commit',
    'chmod 644 .git/hooks/pre-push',
    'chmod 000 .husky/_/pre-commit',
    'chmod -R -x .git/hooks',
    'sudo chmod -x .git/hooks/pre-commit',
    'chmod u-x,g-x /srv/repo/.git/hooks/commit-msg',
  ])('%s', (cmd) => {
    expect(hooks(cmd), `${cmd} should be a hooks bypass`).toBe(true);
  });

  it('is one finding per check: a forced push without hooks is both', () => {
    expect(rules('git push --no-verify -f origin main').sort()).toEqual([
      'review-force-push',
      'review-git-hooks-bypass',
    ]);
  });
});

describe('commands.git-hooks-bypass: ordinary work stays clean', () => {
  it.each([
    'git commit -m "wip"',
    'git commit -am "wip"',
    'git commit -m "add --no-verify to the docs"',
    'git commit -m "HUSKY=0 explained"',
    'git push -n origin main',
    'git push --dry-run origin main',
    'git push origin main',
    'git config core.hooksPath',
    'git config --get core.hooksPath',
    // the project's own versioned hooks, inside the tree (node9Firewall#413 follow-up)
    'git config core.hooksPath .githooks',
    'git config --local core.hooksPath .githooks',
    'git config core.hooksPath .husky',
    'git config core.hooksPath ./tools/git-hooks',
    'git config core.hooksPath .git/hooks',
    'git config set core.hooksPath .githooks',
    'git -c core.hooksPath=.githooks commit -m x',
    'git -c core.hooksPath=.githooks push origin main',
    'git config core.hooksPath .githooks && git push origin main',
    'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=.githooks git commit -m x',
    'git config --list',
    'git config user.name "x"',
    'git -c core.pager=cat log',
    'git -c user.email=a@b commit -m x',
    'HUSKY=0 npm ci',
    'HUSKY=0 npm install',
    'SKIP=1 make test',
    'LEFTHOOK=0 npm run build',
    'HUSKY=1 git commit -m x',
    'export HUSKY=1; git commit -m x',
    'echo "HUSKY=0 git commit" > notes.txt',
    'chmod +x .husky/pre-commit',
    'chmod 755 .git/hooks/pre-commit',
    'chmod -x scripts/old.sh',
    'chmod 644 README.md',
    'cat .git/hooks/pre-commit',
    'ls .husky',
    'git commit --verify -m x',
    'npx husky',
    'git rebase --continue',
  ])('%s', (cmd) => {
    expect(hooks(cmd), `${cmd} should be clean`).toBe(false);
  });
});

// ── Part 3: commands.git-stage-all (opt-in) ──────────────────────────────────

const stageAll = (cmd: string): boolean => rules(cmd).includes('review-git-stage-all');

describe('commands.git-stage-all: everything staged at once', () => {
  it.each([
    'git add -A',
    'git add --all',
    'git add -A .',
    'git add .',
    'git add ./',
    'git add -- .',
    'git add src/..',
    'git add ./src/../',
    'git add :/',
    'git add ":(top)"',
    'git add "*"',
    'git add -u',
    'git add --update',
    'git add --no-ignore-removal',
    'git add -Av',
    'git add -fA',
    'git commit -a -m wip',
    'git commit -am wip',
    'git commit -anm wip',
    'git commit --all -m wip',
    'git commit -a --amend --no-edit',
    'git commit . -m wip',
    'git commit -m wip -- :/',
    'git -C ../app add -A',
    // -C that leaves the tree, is absolute or dynamic: read as today
    'git -C ../app add .',
    'git -C /srv/repo add .',
    'git -C "$REPO" add .',
    // -C into a subdirectory, then climbing back to the top
    'git -C sub add ..',
    'git -C packages/a add ../..',
    // -A, -u, commit -a with no pathspec stage the whole tree from anywhere
    'git -C sub add -A',
    'git -C sub commit -am wip',
    // a -C filled in at run time is dynamic (code review)
    'ls -d */ | xargs -I{} git -C {} add .',
    'find . -maxdepth 1 -type d -exec git -C {} add . \\;',
    "sh -c 'git add -A && git commit -m wip'",
    'f=-A; git add $f',
    "git config alias.ca 'commit -a' && git ca -m wip",
    "git config alias.ca 'commit -a'",
    'git add -A && git commit -m "feat: thing"',
  ])('%s', (cmd) => {
    expect(stageAll(cmd), `${cmd} should stage everything`).toBe(true);
  });

  it('rides the check id of part 3 only', () => {
    const f = analyzeGit('git add -A').findings;
    expect(f.map((x) => x.checkId)).toEqual(['commands.git-stage-all']);
  });
});

describe('commands.git-stage-all: named files stay clean', () => {
  it.each([
    'git add src/index.ts',
    'git add src/ README.md',
    'git add -A src/',
    'git add -u src/',
    'git add --all -- src/',
    'git add ./src',
    'git add .github/',
    'git add .env.example',
    'git add -p',
    'git add -p .',
    'git add -i',
    'git add -n .',
    'git add --dry-run -A',
    'git add -e src/x.ts',
    'git add ":(glob)src/**/*.ts"',
    'git add ":!secrets" src',
    'git commit -m "wip"',
    'git commit -m "git add -A is discouraged"',
    'git commit --amend --no-edit',
    'git commit --dry-run -a',
    'git commit -m wip src/index.ts',
    'git commit --only -m wip src/x.ts',
    'git status',
    'git diff .',
    'git checkout .',
    'git restore .',
    'git clean -n .',
    'npm run add-all',
  ])('%s', (cmd) => {
    expect(stageAll(cmd), `${cmd} should be clean`).toBe(false);
  });
});

// ── -C into a directory: whole tree only if that directory is a work-tree top ──
// (node9Firewall#413 follow-up, code review). The command alone cannot tell
// `git -C sub add .` (a subdirectory) from `git -C myapp add .` run from the
// folder above the repository (the whole tree). The finding names the
// directory; the gate, which knows the working directory, asks the disk.

const stageAllFinding = (cmd: string) =>
  analyzeGit(cmd).findings.find((f) => f.checkId === 'commands.git-stage-all');

describe('commands.git-stage-all: -C into a directory is decided by the disk', () => {
  it.each([
    ['git -C sub add .', 'sub'],
    ['git -C packages/web add .', 'packages/web'],
    ['git -C ./docs add -- .', 'docs'],
    ['f() { git -C "site" add .; }; f', 'site'],
    ['git -C sub -C deeper add .', 'sub/deeper'],
    ['git -C sub add -A .', 'sub'],
    ['git -C myapp add .', 'myapp'],
    ['git -C sub add "*"', 'sub'],
    ['git -C sub commit -m wip .', 'sub'],
    ['git config alias.aa add && git -C sub aa .', 'sub'],
  ])('%s -> whole tree only if %s is a work-tree top', (cmd, dir) => {
    expect(stageAllFinding(cmd)?.ifWorkTreeTop, cmd).toBe(dir);
  });
  it('a finding that does not depend on the directory carries no condition', () => {
    for (const cmd of [
      'git add .',
      'git -C sub add -A',
      'git -C sub add ..',
      'git -C /srv/repo add .',
    ]) {
      const f = stageAllFinding(cmd);
      expect(f, cmd).toBeDefined();
      expect(f?.ifWorkTreeTop, cmd).toBeUndefined();
    }
  });
  it('named files under -C are no finding at all', () => {
    expect(stageAllFinding('git -C sub add src/x.ts')).toBeUndefined();
  });
});

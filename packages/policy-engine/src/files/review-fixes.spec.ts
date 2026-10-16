import { describe, expect, it } from 'vitest';
import { collectFileAccesses, evaluateProtectedFileAccess } from './protected-access';
import { evaluatePolicy } from '../policy';
import { DEFAULT_CONFIG } from '../../../../src/config';

// Regressions found by the pre-push review of #341. Each case failed before
// the fix it names in the describe title.
const context = { cwd: '/work', homeDirs: ['/home/u'] };
const home = { cwd: '/home/u', homeDirs: ['/home/u'] };
const verdict = (command: string, ctx = context) =>
  evaluateProtectedFileAccess(collectFileAccesses('Bash', { command }, ctx), ctx, {})?.decision ??
  null;

describe('dynamic operands keep their literal prefix', () => {
  it.each([
    'echo x >> /etc/sudo$(echo ers)',
    'echo x > "/etc/${X:-passwd}"',
    'dd of=/etc/pass$X',
    'rm /etc/pam.d/$X',
    'rm ${f:-/etc/passwd}',
    'rm ${f-/etc}/passwd',
  ])('blocks %s', (command) => {
    expect(verdict(command)).toBe('block');
  });
  it.each(['echo x > $OUT', 'rm -rf $DIR', 'cp $SRC /tmp/x'])(
    'does not invent a protected target for %s',
    (command) => {
      expect(verdict(command, home)).toBeNull();
    }
  );
});

describe('statement shapes the walker skipped', () => {
  it.each([
    'time echo x >> /etc/sudoers',
    'time { rm /etc/passwd; }',
    'coproc echo x > /etc/passwd',
    'echo x >&/etc/passwd',
    'echo x >> /etc/sudoers\n}',
    "su -c 'rm /etc/passwd'",
    'su root --command="rm /etc/passwd"',
    "sh -c -- 'rm /etc/passwd'",
    'bash <<EOF\nrm /etc/passwd\nEOF',
    'sudo bash -s <<EOF\nrm /etc/passwd\nEOF',
    'f=/etc/passwd; export f; rm $f',
    'f=/etc/pass; f+=wd; rm $f',
    'rm /etc/passwd' + ' && :'.repeat(70),
    'rm /etc/passwd' + ' | cat'.repeat(70),
    ':' + ' && :'.repeat(70) + ' && rm /etc/passwd',
  ])('blocks %s', (command) => {
    expect(verdict(command)).toBe('block');
  });
  it('does not run a heredoc that is data for a script operand', () => {
    expect(verdict('bash script.sh <<EOF\nrm /etc/passwd\nEOF')).toBeNull();
    expect(verdict('cat <<EOF\nrm /etc/passwd\nEOF')).toBeNull();
  });
});

describe('wrapper flags never swallow a mutation verb', () => {
  it.each([
    'sudo -n rm /etc/passwd',
    'sudo -- rm /etc/passwd',
    'sudo -E tee -a /etc/sudoers',
    'env -i rm /etc/passwd',
    'nice -5 rm /etc/passwd',
    'command -p rm /etc/passwd',
  ])('blocks %s', (command) => {
    expect(verdict(command)).toBe('block');
  });
});

describe('root, sudoers.d and the tilde cwd', () => {
  it.each(['rm -rf /.', 'rm -rf //', 'rm -rf /etc/..'])('treats %s as touching /etc', (command) => {
    expect(verdict(command)).toBe('block');
  });
  it.each([
    'echo "u ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/u',
    'install -m 440 /tmp/x /etc/sudoers.d/x',
  ])('blocks %s', (command) => {
    expect(verdict(command)).toBe('block');
  });
  it.each([
    'cd ~ && echo x >> .bashrc',
    'cd ~/ && rm .bashrc',
    'cd ~/projects && echo x >> ../.bashrc',
  ])('reviews %s with a cwd outside the home', (command) => {
    expect(verdict(command)).toBe('review');
  });
  it('does not treat cd $DIR or cd - as cd to the home', () => {
    expect(verdict('cd $DIR && echo x >> .bashrc')).toBeNull();
    expect(verdict('cd - && echo x >> .bashrc')).toBeNull();
  });
});

describe('find actions respect name tests and -delete', () => {
  it.each([
    'find /etc -delete',
    'find /etc -name passwd -delete',
    'find / -delete',
    'find /etc -name passwd -exec rm {} \\;',
    'find /etc -fprint /etc/passwd',
  ])('blocks %s', (command) => {
    expect(verdict(command)).toBe('block');
  });
  it.each([
    'find / -name "*.tmp" -exec rm {} \\;',
    'find ~ -type d -name node_modules -exec rm -rf {} +',
    'find . -name "*.pyc" -exec rm {} \\;',
    'find . -maxdepth 1 -name "*.tmp" -exec rm {} \\;',
    'find . -name "*.pyc" -delete',
    'find /var/log -name "*.log" -delete',
  ])('finds nothing in %s', (command) => {
    expect(verdict(command, home)).toBeNull();
  });
  it('still reviews a find over the home that removes everything', () => {
    expect(verdict('find ~ -exec rm {} \\;')).toBe('review');
    expect(verdict('find ~ -maxdepth 1 -type f -delete')).toBe('review');
  });
});

describe('shell globs follow bash, not find', () => {
  it.each(['rm -rf *', 'rm *', 'echo x > *', 'sed -i s/a/b/ *', 'mv * /tmp/', 'cp -r src/ .'])(
    'does not match a dotfile for %s',
    (command) => {
      expect(verdict(command, home)).toBeNull();
    }
  );
  it('still matches a pattern that names the dot', () => {
    expect(verdict('rm .bash*', home)).toBe('review');
    expect(verdict('rm -rf /etc/pass*')).toBe('block');
  });
  it('strips a trailing slash from a copy source before taking its basename', () => {
    expect(verdict('cp -a /tmp/docs/ /etc/')).toBeNull();
    expect(verdict('cp -r /tmp/pam.d/ /etc/')).toBe('block');
  });
});

describe('directory tracking', () => {
  it('uses the new directory only for the next command of a pure && chain', () => {
    expect(verdict('cd /etc && cd /tmp && rm passwd')).toBeNull();
  });
  it.each([
    'cd /etc && rm passwd',
    'cd /etc && true; rm passwd',
    'cd /etc || true; rm passwd',
    'cd etc && rm passwd',
    // A cd to a missing directory fails and leaves the shell where it was.
    'cd /etc; cd /tmp; rm passwd',
    'cd /etc; cd /nonexistent; rm passwd',
    'cd /etc && cd /nonexistent || rm passwd',
    'cd /etc && cd /nonexistent 2>/dev/null; rm passwd',
    'cd /etc || cd /tmp && rm passwd',
    'cd /etc; cd /tmp; cd -; rm passwd',
    'pushd /etc; cd /tmp; rm passwd',
  ])('keeps a directory the shell may be in: %s', (command) => {
    expect(verdict(command, { cwd: '/', homeDirs: ['/home/u'] })).toBe('block');
  });
});

describe('second review round', () => {
  it.each([
    'cat <<EOF | bash\nrm /etc/passwd\nEOF',
    "bash <<< 'rm /etc/passwd'",
    "echo 'rm /etc/passwd' | bash",
    "printf 'rm /etc/passwd' | sudo sh",
  ])('parses a literal script fed to a shell: %s', (command) => {
    expect(verdict(command)).toBe('block');
  });
  it.each([
    "echo 'rm /etc/passwd'",
    'cat <<EOF | grep x\nrm /etc/passwd\nEOF',
    "bash script.sh <<< 'rm /etc/passwd'",
  ])('treats text that no shell runs as data: %s', (command) => {
    expect(verdict(command)).toBeNull();
  });
  it.each([
    "find / -path '*/etc/passwd' -delete",
    'find /etc \\( -name x -o -name passwd \\) -delete',
    'find /etc \\( -name passwd -o -name x \\) -delete',
    'find /etc ! -name x -delete',
    'find /etc -not -name x -exec rm {} \\;',
  ])('does not let a find expression narrow away a protected file: %s', (command) => {
    expect(verdict(command)).toBe('block');
  });
  it('inspects only the statements before a syntax error', () => {
    expect(verdict("cat > notes.md <<'EOF'\nrm -rf /etc/pam.d\nEOF\nfoo() {")).toBeNull();
    expect(verdict('echo x >> /etc/sudoers\n}')).toBe('block');
    expect(verdict('echo x >> /etc/sudoers; }')).toBeNull();
  });
  it('needs a literal prefix before matching a dynamic operand', () => {
    expect(verdict('rm -rf $BUILD_DIR', { cwd: '/', homeDirs: ['/home/u'] })).toBeNull();
    expect(verdict('echo x > $LOG', { cwd: '/etc', homeDirs: ['/home/u'] })).toBeNull();
    expect(verdict('dd of=/etc/pass$X')).toBe('block');
  });
});

describe('the matcher never throws into the gate', () => {
  it('holds a pattern picomatch cannot compile for approval', () => {
    const command = 'rm /etc/' + 'a'.repeat(70_000) + '*';
    const accesses = collectFileAccesses('Bash', { command }, context);
    expect(evaluateProtectedFileAccess(accesses, context, {})).toMatchObject({
      decision: 'review',
      ruleName: 'file-inspection-incomplete',
    });
  });
  it('keeps the block found beside an uncompilable pattern', () => {
    const command = 'echo x >> /etc/sudoers; : > /etc/[a' + 'b'.repeat(70_000) + ']';
    expect(verdict(command)).toBe('block');
  });
  it('reaches the same verdicts through the policy engine', async () => {
    const config = structuredClone(DEFAULT_CONFIG);
    config.policy.sandboxPaths = [];
    const ctx = { agent: 'Claude Code', ...context };
    const long = await evaluatePolicy(
      config,
      'Bash',
      { command: 'rm /etc/' + 'a'.repeat(70_000) + '*' },
      ctx
    );
    expect(long.decision).toBe('review');
    const block = await evaluatePolicy(config, 'Bash', { command: 'sudo -n rm /etc/passwd' }, ctx);
    expect(block).toMatchObject({ decision: 'block', ruleName: 'block-system-auth-mutation' });
  });
});

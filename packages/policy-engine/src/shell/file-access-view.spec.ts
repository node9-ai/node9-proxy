import { describe, it, expect } from 'vitest';
import { fileAccessView } from './index';
import { evaluateSmartConditions } from '../rules';
import type { SmartRule } from '../types';

// node9Firewall#385: a jail of /usr or /bin met every script whose first line
// is `#!/usr/bin/env bash` and every command that runs a program by its path,
// because the jail's bash rule matched the path anywhere in the command text.
// The interpreter line and the program a command runs are not file reads; an
// argument the program reads, a redirect and a script handed to an interpreter
// are. The jail's rules opt into this view with `reading: 'access'`.

// The fragment pathToRegexFragment builds for `/usr` and `/etc` (the jail's own
// shape, written out so this spec does not depend on the host package).
const USR = '(^|[\\s/\\\\])usr([\\s/\\\\]|$)';
const ETC = '(^|[\\s/\\\\])etc([\\s/\\\\]|$)';

const jailRule = (value: string, reading?: 'access'): SmartRule => ({
  name: 'block-path-usr-bash',
  tool: 'bash',
  conditions: [{ field: 'command', op: 'matches', value, ...(reading ? { reading } : {}) }],
  verdict: 'block',
});

const hits = (command: string, value = USR) =>
  evaluateSmartConditions({ command }, jailRule(value, 'access'));
const hitsWholeText = (command: string) => evaluateSmartConditions({ command }, jailRule(USR));

describe('fileAccessView', () => {
  it('drops a clean interpreter line', () => {
    expect(fileAccessView('#!/usr/bin/env bash\necho hi')).toBe('\necho hi');
    expect(fileAccessView('#!/bin/bash -e\necho hi')).toBe('\necho hi');
    expect(fileAccessView('#!/usr/bin/env -S python3 -u\nprint(1)')).toBe('\nprint(1)');
  });

  it('keeps an interpreter line that carries shell syntax (cmd.exe would run it)', () => {
    const cmd = '#!/bin/bash & type C:\\x\necho hi';
    expect(fileAccessView(cmd).startsWith('#!/bin/bash & type')).toBe(true);
    expect(fileAccessView('#!/bin/sh; cat /etc/hosts\n')).toContain('/etc/hosts');
  });

  it('only the first line is an interpreter line', () => {
    expect(fileAccessView('echo a\n#!/usr/bin/env bash')).toContain('/usr/bin/env');
  });

  it('shortens the program each command runs to its name', () => {
    expect(fileAccessView('/usr/bin/python3 app.py')).toBe('python3 app.py');
    expect(fileAccessView('sudo /usr/sbin/service nginx reload')).toBe('sudo service nginx reload');
    expect(fileAccessView('ls; /bin/echo ok && ./bin/run')).toBe('ls; echo ok && run');
  });

  it('a program outside the system program directories keeps its path (review finding)', () => {
    expect(fileAccessView('~/.gmail-mcp/dump-token.sh')).toBe('~/.gmail-mcp/dump-token.sh');
    expect(fileAccessView('/home/u/.aws/print.sh --all')).toBe('/home/u/.aws/print.sh --all');
    expect(fileAccessView('../../home/u/.aws/print.sh')).toBe('../../home/u/.aws/print.sh');
    expect(fileAccessView('/usr/local/bin/tool x')).toBe('tool x');
  });

  it('keeps every argument and redirect', () => {
    expect(fileAccessView('/bin/cat /etc/hosts')).toBe('cat /etc/hosts');
    expect(fileAccessView('/usr/bin/wc -l < /etc/hosts')).toBe('wc -l < /etc/hosts');
    expect(fileAccessView('bash /etc/x.sh')).toBe('bash /etc/x.sh');
  });

  it('leaves a dynamic program word alone', () => {
    expect(fileAccessView('"$BIN"/usr/x arg')).toBe('"$BIN"/usr/x arg');
  });

  it('returns an unparsable command unchanged', () => {
    expect(fileAccessView('/usr/bin/x "unterminated')).toBe('/usr/bin/x "unterminated');
  });
});

describe("a jail rule with reading: 'access'", () => {
  it('does not meet an interpreter line', () => {
    expect(hits('#!/usr/bin/env bash\nfor i in 1 2; do echo "$i"; done')).toBe(false);
  });

  it('does not meet the program a command runs', () => {
    expect(hits('/usr/bin/python3 app.py')).toBe(false);
    expect(hits('env /usr/bin/node build.js')).toBe(false);
  });

  it('still meets a file the command reads', () => {
    expect(hits('cat /usr/share/dict/words')).toBe(true);
    expect(hits('#!/usr/bin/env bash\ncat /usr/share/dict/words')).toBe(true);
    expect(hits('/usr/bin/python3 /usr/lib/x.py')).toBe(true);
    expect(hits('wc -l < /etc/hosts', ETC)).toBe(true);
    expect(hits('bash /etc/x.sh', ETC)).toBe(true);
  });

  it('still meets a script run from inside a jailed directory', () => {
    const AWS = '(^|[\\s/\\\\])\\.aws([\\s/\\\\]|$)';
    expect(hits('~/.aws/print-keys.sh', AWS)).toBe(true);
  });

  it('still meets a path inside a literal shell payload', () => {
    expect(hits("bash -c 'cat /usr/share/x'")).toBe(true);
  });

  it('a rule without the reading keeps matching the whole text', () => {
    expect(hitsWholeText('#!/usr/bin/env bash\necho hi')).toBe(true);
    expect(hitsWholeText('/usr/bin/python3 app.py')).toBe(true);
  });
});

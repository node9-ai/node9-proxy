// fw#372 A3: the script files a command runs, as written. The host asks the
// daemon whether the session wrote them and judges their content; this
// extractor only names them.
import { describe, it, expect } from 'vitest';
import { shellScriptOperands, MAX_SCRIPT_OPERANDS } from './index';

describe('shellScriptOperands', () => {
  it('the first operand of a shell, with flags and -- skipped', () => {
    expect(shellScriptOperands('bash x.sh')).toEqual(['x.sh']);
    expect(shellScriptOperands('sh -e ./scripts/x.sh arg1 arg2')).toEqual(['./scripts/x.sh']);
    expect(shellScriptOperands('bash -o pipefail -x run.sh')).toEqual(['run.sh']);
    expect(shellScriptOperands('zsh -- ./x.sh')).toEqual(['./x.sh']);
    expect(shellScriptOperands('source env.sh')).toEqual(['env.sh']);
    expect(shellScriptOperands('. ./lib.sh')).toEqual(['./lib.sh']);
  });

  it('a path run directly, through wrappers and chains', () => {
    expect(shellScriptOperands('./deploy.sh')).toEqual(['./deploy.sh']);
    expect(shellScriptOperands('/tmp/run.sh --fast')).toEqual(['/tmp/run.sh']);
    expect(shellScriptOperands('sudo bash setup.sh')).toEqual(['setup.sh']);
    expect(shellScriptOperands('chmod +x x.sh && ./x.sh')).toEqual(['./x.sh']);
    expect(shellScriptOperands('cd build && bash ../scripts/a.sh; sh b.sh')).toEqual([
      '../scripts/a.sh',
      'b.sh',
    ]);
  });

  it('inline code, bare commands, dynamic operands and installed tools are not scripts', () => {
    expect(shellScriptOperands("bash -c 'echo hi'")).toEqual([]);
    expect(shellScriptOperands('ls -la')).toEqual([]);
    expect(shellScriptOperands('npm run build')).toEqual([]);
    expect(shellScriptOperands('bash "$SCRIPT"')).toEqual([]);
    expect(shellScriptOperands('./node_modules/.bin/vitest run')).toEqual([]);
    expect(shellScriptOperands('node_modules/.bin/tsc -p .')).toEqual([]);
    expect(shellScriptOperands('bash')).toEqual([]);
    expect(shellScriptOperands('cat x.sh')).toEqual([]);
  });

  it('is bounded and never throws on unparsable text', () => {
    const many = Array.from({ length: 20 }, (_, i) => `bash s${i}.sh`).join('; ');
    expect(shellScriptOperands(many)).toHaveLength(MAX_SCRIPT_OPERANDS);
    expect(shellScriptOperands('bash x.sh ((')).toEqual([]);
  });
});

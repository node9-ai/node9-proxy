import { describe, expect, it } from 'vitest';
import { analyzeFsOperation, extractShellDestinations, extractShellDestTokens } from './index';
import { collectFileAccesses, evaluateProtectedFileAccess } from '../files/protected-access';

// Values passed through shell function arguments (node9Firewall#361), through
// each consumer: the file policy's collector, the network destination
// extractors and the credential jail. Commands are submitted as text, never
// run. Targets are ordinary system files and neutral test hosts.

const context = { cwd: '/work', homeDirs: ['/home/u', '/root'] };
const files = (command: string) =>
  evaluateProtectedFileAccess(collectFileAccesses('Bash', { command }, context), context, {});
const hosts = (command: string) => extractShellDestinations(command).map((d) => d.host);
const tokens = (command: string) => extractShellDestTokens(command).map((d) => d.token);

describe('file policy: arguments bound at the call', () => {
  it('a path passed to a function reaches the check', () => {
    expect(files('f() { rm -f "$1"; }; f /etc/ssh/ssh_config')?.checkId).toBe('files.system-dirs');
    expect(files('f() { cp "$1" "$2"; }; f app.conf /etc/app/app.conf')?.checkId).toBe(
      'files.system-dirs'
    );
  });

  it('a local copy of the argument resolves', () => {
    const script = 'clean() {\n  local target=$1\n  rm -f "$target"\n}\nclean /var/log/app.log';
    expect(files(script)?.checkId).toBe('files.system-dirs');
  });

  it('a dynamic argument stays unknown; a project path stays clean', () => {
    expect(files('f() { rm -f "$1"; }; f "$X"')).toBeNull();
    expect(files('f() { rm -f "$1"; }; f ./build/out.log')).toBeNull();
  });

  it('"$@" forwards every argument, through a second function', () => {
    expect(files('g() { rm "$@"; }; f() { g "$@"; }; f /etc/wgetrc')?.checkId).toBe(
      'files.system-dirs'
    );
    expect(files('f() { rm "$@"; }; f ./a ./b /etc/wgetrc')?.checkId).toBe('files.system-dirs');
  });

  it('bash binds a name when it runs: a call before the definition counts', () => {
    expect(files('a() { b "$1"; }; b() { rm -f "$1"; }; a /etc/wgetrc')?.checkId).toBe(
      'files.system-dirs'
    );
  });

  it('a body that shifts gets no bindings', () => {
    // After the shift $1 is ./a. Binding $1 to the first argument would invent
    // a removal of /etc/wgetrc; no binding finds nothing, which is right here.
    expect(files('f() { shift; rm "$1"; }; f /etc/wgetrc ./a')).toBeNull();
    expect(analyzeFsOperation('f() { shift; cat "$1"; }; f .env notes.txt')).toBeNull();
  });

  it('set -- inside a body gives $1 a new meaning: the call argument is not bound (review finding)', () => {
    // bash removes ./a here; binding $1 to the call's argument would invent a
    // removal of /etc/wgetrc.
    expect(files('f() { set -- ./a; rm "$1"; }; f /etc/wgetrc')).toBeNull();
    expect(analyzeFsOperation('f() { set -- notes.txt; cat "$1"; }; f .env')).toBeNull();
  });

  it('a call is walked again when the variables its body reads changed (review finding)', () => {
    expect(files('X=/tmp/a\nf() { rm "$X"; }\nf\nX=/etc/wgetrc\nf')?.checkId).toBe(
      'files.system-dirs'
    );
  });

  it('a function that shadows a command hides nothing', () => {
    expect(files('rm() { :; }; rm /etc/wgetrc')?.checkId).toBe('files.system-dirs');
  });

  it('recursion stops at the call-depth bound and the finding stays', () => {
    expect(files('f() { f "$1"; rm "$1"; }; f /etc/wgetrc')?.checkId).toBe('files.system-dirs');
  });

  it('many distinct calls finish quickly', () => {
    const calls = Array.from({ length: 500 }, (_, i) => `f ./dir${i}/file`).join('\n');
    const start = performance.now();
    files(`f() { rm -f "$1"; }\n${calls}`);
    // A guard against explosive growth, not a benchmark: 3 s under a loaded
    // full-suite run (fw#411); an exponential walk is minutes.
    expect(performance.now() - start).toBeLessThan(8000);
  });
});

describe('destinations: variables and function arguments', () => {
  it('a URL in a literal top-level variable names its host', () => {
    expect(hosts('u=https://api.example.test/v1; curl "$u"')).toEqual(['api.example.test']);
    expect(tokens('u=https://api.example.test/v1; curl "$u"')).toEqual(['api.example.test']);
  });

  it('a URL passed to a function names its host', () => {
    const script =
      'fetch_page() {\n  local url=$1\n  curl -s "$url"\n}\nfetch_page "https://docs.example.test/a"';
    expect(hosts(script)).toEqual(['docs.example.test']);
    expect(tokens(script)).toEqual(['docs.example.test']);
  });

  it('an assignment between the definition and the call is visible in the body (review finding)', () => {
    expect(hosts('f() { curl "$u"; }\nu=https://x.example.test\nf')).toEqual(['x.example.test']);
  });

  it('an unknown argument and a later assignment name nothing', () => {
    expect(hosts('fetch() { curl -s "$1"; }; fetch "$u"')).toEqual([]);
    expect(hosts('curl "$u"; u=https://late.example.test')).toEqual([]);
  });

  it('the two extractors agree on a wrapped command', () => {
    expect(hosts('sudo curl https://api.example.test/x')).toEqual(['api.example.test']);
    expect(tokens('sudo curl https://api.example.test/x')).toEqual(['api.example.test']);
  });
});

describe('credential jail: arguments bound at the call', () => {
  it('a jailed file read through a function argument is judged like the direct read', () => {
    const direct = analyzeFsOperation('cat .env')?.verdict;
    expect(direct).toBe('block');
    expect(analyzeFsOperation('show() { cat "$1"; }; show .env')?.verdict).toBe(direct);
    expect(analyzeFsOperation('show() { local f=$1; cat "$f"; }; show .env')?.verdict).toBe(direct);
  });

  it('a variable assigned after the definition and before the call is visible (review finding)', () => {
    expect(analyzeFsOperation('f() { cat "$K"; }\nK=.env\nf')?.verdict).toBe('block');
  });

  it('nested payloads share one call budget and finish quickly (review finding)', () => {
    // A guard against explosive growth, not a benchmark: 16 payloads of 16
    // calls each stay far below the hook's time limit even under load.
    const calls = Array.from({ length: 16 }, (_, i) => `f ./d${i}`).join('; ');
    const payload = `f() { cat "$1"; }; ${calls}`;
    const command = Array.from({ length: 16 }, (_, i) => `sh -c '${payload}; echo ${i}'`).join(
      '\n'
    );
    const start = performance.now();
    analyzeFsOperation(command);
    expect(performance.now() - start).toBeLessThan(10_000);
  });

  it('an ordinary file through the same function stays allowed', () => {
    expect(analyzeFsOperation('show() { cat "$1"; }; show notes.txt')).toBeNull();
  });
});

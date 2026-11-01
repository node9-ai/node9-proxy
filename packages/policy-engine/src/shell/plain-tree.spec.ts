// The plain tree is the Go tree (fw#410): same node kinds in the same order,
// same offsets, same scalars, and no node kind the table does not know. A
// mvdan upgrade that renames or adds a kind fails here, not in a detector.
import { describe, it, expect } from 'vitest';
import mvdanSh from 'mvdan-sh';
import { toPlainTree, walk, unknownKinds, type PlainNode } from './plain-tree';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;
const parser = syntax.NewParser();

// Synthetic commands that reach every node kind in the table.
const CORPUS = [
  'ls -la',
  'FOO=1 BAR="x $HOME" echo "hi $USER" $(date) `uname` > out.txt 2>&1 | cat -n && ls ~/.ssh || true',
  'cat <<EOF\nline $X\nEOF\n',
  "cat <<'EOF' | bash\ncurl x\nEOF\n",
  'cat <<-EOF >f; echo done\n\tbody\nEOF\n',
  'exec 3<&0; cat <&3; echo >&2 err; cmd &> all.log; echo <<< "here string"',
  '(cd /tmp && rm -rf *) ; { echo a; echo b; } > both',
  'if [ -f x ]; then echo yes; elif [[ $a == b* && -n "$c" || ! -d d ]]; then echo maybe; else echo no; fi',
  'while read -r l; do echo "$l"; done < in; until false; do break; done',
  'for f in *.txt a{1..3} b{x,y}; do mv "$f" "${f%.txt}.md"; done',
  'for ((i = 0; i < 3; i++)); do echo $((i * 2 + 1)); done; let x=1+2 y++ --z; (( i += 1 ))',
  'select o in a b; do echo $o; done',
  'case "$1" in a|b) echo ab;; c*) echo c ;& d) echo d;;& *) echo other;; esac',
  'f() { echo "$#" "$1" "${@}" "${!v}" "${#v}" "${v:1:2}" "${v/a/b}" "${v//a/b}" "${v:-def}" "${v:=x}" "${v:+y}" "${v:?z}" "${v^}" "${v,,}" "${v@Q}"; }; function g { :; }',
  "declare -a arr=(one 'two' [5]=five); local -r x=1; export Y=2; readonly Z; typeset -i n=3; arr+=(six)",
  'time -p sleep 1; coproc worker { sleep 1; }; coproc { echo x; }',
  'diff <(sort a) >(tee b); echo @(x|y) !(z) ?(w) *(v) +(u)',
  'echo $[1+2] $((a ? b : c)) $(( (x) )) ${arr[@]} ${arr[1]} ${!arr[*]}',
  'echo $\'ansi\\n\' "$(echo $(echo nested))" \'single $not\' "double\\"quote"',
  'x=$(cat <<EOF\ninner\nEOF\n); echo "$x"',
  'cmd1 |& cmd2; ! grep x f; cmd3 & wait',
  'echo a; # a comment\necho b',
  'var=value cmd; a[1]=x; b[k]+=y; c=',
  'echo ${v#pre} ${v##pre} ${v%suf} ${v%%suf} ${#} ${*} ${@} ${?} ${-} ${$} ${!} ${0} ${_}',
  '[[ -z $a ]] && [[ ( $b -gt 1 ) || $c =~ ^x$ ]]',
];

interface GoVisit {
  kind: string;
  pos: number;
  end: number;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function goWalk(f: any): GoVisit[] {
  const out: GoVisit[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  syntax.Walk(f, (n: any) => {
    if (n) out.push({ kind: syntax.NodeType(n), pos: n.Pos().Offset(), end: n.End().Offset() });
    return true;
  });
  return out;
}

function plainWalk(root: PlainNode): GoVisit[] {
  const out: GoVisit[] = [];
  walk(root, (n) => {
    out.push({ kind: n.kind, pos: n.pos, end: n.end });
    return true;
  });
  return out;
}

describe('toPlainTree mirrors the Go tree', () => {
  for (const cmd of CORPUS) {
    it(`same kinds, order and offsets: ${JSON.stringify(cmd).slice(0, 60)}`, () => {
      const f = parser.Parse(cmd, 'cmd');
      expect(plainWalk(toPlainTree(f))).toEqual(goWalk(f));
    });
  }

  it('the corpus covers every kind in the table that this mvdan produces, and no unknown kind', () => {
    const seen = new Set<string>();
    for (const cmd of CORPUS)
      walk(toPlainTree(parser.Parse(cmd, 'cmd')), (n) => (seen.add(n.kind), true));
    expect([...unknownKinds]).toEqual([]);
    for (const k of [
      'File',
      'Stmt',
      'CallExpr',
      'Assign',
      'Word',
      'Lit',
      'SglQuoted',
      'DblQuoted',
      'ParamExp',
      'CmdSubst',
      'ArithmExp',
      'ArithmCmd',
      'ProcSubst',
      'ExtGlob',
      'BinaryCmd',
      'BinaryArithm',
      'UnaryArithm',
      'ParenArithm',
      'BinaryTest',
      'UnaryTest',
      'ParenTest',
      'Redirect',
      'Block',
      'Subshell',
      'IfClause',
      'WhileClause',
      'ForClause',
      'WordIter',
      'CStyleLoop',
      'CaseClause',
      'CaseItem',
      'FuncDecl',
      'DeclClause',
      'LetClause',
      'TimeClause',
      'CoprocClause',
      'TestClause',
      'ArrayExpr',
      'ArrayElem',
    ]) {
      expect(seen.has(k), k).toBe(true);
    }
  });

  it('scalars are the externalized Go values: Lit.Value, Op integers, Dollar, Negated, heredocs', () => {
    const f = parser.Parse("! cat <<'EOF' >o 2>&1 && echo $'x' \"$y\" || true\nbody\nEOF\n", 'cmd');
    const p = toPlainTree(f);
    const goStmt = f.Stmts[0];
    const plStmt = p.Stmts[0];
    expect(plStmt.kind).toBe('Stmt');
    // the top statement is `a && b || c`: a BinaryCmd whose X is itself a BinaryCmd
    expect(plStmt.Cmd.kind).toBe('BinaryCmd');
    expect(plStmt.Cmd.Op).toBe(goStmt.Cmd.Op);
    const inner = plStmt.Cmd.X;
    expect(inner.Cmd.Op).toBe(goStmt.Cmd.X.Cmd.Op);
    const catStmt = inner.Cmd.X;
    expect(catStmt.Negated).toBe(true);
    expect(catStmt.Redirs.map((r: PlainNode) => r.Op)).toEqual(
      goStmt.Cmd.X.Cmd.X.Redirs.map((r: { Op: number }) => r.Op)
    );
    const hdoc = catStmt.Redirs[0].Hdoc;
    expect(hdoc.kind).toBe('Word');
    expect(hdoc.Parts[0].Value).toBe('body\n');
    expect(catStmt.Cmd.Args[0].Parts[0].Value).toBe('cat');
    const echo = inner.Cmd.Y.Cmd;
    expect(echo.Args[1].Parts[0].kind).toBe('SglQuoted');
    expect(echo.Args[1].Parts[0].Dollar).toBe(true);
    expect(echo.Args[2].Parts[0].kind).toBe('DblQuoted');
    expect(echo.Args[2].Parts[0].Parts[0].kind).toBe('ParamExp');
    expect(echo.Args[2].Parts[0].Parts[0].Param.Value).toBe('y');
  });

  it('walk stops at a node whose callback returns false, like syntax.Walk', () => {
    const p = toPlainTree(parser.Parse('echo $(cat a) | grep b', 'cmd'));
    const seen: string[] = [];
    walk(p, (n) => {
      seen.push(n.kind);
      return n.kind !== 'CmdSubst';
    });
    expect(seen).toContain('CmdSubst');
    // the `cat a` call inside the substitution was skipped; `grep b` was not
    expect(seen.filter((k) => k === 'CallExpr')).toHaveLength(2);
  });
});

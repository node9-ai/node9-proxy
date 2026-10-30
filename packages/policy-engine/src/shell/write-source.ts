// packages/policy-engine/src/shell/write-source.ts
// Is the content a shell command writes into a file readable from the
// command itself? `echo "x" > F`, `printf … > F`, `cat > F <<EOF`, `sed -i`,
// `touch F` and `: > F` carry their content (or none) in the text the
// content rule already scanned. `cp X F`, `mv X F`, `install`, `rsync`,
// `dd of=F`, a download into F, and `tee F < X` bring bytes from elsewhere:
// those are the writes whose content cannot be seen (node9Firewall#413 part 4).
import mvdanSh from 'mvdan-sh';
import { baseWord, parseShared, resolveWordLiteral, unwrapCommandHead } from './index';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

/** mvdan's operator number for `<`, read off the parser rather than written down. */
const RDR_IN: number | null = (() => {
  try {
    return parseShared('x <y').Stmts[0].Redirs[0].Op as number;
  } catch {
    return null;
  }
})();

/** Verbs that copy bytes from another file or the network into their target. */
const COPY_VERBS = new Set([
  'cp',
  'mv',
  'install',
  'rsync',
  'scp',
  'dd',
  'curl',
  'wget',
  'aria2c',
  'http',
  'https',
  'xh',
  'ln',
  'git',
  'base64',
  'gunzip',
  'unzip',
  'tar',
]);

/** Verbs whose operands are the text itself, not files to read. */
const LITERAL_VERBS = new Set(['echo', 'printf', ':', 'true', 'touch', 'sed']);

/**
 * True when the write to `target` (the path as the command spells it) takes
 * its bytes from somewhere the command text does not show. Conservative: a
 * command that does not parse, a statement whose head is dynamic, or a
 * target no statement is seen to write, all count as unseen.
 */
export function shellWriteUnseen(command: string, target: string): boolean {
  const f = parseShared(command);
  if (typeof f === 'symbol') return true;
  let unseen = false;
  let seen = false;
  try {
    syntax.Walk(f, (node: unknown) => {
      if (!node || unseen) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'Stmt' || !n.Cmd || syntax.NodeType(n.Cmd) !== 'CallExpr')
        return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const words: (string | null)[] = ((n.Cmd.Args || []) as any[]).map((a) =>
        resolveWordLiteral(a)
      );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const redirs: any[] = n.Redirs || [];
      const redirectsTo = redirs.some((r) => r.Word && resolveWordLiteral(r.Word) === target);
      const readsFromFile = redirs.some((r) => r.Op === RDR_IN && r.Word && !r.Hdoc);
      const named = words.includes(target);
      if (!redirectsTo && !named) return true;
      const head = unwrapCommandHead(words);
      if (words[head] === null) {
        unseen = true;
        return false;
      }
      const verb = baseWord(words[head]);
      // `cat /tmp/x > F`, `sort notes > F`: a redirect fed by a file operand.
      // `cat > F <<EOF` and `echo … > F` have no source file.
      const sourceOperand =
        redirectsTo &&
        !LITERAL_VERBS.has(verb) &&
        words.slice(head + 1).some((w) => w !== null && w !== target && !w.startsWith('-'));
      if (COPY_VERBS.has(verb) || readsFromFile || sourceOperand) {
        unseen = true;
        return false;
      }
      seen = true;
      return true;
    });
  } catch {
    return true;
  }
  return unseen || !seen;
}

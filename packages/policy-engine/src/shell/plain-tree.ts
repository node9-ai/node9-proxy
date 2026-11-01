// One plain JavaScript copy of a parsed shell command (fw#410).
//
// mvdan-sh is a GopherJS build: every read of a node field (`n.Args`,
// `n.Parts`, `Pos().Offset()`) externalizes a fresh copy across the Go/JS
// boundary, and every `syntax.Walk` callback crosses it once per node. The
// engine analyses one Bash call about ten times (fs operations, dangerous
// exec, destinations, exposure, script operands, normalisation, ...), so one
// judged call paid ten walks over a Go tree; measured at 64 ms per call on
// real commands, 16 ms of it the parse and the rest the boundary.
//
// This module converts the Go tree ONCE into plain objects (one read per
// field) and offers `walk`, the same traversal contract the engine's callbacks
// were written against. Field names are the Go names, so a reader of
// `n.Args`, `p.Value` or `n.Op` sees the same shape; `kind` replaces
// `syntax.NodeType(n)`, `pos`/`end` replace `Pos().Offset()`/`End().Offset()`.
// `Op` keeps the integer mvdan externalizes, which the engine compares against
// constants it derives by parsing sample commands.

import mvdanSh from 'mvdan-sh';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

/** A converted node. Child fields hold PlainNode | PlainNode[] | null; scalars
 *  hold what mvdan externalized (string, number, boolean). */
export interface PlainNode {
  kind: string;
  /** Byte offsets into the command's UTF-8 encoding, as mvdan reports them. */
  pos: number;
  end: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [field: string]: any;
}

interface KindSpec {
  /** Child fields in the order mvdan's Walk visits them. */
  nodes?: readonly string[];
  /** Scalar fields the engine reads. */
  scalars?: readonly string[];
  /** Child fields converted for readers but NOT visited by mvdan's Walk
   *  (walk.go skips them); `walk` skips them too, so the two agree. */
  notWalked?: readonly string[];
}

// mvdan.cc/sh/v3/syntax nodes.go / walk.go. Child order is the Walk order; the
// parity spec checks it kind by kind against the Go walk.
const KINDS: Record<string, KindSpec> = {
  File: { nodes: ['Stmts'] },
  Stmt: { nodes: ['Cmd', 'Redirs'], scalars: ['Negated', 'Background', 'Coprocess'] },
  CallExpr: { nodes: ['Assigns', 'Args'] },
  Assign: { nodes: ['Name', 'Value', 'Index', 'Array'], scalars: ['Append', 'Naked'] },
  Word: { nodes: ['Parts'] },
  Lit: { scalars: ['Value'] },
  SglQuoted: { scalars: ['Value', 'Dollar'] },
  DblQuoted: { nodes: ['Parts'], scalars: ['Dollar'] },
  ParamExp: {
    nodes: ['Param', 'Index', 'Slice', 'Repl', 'Exp'],
    scalars: ['Short', 'Excl', 'Length', 'Width'],
  },
  CmdSubst: { nodes: ['Stmts'], scalars: ['Backquotes', 'TempFile', 'ReplyVar'] },
  ArithmExp: { nodes: ['X'], scalars: ['Bracket', 'Unsigned'] },
  ArithmCmd: { nodes: ['X'], scalars: ['Unsigned'] },
  ProcSubst: { nodes: ['Stmts'], scalars: ['Op'] },
  ExtGlob: { nodes: ['Pattern'], scalars: ['Op'] },
  BraceExp: { nodes: ['Elems'], scalars: ['Sequence'] }, // only with SplitBraces, unused here
  BinaryCmd: { nodes: ['X', 'Y'], scalars: ['Op'] },
  BinaryArithm: { nodes: ['X', 'Y'], scalars: ['Op'] },
  UnaryArithm: { nodes: ['X'], scalars: ['Op', 'Post'] },
  ParenArithm: { nodes: ['X'] },
  BinaryTest: { nodes: ['X', 'Y'], scalars: ['Op'] },
  UnaryTest: { nodes: ['X'], scalars: ['Op'] },
  ParenTest: { nodes: ['X'] },
  Redirect: { nodes: ['N', 'Word', 'Hdoc'], scalars: ['Op'] },
  Block: { nodes: ['Stmts'] },
  Subshell: { nodes: ['Stmts'] },
  IfClause: { nodes: ['Cond', 'Then', 'Else'] },
  WhileClause: { nodes: ['Cond', 'Do'], scalars: ['Until'] },
  ForClause: { nodes: ['Loop', 'Do'], scalars: ['Select'] },
  WordIter: { nodes: ['Name', 'Items'] },
  CStyleLoop: { nodes: ['Init', 'Cond', 'Post'] },
  CaseClause: { nodes: ['Word', 'Items'] },
  CaseItem: { nodes: ['Patterns', 'Stmts'], scalars: ['Op'] },
  FuncDecl: { nodes: ['Name', 'Body'], scalars: ['RsrvWord'] },
  DeclClause: { nodes: ['Variant', 'Args'], notWalked: ['Variant'] },
  LetClause: { nodes: ['Exprs'] },
  TimeClause: { nodes: ['Stmt'], scalars: ['PosixFormat'] },
  CoprocClause: { nodes: ['Name', 'Stmt'] },
  TestClause: { nodes: ['X'] },
  TestDecl: { nodes: ['Description', 'Body'] },
  ArrayExpr: { nodes: ['Elems'] },
  ArrayElem: { nodes: ['Index', 'Value'] },
  Comment: { scalars: ['Text'] },
};

// ParamExp's `Slice`, `Repl` and `Exp` are plain Go structs, not nodes: they
// have no Pos/End and the Go Walk never visits them, only their children.
// They convert to objects without `kind`, flagged `struct`, and `childrenOf`
// descends through them.
const STRUCTS: Record<string, KindSpec> = {
  'ParamExp.Slice': { nodes: ['Offset', 'Length'], notWalked: ['Offset', 'Length'] },
  'ParamExp.Repl': { nodes: ['Orig', 'With'], scalars: ['All'] },
  'ParamExp.Exp': { nodes: ['Word'], scalars: ['Op'] },
};

/** Kinds met by `toPlainTree` that the table does not know. Such a node keeps
 *  `kind`, `pos` and `end` only; the parity spec asserts this stays empty for
 *  the corpus, so a new mvdan version cannot silently drop children. */
export const unknownKinds = new Set<string>();

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isGoNode(v: any): boolean {
  return v !== null && typeof v === 'object' && typeof v.Pos === 'function';
}

/** Convert a mvdan node (a parsed File, usually) into a PlainNode tree. Each
 *  Go field is read exactly once. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function toPlainTree(goNode: any): PlainNode {
  const kind: string = syntax.NodeType(goNode);
  const out: PlainNode = { kind, pos: goNode.Pos().Offset(), end: goNode.End().Offset() };
  const spec = KINDS[kind];
  if (!spec) {
    unknownKinds.add(kind);
    return out;
  }
  convertFields(goNode, spec, out, kind);
  return out;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function convertFields(goNode: any, spec: KindSpec, out: PlainNode, kind: string): void {
  for (const f of spec.scalars ?? []) out[f] = goNode[f];
  for (const f of spec.nodes ?? []) {
    const v = goNode[f];
    if (v === undefined || v === null) {
      out[f] = null;
    } else if (Array.isArray(v)) {
      out[f] = v.map((c) => (isGoNode(c) ? toPlainTree(c) : c));
    } else if (isGoNode(v)) {
      out[f] = toPlainTree(v);
    } else if (typeof v === 'object' && STRUCTS[`${kind}.${f}`]) {
      const sub: PlainNode = { struct: `${kind}.${f}` } as unknown as PlainNode;
      convertFields(v, STRUCTS[`${kind}.${f}`], sub, `${kind}.${f}`);
      out[f] = sub;
    } else {
      out[f] = v;
    }
  }
}

/** The children of a plain node, in Walk order. */
export function childrenOf(n: PlainNode): PlainNode[] {
  const spec = n.kind ? KINDS[n.kind] : STRUCTS[n.struct as string];
  if (!spec?.nodes) return [];
  const out: PlainNode[] = [];
  for (const f of spec.nodes) {
    if (spec.notWalked?.includes(f)) continue;
    const v = n[f];
    if (!v) continue;
    if (Array.isArray(v)) {
      for (const c of v) if (c) out.push(c);
    } else if (v.kind) {
      out.push(v);
    } else if (v.struct) {
      out.push(...childrenOf(v)); // a struct is not a node: its children are
    }
  }
  return out;
}

/**
 * Depth-first traversal with `syntax.Walk`'s contract for the engine's
 * callbacks: `fn(node)` is called for each node; returning `false` skips that
 * node's children. Unlike the Go Walk, `fn` is never called with `null` (the
 * engine's callbacks all began with `if (!node) return false`).
 */
export function walk(root: PlainNode | null | undefined, fn: (node: PlainNode) => boolean): void {
  if (!root) return;
  if (!fn(root)) return;
  for (const c of childrenOf(root)) walk(c, fn);
}

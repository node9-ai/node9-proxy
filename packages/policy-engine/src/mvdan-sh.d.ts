declare module 'mvdan-sh' {
  interface SyntaxNode {
    [key: string]: unknown;
  }
  interface Syntax {
    NewParser(): { Parse(src: string, name: string): SyntaxNode };
    Walk(node: SyntaxNode, fn: (node: SyntaxNode | null) => boolean): void;
    NodeType(node: SyntaxNode): string;
  }
  const syntax: Syntax;
  export default { syntax };
}

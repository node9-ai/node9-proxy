// src/context-sniper.ts
// Shared Context Sniper module.
// Pre-computes the code snippet and intent ONCE in authorizeHeadless (core.ts),
// then the resulting RiskMetadata bundle flows to every approval channel:
// native popup, browser daemon, cloud/SaaS backend, Slack, and Mission Control.

import path from 'path';

export interface RiskMetadata {
  intent: 'EDIT' | 'EXEC';
  tier: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  blockedByLabel: string;
  matchedWord?: string;
  matchedField?: string;
  contextSnippet?: string; // Pre-computed 7-line window with 🛑 marker
  contextLineIndex?: number; // Index of the 🛑 line within the snippet (0-based)
  editFileName?: string; // basename of file_path (EDIT intent only)
  editFilePath?: string; // full file_path (EDIT intent only)
  ruleName?: string; // Tier 2 (Smart Rules) only
}

/** Keeps the start and end of a long string, truncating the middle. */
export function smartTruncate(str: string, maxLen = 500): string {
  if (str.length <= maxLen) return str;
  const edge = Math.floor(maxLen / 2) - 3;
  return `${str.slice(0, edge)} ... ${str.slice(-edge)}`;
}

/**
 * Returns the 7-line context window centred on matchedWord, plus the
 * 0-based index of the hit line within the returned snippet.
 * If the text is short or the word isn't found, returns the full text and lineIndex -1.
 */
export function extractContext(
  text: string,
  matchedWord?: string
): { snippet: string; lineIndex: number } {
  const lines = text.split('\n');
  if (lines.length <= 7 || !matchedWord) {
    return { snippet: smartTruncate(text, 500), lineIndex: -1 };
  }

  const escaped = matchedWord.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`\\b${escaped}\\b`, 'i');

  const allHits = lines.map((line, i) => ({ i, line })).filter(({ line }) => pattern.test(line));
  if (allHits.length === 0) return { snippet: smartTruncate(text, 500), lineIndex: -1 };

  // Prefer non-comment lines so we highlight actual code, not documentation
  const nonComment = allHits.find(({ line }) => {
    const trimmed = line.trim();
    return !trimmed.startsWith('//') && !trimmed.startsWith('#');
  });
  const hitIndex = (nonComment ?? allHits[0]).i;

  const start = Math.max(0, hitIndex - 3);
  const end = Math.min(lines.length, hitIndex + 4);
  const lineIndex = hitIndex - start;

  const snippet = lines
    .slice(start, end)
    .map((line, i) => `${start + i === hitIndex ? '🛑 ' : '   '}${line}`)
    .join('\n');

  const head = start > 0 ? `... [${start} lines hidden] ...\n` : '';
  const tail = end < lines.length ? `\n... [${lines.length - end} lines hidden] ...` : '';

  return { snippet: `${head}${snippet}${tail}`, lineIndex };
}

const CODE_KEYS = [
  'command',
  'cmd',
  'shell_command',
  'bash_command',
  'script',
  'code',
  'input',
  'sql',
  'query',
  'arguments',
  'args',
  'param',
  'params',
  'text',
];

/**
 * Computes the RiskMetadata bundle from args + policy result fields.
 * Called once in authorizeHeadless; the result is forwarded unchanged to all channels.
 */
export function computeRiskMetadata(
  args: unknown,
  tier: RiskMetadata['tier'],
  blockedByLabel: string,
  matchedField?: string,
  matchedWord?: string,
  ruleName?: string
): RiskMetadata {
  let intent: 'EDIT' | 'EXEC' = 'EXEC';
  let contextSnippet: string | undefined;
  let contextLineIndex: number | undefined;
  let editFileName: string | undefined;
  let editFilePath: string | undefined;

  // Handle Gemini-style stringified JSON
  let parsed = args;
  if (typeof args === 'string') {
    const trimmed = args.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        /* keep as string */
      }
    }
  }

  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;

    if (obj.old_string !== undefined && obj.new_string !== undefined) {
      // EDIT intent — extract context from the incoming new_string
      intent = 'EDIT';
      if (obj.file_path) {
        editFilePath = String(obj.file_path);
        editFileName = path.basename(editFilePath);
      }
      const result = extractContext(String(obj.new_string), matchedWord);
      contextSnippet = result.snippet;
      if (result.lineIndex >= 0) contextLineIndex = result.lineIndex;
    } else if (matchedField && obj[matchedField] !== undefined) {
      // EXEC — we know which field triggered, extract context from it
      const result = extractContext(String(obj[matchedField]), matchedWord);
      contextSnippet = result.snippet;
      if (result.lineIndex >= 0) contextLineIndex = result.lineIndex;
    } else {
      // EXEC fallback — pick the first recognisable code-like key
      const foundKey = Object.keys(obj).find((k) => CODE_KEYS.includes(k.toLowerCase()));
      if (foundKey) {
        const val = obj[foundKey];
        contextSnippet = smartTruncate(typeof val === 'string' ? val : JSON.stringify(val), 500);
      }
    }
  } else if (typeof parsed === 'string') {
    contextSnippet = smartTruncate(parsed, 500);
  }

  return {
    intent,
    tier,
    blockedByLabel,
    ...(matchedWord && { matchedWord }),
    ...(matchedField && { matchedField }),
    ...(contextSnippet !== undefined && { contextSnippet }),
    ...(contextLineIndex !== undefined && { contextLineIndex }),
    ...(editFileName && { editFileName }),
    ...(editFilePath && { editFilePath }),
    ...(ruleName && { ruleName }),
  };
}

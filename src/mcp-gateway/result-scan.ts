// src/mcp-gateway/result-scan.ts
// Response-channel checks for MCP tool results passing through the gateway.
//
// The gateway sees every upstream tool result in plain text before the agent
// does, which is the one place a returned secret can be redacted and injected
// text framed BEFORE the model reads it (the PostToolUse hook in
// cli/commands/log.ts can only do that for agents whose shim mutates output).
// Pure over its inputs: the caller supplies the config slice and performs the
// side effects (session taint, stderr) from the returned findings.
import { redactText, scanInjection, type InjectionMatch, type InjectionConfidence } from '../dlp';
import { newUntrustedFrame, newSourceFrame, neutralizeMarkers } from '../utils/untrusted-frame';
import { extractContentDestinations } from '@node9/policy-engine';

export interface ResultScanConfig {
  /** policy.dlp.enabled — secret redaction. */
  dlpEnabled: boolean;
  /** policy.injectionScan — framing of injected text. */
  injection: { enabled: boolean; minConfidence: 'medium' | 'high'; allow: string[] };
  /** fw#318 spotlight: frame EVERY result as data from this kind of source
   *  ('email', 'web page', ...). Undefined keeps the detection-only framing. */
  spotlight?: string;
}

export interface ResultScan {
  /** The line to forward: the input when nothing changed. */
  line: string;
  changed: boolean;
  /** DLP pattern names redacted out of the result (deduplicated). */
  secrets: string[];
  /** Actionable injection match, or null. */
  injection: InjectionMatch | null;
  /** fw#318: destination-like values in the result text (emails, hosts, IBANs). */
  destinations: string[];
}

const CONFIDENCE_RANK: Record<InjectionConfidence, number> = { low: 0, medium: 1, high: 2 };

type TextContent = { type: 'text'; text: string; [k: string]: unknown };

function isTextContent(item: unknown): item is TextContent {
  return (
    typeof item === 'object' &&
    item !== null &&
    (item as { type?: unknown }).type === 'text' &&
    typeof (item as { text?: unknown }).text === 'string'
  );
}

/**
 * Scan one JSON-RPC response line that answers a tracked `tools/call`.
 * `parsed` is the already-parsed line. Text content items are redacted in
 * place; `structuredContent` is redacted through its JSON form. When the
 * post-redaction text reads as injected, a header and footer content item
 * frame the whole result as data. Anything that is not a tool result (no
 * `result.content` array) is returned unchanged.
 */
export function scanToolResult(
  line: string,
  parsed: unknown,
  tool: string,
  cfg: ResultScanConfig
): ResultScan {
  const unchanged: ResultScan = {
    line,
    changed: false,
    secrets: [],
    injection: null,
    destinations: [],
  };
  if (typeof parsed !== 'object' || parsed === null) return unchanged;
  const result = (parsed as { result?: unknown }).result;
  if (typeof result !== 'object' || result === null) return unchanged;
  const res = result as { content?: unknown; structuredContent?: unknown; isError?: unknown };
  if (!Array.isArray(res.content)) return unchanged;
  // An error result carries the server's message, not outside content; the
  // DLP still redacts it, spotlight leaves it alone so clients that read the
  // message verbatim keep working.
  const spotlight = res.isError === true ? undefined : cfg.spotlight;

  const secrets = new Set<string>();
  let mutated = false;
  const texts: string[] = [];

  const content = res.content.map((item) => {
    if (!isTextContent(item)) return item;
    let text = item.text;
    if (cfg.dlpEnabled) {
      const { result: redacted, found } = redactText(text);
      if (found.length > 0) {
        found.forEach((f) => secrets.add(f));
        text = redacted;
        mutated = true;
      }
    }
    texts.push(text);
    return text === item.text ? item : { ...item, text };
  });

  let structured = res.structuredContent;
  if (structured !== undefined && cfg.dlpEnabled) {
    let json: string | null = null;
    try {
      json = JSON.stringify(structured);
    } catch {
      json = null; // not serialisable — nothing to scan or redact
    }
    if (json !== null) {
      const { result: redacted, found } = redactText(json);
      if (found.length > 0) {
        found.forEach((f) => secrets.add(f));
        mutated = true;
        try {
          structured = JSON.parse(redacted);
        } catch {
          // The redaction marker broke the JSON shape (a secret inside a key
          // or a bare value): drop the structured copy rather than leak it.
          structured = undefined;
        }
      }
      texts.push(json);
    }
  }

  let injection: InjectionMatch | null = null;
  const inj = cfg.injection;
  if (inj.enabled && !inj.allow.includes(tool) && texts.length > 0) {
    const m = scanInjection(texts.join('\n'), { tool });
    if (m && CONFIDENCE_RANK[m.confidence] >= CONFIDENCE_RANK[inj.minConfidence]) {
      injection = m;
      mutated = true;
    }
  }

  const destinations = texts.length > 0 ? extractContentDestinations(texts.join('\n')) : [];
  if (spotlight !== undefined && texts.length > 0) mutated = true;
  if (!mutated) return { ...unchanged, destinations };

  // A fresh random boundary per result (utils/untrusted-frame.ts): content
  // that writes a footer of its own cannot close a frame it cannot name.
  // With spotlight the frame is the source frame and is applied always, and
  // it rides INSIDE the first and last text items rather than as items of
  // its own, so a client that reads `content[0].text` still finds its text
  // (prefixed), not a node9 header in place of it.
  let framed = content;
  if (spotlight !== undefined) {
    const frame = newSourceFrame(spotlight);
    const textIdx = content.map((item, i) => (isTextContent(item) ? i : -1)).filter((i) => i >= 0);
    const first = textIdx[0];
    const last = textIdx[textIdx.length - 1];
    framed = content.map((item, i) => {
      if (!isTextContent(item)) return item;
      let text = neutralizeMarkers(item.text);
      if (i === first) text = `${frame.header}\n${text}`;
      if (i === last) text = `${text}\n${frame.footer}`;
      return { ...item, text };
    });
  } else if (injection) {
    const frame = newUntrustedFrame();
    framed = [
      { type: 'text', text: frame.header },
      ...content.map((item) =>
        isTextContent(item) ? { ...item, text: neutralizeMarkers(item.text) } : item
      ),
      { type: 'text', text: frame.footer },
    ];
  }
  const nextResult: Record<string, unknown> = {
    ...(result as Record<string, unknown>),
    content: framed,
  };
  if (res.structuredContent !== undefined) {
    if (structured === undefined) delete nextResult.structuredContent;
    else nextResult.structuredContent = structured;
  }
  const next = { ...(parsed as Record<string, unknown>), result: nextResult };
  return {
    line: JSON.stringify(next),
    changed: true,
    secrets: [...secrets],
    injection,
    destinations,
  };
}

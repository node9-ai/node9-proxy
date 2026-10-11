// src/ci-check/listing.ts
// A `gh` listing whose output is cut down to identifiers before anyone reads it carries no text a
// stranger wrote. Shared by the scheduled-reader rule (T.5) and the skill rule (T.8).

// A listing is sanitized only when every field it keeps is an identifier:
// `--jq '[.number, .title, .body]'` still hands over the body (review, round 2).
const SAFE_LIST_FIELD_RE =
  /^(?:number|url|html_url|id|node_id|sha|state|createdat|updatedat|closedat|mergedat|headrefname|baserefname|isdraft|headrefoid|login|user|author_association)$/i;
export function sanitizedListing(t: string): boolean {
  if (t.length > 50_000) return false;
  if (/\|\s*grep\s+-[a-zA-Z]*o/.test(t)) return true;
  const fieldsSafe = (expr: string, fieldRe: RegExp) => {
    const fields = [...expr.matchAll(fieldRe)].map((m) => m[1]);
    return fields.length > 0 && fields.every((f) => SAFE_LIST_FIELD_RE.test(f));
  };
  const jq = [
    ...t.matchAll(/(?:--jq|\s-q)[\s=]+(?:'([^']{0,500})'|"([^"]{0,500})"|([^\s'"]{1,200}))/g),
  ].map((m) => m[1] ?? m[2] ?? m[3]);
  if (jq.length) return jq.every((e) => fieldsSafe(e, /\.([A-Za-z_]\w{0,60})/g));
  const json = [...t.matchAll(/--json[\s=]+['"]?([\w,]{1,500})/g)].map((m) => m[1]);
  return json.length > 0 && json.every((e) => fieldsSafe(e, /([A-Za-z_]\w{0,60})/g));
}

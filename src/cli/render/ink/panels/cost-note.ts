// The CLI prices from tokens x list price and knows nothing about plans —
// on purpose: a plan is a fact about a PERSON, and only the cloud knows who
// is behind a key. For a machine that never connected this is the only
// report there is, so the panel must say what its number is and where the
// exact one lives. A connected machine is pointed at the dashboard instead
// of being told to connect.
//
// Two explicit lines rather than one wrapped sentence: the half-width panel
// is ~40 columns and a wrap would split "dashboard → Report" mid-phrase.
import { isKeyedForPolicy } from '../../../../config/keyed-guard.js';

export const COST_LABEL = 'COST · based on API value';

export function costNoteLines(keyed: boolean): [string, string] {
  return keyed
    ? ['Your plan and exact spend:', 'dashboard → Report']
    : ['To see your plan or exact spend, connect:', 'node9 login (for free)'];
}

/** Live (non-test) callers that have no explicit flag ask the config. */
export function costNoteLinesForThisMachine(): [string, string] {
  return costNoteLines(isKeyedForPolicy());
}

// Shared "· top N of M" suffix for panel titles whose rows are capped.
//
// The `… +N more` overflow line was deliberately removed from these panels to
// save a vertical row (the severity band above carries the total). That left no
// on-screen signal that a panel shows a subset — a list of 4 under a band that
// says 10 reads as a bug. Decision 2026-08-25: the subset signal lives in the
// panel TITLE, which costs zero rows. One helper so four panels cannot drift in
// phrasing.
export function topOf(shown: number, total: number): string {
  return total > shown ? ` · top ${shown} of ${total}` : '';
}

import fs from 'fs';

/**
 * Creates `dir` if needed (mode 0700) and says whether it is safe to keep
 * node9 state in: a real directory, not a link, owned by this user.
 *
 * Directories under ~/.node9 are reachable by the agent with mv and ln. A link
 * planted there would point node9's own writes, reads and clean-ups at a
 * directory the agent chose, so callers skip their state when this is false.
 * Any filesystem error also returns false.
 */
export function ensureOwnDir(dir: string): boolean {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const st = fs.lstatSync(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) return false;
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) return false;
    return true;
  } catch {
    return false;
  }
}

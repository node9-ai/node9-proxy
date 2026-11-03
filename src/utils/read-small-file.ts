import fs from 'fs';

/**
 * The text of `file` when it is a regular file of at most `maxBytes`, else
 * null. One descriptor does the check and the read, so a file swapped in after
 * the check cannot be read instead (CodeQL js/file-system-race); O_NONBLOCK
 * keeps a FIFO from stalling the open, and the read never goes past the limit.
 * A link is followed: dotfile managers link CLAUDE.md and settings files.
 */
export function readSmallFile(file: string, maxBytes: number): string | null {
  let fd: number;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  } catch {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return null;
    const buf = Buffer.alloc(Math.min(st.size, maxBytes));
    let read = 0;
    while (read < buf.length) {
      const n = fs.readSync(fd, buf, read, buf.length - read, read);
      if (n === 0) break;
      read += n;
    }
    return buf.toString('utf8', 0, read);
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

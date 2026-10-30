import fs from 'fs';

export interface CappedRead {
  /** At most `maxBytes` of file content. */
  bytes: Buffer;
  /** True when the file held more than `maxBytes`, so the caller can reject. */
  truncated: boolean;
}

/**
 * Read at most `maxBytes` from `file`, with the cap enforced by the read rather
 * than by a prior `statSync`.
 *
 * The pattern this replaces is:
 *
 *     const stat = fs.statSync(file);
 *     if (stat.size > CAP) return null;   // guard
 *     return fs.readFileSync(file);       // unbounded
 *
 * The guard reads one file and the read reads whatever the path points at by
 * then, so swapping the file in between defeats exactly the limit the guard
 * exists to impose (CodeQL js/file-system-race). `posture` walks paths the user
 * does not own, which is where that matters most.
 *
 * The size here comes from `fstat` on the already-open descriptor, not from
 * `stat` on the path. A descriptor is bound to the inode it opened, so nothing
 * that happens to the path afterwards can change what it describes. That also
 * keeps the allocation proportional to the file instead of to the cap, which
 * matters when a caller passes a large budget (skill-pin allows 50 MB in
 * total, and allocating that per file would be absurd).
 *
 * Returns null when the path cannot be opened or is not a regular file.
 * `openFlags` lets a caller on a hook path pass O_NONBLOCK, so a FIFO swapped
 * in at the path cannot hang the open.
 */
export function readCapped(
  file: string,
  maxBytes: number,
  openFlags: string | number = 'r'
): CappedRead | null {
  if (maxBytes < 0) return null;
  let fd: number;
  try {
    fd = fs.openSync(file, openFlags);
  } catch {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return null;
    // One byte past the cap is enough to know the file exceeded it.
    const want = Math.min(st.size, maxBytes + 1);
    const buf = Buffer.alloc(want);
    let read = 0;
    // readSync can return a short count; loop until the buffer is filled or
    // the file ends, so a slow or piped-in file is not silently truncated.
    while (read < want) {
      const n = fs.readSync(fd, buf, read, want - read, read);
      if (n <= 0) break;
      read += n;
    }
    return {
      bytes: buf.subarray(0, Math.min(read, maxBytes)),
      truncated: read > maxBytes,
    };
  } catch {
    return null;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      /* already closed */
    }
  }
}

/** `readCapped` as UTF-8 text. Same contract; null when unreadable. */
export function readCappedText(
  file: string,
  maxBytes: number,
  openFlags: string | number = 'r'
): { text: string; truncated: boolean } | null {
  const r = readCapped(file, maxBytes, openFlags);
  return r ? { text: r.bytes.toString('utf8'), truncated: r.truncated } : null;
}

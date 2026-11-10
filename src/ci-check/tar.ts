// src/ci-check/tar.ts
// A minimal, push-based tar reader for the repository archive GitHub serves (`git archive`
// output: ustar headers, pax `x`/`g` records). DATA ONLY: an entry's path is handed to the
// caller as a string and never touches the filesystem; nothing is extracted, nothing runs.
// Any malformed input throws TarError, and the caller drops the whole archive.
// Design: docs roadmap/active/scan-big-repos-tarball-design.md §3.2.

export class TarError extends Error {}

export type TarKind = 'file' | 'link' | 'other';

export interface TarEntry {
  path: string;
  kind: TarKind;
  /** Data bytes that follow the header (0 for a link). */
  size: number;
  /** A symlink's target text; '' for anything else. */
  linkname: string;
}

const BLOCK = 512;
/** A pax record set or GNU long name larger than this is not a real archive. */
const MAX_META_BYTES = 1024 * 1024;

const isZero = (b: Buffer): boolean => {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
};

function cstr(b: Buffer, start: number, len: number): string {
  const end = b.indexOf(0, start);
  const stop = end === -1 || end > start + len ? start + len : end;
  return b.toString('utf8', start, stop);
}

/** Octal, NUL/space padded; or GNU base-256 when the high bit of the first byte is set. */
function numeric(b: Buffer, start: number, len: number): number {
  if (b[start] & 0x80) {
    if (b[start] !== 0x80) throw new TarError('negative or oversized base-256 number');
    let n = 0;
    for (let i = start + 1; i < start + len; i++) {
      n = n * 256 + b[i];
      if (n > Number.MAX_SAFE_INTEGER) throw new TarError('number too large');
    }
    return n;
  }
  const text = cstr(b, start, len).trim();
  if (text === '') return 0;
  if (!/^[0-7]+$/.test(text)) throw new TarError('malformed octal field');
  const n = parseInt(text, 8);
  if (!Number.isSafeInteger(n)) throw new TarError('number too large');
  return n;
}

function checksumOk(h: Buffer): boolean {
  const stored = numeric(h, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i];
  return sum === stored;
}

/** pax records: "<len> <key>=<value>\n", where <len> counts the whole record. */
function paxRecords(data: Buffer): Map<string, string> {
  const out = new Map<string, string>();
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp === -1) throw new TarError('malformed pax record');
    const lenText = data.toString('ascii', off, sp);
    if (!/^[0-9]+$/.test(lenText)) throw new TarError('malformed pax record');
    const len = Number(lenText);
    if (len <= sp - off + 1 || off + len > data.length || data[off + len - 1] !== 0x0a)
      throw new TarError('malformed pax record');
    const rec = data.toString('utf8', sp + 1, off + len - 1);
    const eq = rec.indexOf('=');
    if (eq <= 0) throw new TarError('malformed pax record');
    out.set(rec.slice(0, eq), rec.slice(eq + 1));
    off += len;
  }
  return out;
}

type Meta = 'pax' | 'global' | 'longname' | 'longlink';

/**
 * Feed decompressed bytes with `push`, then call `end`. For every file or link entry, `want`
 * decides whether its bytes are kept; kept entries arrive whole in `done`. Bytes of every other
 * entry are skipped as they stream past, never buffered.
 */
export class TarReader {
  private header = Buffer.alloc(BLOCK);
  private headerLen = 0;
  /** Data bytes left in the current entry, then its padding. */
  private left = 0;
  private pad = 0;
  private chunks: Buffer[] | null = null;
  private current: TarEntry | null = null;
  private meta: Meta | null = null;
  private pax = new Map<string, string>();
  private longName: string | null = null;
  private longLink: string | null = null;
  private finished = false;

  constructor(
    private readonly want: (e: TarEntry) => boolean,
    private readonly done: (e: TarEntry, data: Buffer) => void
  ) {}

  /** True once the end-of-archive block was seen. */
  get ended(): boolean {
    return this.finished;
  }

  push(chunk: Buffer): void {
    let off = 0;
    while (off < chunk.length) {
      if (this.finished) return; // trailing zero blocks and padding after the end
      if (this.left > 0) {
        const take = Math.min(this.left, chunk.length - off);
        if (this.chunks) this.chunks.push(chunk.subarray(off, off + take));
        this.left -= take;
        off += take;
        if (this.left === 0) this.finishEntry();
        continue;
      }
      if (this.pad > 0) {
        const take = Math.min(this.pad, chunk.length - off);
        this.pad -= take;
        off += take;
        continue;
      }
      const take = Math.min(BLOCK - this.headerLen, chunk.length - off);
      chunk.copy(this.header, this.headerLen, off, off + take);
      this.headerLen += take;
      off += take;
      if (this.headerLen === BLOCK) {
        this.headerLen = 0;
        this.readHeader(this.header);
      }
    }
  }

  /** The stream is over: anything short of the end-of-archive block is a truncated archive. */
  end(): void {
    if (!this.finished) throw new TarError('archive is truncated');
  }

  private readHeader(h: Buffer): void {
    if (isZero(h)) {
      this.finished = true;
      return;
    }
    if (!checksumOk(h)) throw new TarError('header checksum mismatch');
    const type = h[156] === 0 ? '0' : String.fromCharCode(h[156]);
    let size = numeric(h, 124, 12);
    const magic = h.toString('ascii', 257, 262);
    const prefix = magic === 'ustar' ? cstr(h, 345, 155) : '';
    const name = cstr(h, 0, 100);

    const meta: Meta | null =
      type === 'x'
        ? 'pax'
        : type === 'g'
          ? 'global'
          : type === 'L'
            ? 'longname'
            : type === 'K'
              ? 'longlink'
              : null;
    if (meta) {
      if (size > MAX_META_BYTES) throw new TarError('oversized extended header');
      this.begin(null, size, true, meta);
      return;
    }

    const pax = this.pax;
    if (pax.has('size')) {
      const s = pax.get('size')!;
      if (!/^[0-9]+$/.test(s) || !Number.isSafeInteger(Number(s)))
        throw new TarError('malformed pax size');
      size = Number(s);
    }
    const path = pax.get('path') ?? this.longName ?? (prefix ? `${prefix}/${name}` : name);
    const linkname = pax.get('linkpath') ?? this.longLink ?? cstr(h, 157, 100);
    this.pax = new Map();
    this.longName = null;
    this.longLink = null;

    const kind: TarKind = type === '0' || type === '7' ? 'file' : type === '2' ? 'link' : 'other';
    const entry: TarEntry = { path, kind, size, linkname: kind === 'link' ? linkname : '' };
    this.begin(entry, size, kind !== 'other' && this.want(entry));
  }

  private begin(
    entry: TarEntry | null,
    size: number,
    collect: boolean,
    meta: Meta | null = null
  ): void {
    this.current = entry;
    this.meta = meta;
    this.left = size;
    this.pad = (BLOCK - (size % BLOCK)) % BLOCK;
    this.chunks = collect ? [] : null;
    if (size === 0) this.finishEntry();
  }

  private finishEntry(): void {
    const data = this.chunks ? Buffer.concat(this.chunks) : null;
    this.chunks = null;
    if (this.meta && data) {
      if (this.meta === 'pax') for (const [k, v] of paxRecords(data)) this.pax.set(k, v);
      else if (this.meta === 'longname') this.longName = cstr(data, 0, data.length);
      else if (this.meta === 'longlink') this.longLink = cstr(data, 0, data.length);
      // 'global' (git writes the commit id there) carries nothing the reader needs.
      this.meta = null;
      return;
    }
    if (this.current && data) this.done(this.current, data);
    this.current = null;
  }
}

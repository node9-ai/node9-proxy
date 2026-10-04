// A tiny ZIP writer for the reader's tests: stored or deflated entries, and an
// optional ZIP64 end record (with the 32-bit fields saturated) so the ZIP64
// path is exercised without building a 65,536-entry archive.
import zlib from 'zlib';

export function buildZip(
  files: Array<{ name: string; data: string | Buffer; store?: boolean }>,
  opts: { zip64?: boolean } = {}
): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const raw = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf8');
    const body = f.store ? raw : zlib.deflateRawSync(raw);
    const name = Buffer.from(f.name, 'utf8');
    const method = f.store ? 0 : 8;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, body);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const cdOffset = offset;
  const tail: Buffer[] = [];
  if (opts.zip64) {
    const z64 = Buffer.alloc(56);
    z64.writeUInt32LE(0x06064b50, 0);
    z64.writeBigUInt64LE(44n, 4);
    z64.writeBigUInt64LE(BigInt(files.length), 24);
    z64.writeBigUInt64LE(BigInt(files.length), 32);
    z64.writeBigUInt64LE(BigInt(cd.length), 40);
    z64.writeBigUInt64LE(BigInt(cdOffset), 48);
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    loc.writeBigUInt64LE(BigInt(cdOffset + cd.length), 8);
    loc.writeUInt32LE(1, 16);
    tail.push(z64, loc);
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(opts.zip64 ? 0xffff : files.length, 8);
  eocd.writeUInt16LE(opts.zip64 ? 0xffff : files.length, 10);
  eocd.writeUInt32LE(opts.zip64 ? 0xffffffff : cd.length, 12);
  eocd.writeUInt32LE(opts.zip64 ? 0xffffffff : cdOffset, 16);
  return Buffer.concat([...locals, cd, ...tail, eocd]);
}

/** A minimal OSV MAL record. Package names in tests are canaries, never real. */
export function malRecord(
  id: string,
  eco: 'npm' | 'PyPI',
  name: string,
  shape: { versions?: string[]; all?: boolean; withdrawn?: boolean; modified?: string } = {}
): object {
  return {
    id,
    modified: shape.modified ?? '2026-10-01T00:00:00Z',
    ...(shape.withdrawn ? { withdrawn: '2026-10-01T00:00:00Z' } : {}),
    affected: [
      {
        package: { name, ecosystem: eco },
        ...(shape.versions ? { versions: shape.versions } : {}),
        ...(shape.all ? { ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] } : {}),
      },
    ],
  };
}

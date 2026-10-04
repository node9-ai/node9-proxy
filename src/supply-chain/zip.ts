// src/supply-chain/zip.ts
// Minimal read-only ZIP reader for the OSV archives (gs://osv-vulnerabilities/
// <ECOSYSTEM>/all.zip). No dependency: node:fs for random access, node:zlib for
// the deflate stream. Supports stored and deflated entries and the ZIP64 end
// records the npm archive needs (it holds more than 65,535 entries).
//
// Bounded on purpose: the central directory is capped, every entry is capped
// on both its compressed and its declared uncompressed size, and inflate is
// told the output limit, so a hostile or corrupt archive cannot exhaust memory.
import fs from 'fs';
import zlib from 'zlib';

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

const MAX_CENTRAL_DIR_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 4 * 1024 * 1024;

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

function readAt(fd: number, offset: number, length: number): Buffer {
  const buf = Buffer.alloc(length);
  let read = 0;
  while (read < length) {
    const n = fs.readSync(fd, buf, read, length - read, offset + read);
    if (n === 0) throw new Error('zip: unexpected end of file');
    read += n;
  }
  return buf;
}

function u64(buf: Buffer, at: number): number {
  const v = buf.readBigUInt64LE(at);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('zip: 64-bit value out of range');
  return Number(v);
}

/** Locate and read the central directory; returns every entry. */
export function readZipEntries(fd: number, fileSize: number): ZipEntry[] {
  // EOCD is 22 bytes plus a comment of at most 65,535 bytes.
  const tailLen = Math.min(fileSize, 22 + 65535 + 20);
  const tailStart = fileSize - tailLen;
  const tail = readAt(fd, tailStart, tailLen);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('zip: end of central directory not found');

  let total = tail.readUInt16LE(eocd + 10);
  let cdSize = tail.readUInt32LE(eocd + 12);
  let cdOffset = tail.readUInt32LE(eocd + 16);

  if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || tail.readUInt32LE(loc) !== SIG_ZIP64_LOCATOR)
      throw new Error('zip: ZIP64 locator missing');
    const z64Offset = u64(tail, loc + 8);
    const z64 = readAt(fd, z64Offset, 56);
    if (z64.readUInt32LE(0) !== SIG_ZIP64_EOCD) throw new Error('zip: ZIP64 record missing');
    total = u64(z64, 32);
    cdSize = u64(z64, 40);
    cdOffset = u64(z64, 48);
  }
  if (cdSize > MAX_CENTRAL_DIR_BYTES) throw new Error('zip: central directory too large');
  if (cdOffset + cdSize > fileSize) throw new Error('zip: central directory out of bounds');

  const cd = readAt(fd, cdOffset, cdSize);
  const entries: ZipEntry[] = [];
  let p = 0;
  for (let n = 0; n < total; n++) {
    if (p + 46 > cd.length || cd.readUInt32LE(p) !== SIG_CENTRAL)
      throw new Error('zip: corrupt central directory');
    const method = cd.readUInt16LE(p + 10);
    let compressedSize = cd.readUInt32LE(p + 20);
    let uncompressedSize = cd.readUInt32LE(p + 24);
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    let localHeaderOffset = cd.readUInt32LE(p + 42);
    const name = cd.toString('utf8', p + 46, p + 46 + nameLen);
    // ZIP64 extended information (header id 0x0001): the 64-bit values appear
    // in this order, and only for the fields whose 32-bit slot is saturated.
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = cd.readUInt16LE(e);
      const size = cd.readUInt16LE(e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (uncompressedSize === 0xffffffff) {
          uncompressedSize = u64(cd, q);
          q += 8;
        }
        if (compressedSize === 0xffffffff) {
          compressedSize = u64(cd, q);
          q += 8;
        }
        if (localHeaderOffset === 0xffffffff) localHeaderOffset = u64(cd, q);
      }
      e += 4 + size;
    }
    entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset });
    p = extraEnd + commentLen;
  }
  return entries;
}

/** Read and decompress one entry. Throws on an unsupported method or a cap breach. */
export function readZipEntry(fd: number, entry: ZipEntry): Buffer {
  if (entry.compressedSize > MAX_ENTRY_BYTES || entry.uncompressedSize > MAX_ENTRY_BYTES)
    throw new Error(`zip: entry ${entry.name} exceeds the size cap`);
  const local = readAt(fd, entry.localHeaderOffset, 30);
  if (local.readUInt32LE(0) !== SIG_LOCAL) throw new Error('zip: corrupt local header');
  const dataStart = entry.localHeaderOffset + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
  const data = readAt(fd, dataStart, entry.compressedSize);
  if (entry.method === 0) return data;
  if (entry.method === 8) return zlib.inflateRawSync(data, { maxOutputLength: MAX_ENTRY_BYTES });
  throw new Error(`zip: unsupported compression method ${entry.method}`);
}

// GitHub-classic-token canaries for the proxy's own tests.
//
// The DLP pattern validates the CRC32/Base62 checksum that ends every classic
// token (packages/policy-engine/src/scan/checksums.ts), so a test that wants
// the scanner to FIRE needs a value whose checksum verifies — a shape-only
// string is, by design, no longer a finding. The vectors below were produced
// by an independent implementation (Python zlib.crc32) from seeded random
// bodies; they are not tokens GitHub ever issued. Assembled with join() so no
// contiguous credential-shaped literal lives in the source.
export const FAKE_GH_TOKEN = ['ghp_', 'Ah9twYNPiM', 'w5fvVKHUcl', 'tdvqmH0uuh', '41miR4'].join('');
export const FAKE_GHO_TOKEN = ['gho_', 'SkDIOX5We7', '1mDf7svm8L', '4i3wm9dTRG', '4fY4SB'].join('');
/** Token-shaped, checksum does NOT verify: the scanner must leave it alone. */
export const FAKE_GH_LOOKALIKE = ['ghp_', 'Xm7Kp3Qn9B', 't2Vc6Wr1Ys', '4Zh8Pq5Nv3', 'MtRjWf'].join(
  ''
);

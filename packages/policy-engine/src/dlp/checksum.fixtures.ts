// Fixtures for the checksum-validated detectors: IBAN (mod-97 + ISO 13616
// registry), Bitcoin WIF and BIP-32 extended private keys (base58check).
//
// Every multi-part value is SPLIT and assembled with `asm()` at test time (the
// repo convention, see scan/pii.fixtures.ts). IBAN and base58 strings do not
// match node9's card/SSN gate, but the checkout stays free of contiguous
// credential-shaped literals regardless.
//
// Ground truth is never derived from the validators under test. Positive rows
// are published vectors: IBAN electronic-format examples from the SWIFT / ISO
// 13616 registry (also on Wikipedia "International Bank Account Number"); WIF
// from the Bitcoin wiki "Wallet import format" worked example and the widely
// published key=1 pair; xprv from BIP-32 test vectors 1 and 2. Negative rows
// are one-character mutations of those (which cannot pass the checksum) or
// values whose check digits were brute-forced so that ONLY the registry, the
// version byte, or the compression flag rejects them. Each such row names the
// single guard it witnesses.
//
// Assertion hygiene: rows carry an opaque `id`; specs assert booleans or
// pattern-name arrays and never interpolate an assembled value into a title or
// message.

export type Row = { id: string; parts: string[]; expect: boolean; proves: string };
export const asm = (parts: string[], sep = ''): string => parts.join(sep);

// ── IBAN ────────────────────────────────────────────────────────────────────
export const IBAN_VALID: Row[] = [
  {
    id: 'gb-1',
    parts: ['GB29', 'NWBK', '6016', '1331', '9268', '19'],
    expect: true,
    proves: 'baseline, 22, alpha BBAN',
  },
  {
    id: 'de-1',
    parts: ['DE89', '3704', '0044', '0532', '0130', '00'],
    expect: true,
    proves: 'numeric BBAN, 22',
  },
  {
    id: 'fr-1',
    parts: ['FR14', '2004', '1010', '0505', '0001', '3M02', '606'],
    expect: true,
    proves: '27, letter mid-BBAN',
  },
  {
    id: 'no-1',
    parts: ['NO93', '8601', '1117', '947'],
    expect: true,
    proves: 'shortest registered, 15',
  },
  {
    id: 'mt-1',
    parts: ['MT84', 'MALT', '0110', '0001', '2345', 'MTLC', 'AST0', '01S'],
    expect: true,
    proves: '31, trailing letter',
  },
  { id: 'be-1', parts: ['BE68', '5390', '0754', '7034'], expect: true, proves: '16' },
];
// one-character mutations: mod-97 remainder != 1
export const IBAN_INVALID: Row[] = [
  {
    id: 'gb-1-bad',
    parts: ['GB29', 'NWBK', '6016', '1331', '9268', '18'],
    expect: false,
    proves: 'last digit',
  },
  {
    id: 'de-1-bad',
    parts: ['DE89', '3704', '0044', '0532', '0130', '01'],
    expect: false,
    proves: 'last digit',
  },
  {
    id: 'fr-1-bad',
    parts: ['FR14', '2004', '1010', '0505', '0001', '3M02', '607'],
    expect: false,
    proves: 'last digit',
  },
  { id: 'no-1-bad', parts: ['NO93', '8601', '1117', '948'], expect: false, proves: 'last digit' },
  {
    id: 'mt-1-bad',
    parts: ['MT84', 'MALT', '0110', '0001', '2345', 'MTLC', 'AST0', '01T'],
    expect: false,
    proves: 'letter mutation',
  },
  { id: 'be-1-bad', parts: ['BE68', '5390', '0754', '7035'], expect: false, proves: 'last digit' },
  {
    id: 'de-1-interior',
    parts: ['DE89', '3704', '0045', '0532', '0130', '00'],
    expect: false,
    proves: 'not a last-char check',
  },
  {
    id: 'de-1-swapped',
    parts: ['DE89', '3704', '0044', '0532', '0100', '30'],
    expect: false,
    proves: 'transposition',
  },
];
// check digits brute-forced so mod-97 === 1; ONLY the registry can reject.
// Registry length is applied as a MINIMUM with slice (a human-formatted IBAN
// followed by more text would otherwise over-match and be lost), so a too-long
// DE value is accepted on its first 22 characters.
export const IBAN_REGISTRY: Row[] = [
  {
    id: 'reg-unknown-cc',
    parts: ['AA31', '3704', '0044', '0532', '0130', '00'],
    expect: false,
    proves: 'mod-97 passes; AA is not a registered country',
  },
  {
    id: 'reg-de-short',
    parts: ['DE41', '3704', '0044', '0532', '013'],
    expect: false,
    proves: 'mod-97 passes; 19 < DE minimum 22',
  },
  {
    id: 'reg-de-short-2',
    parts: ['DE51', '1234', '5678', '901'],
    expect: false,
    proves: 'pipelock row; 15 < 22',
  },
  {
    id: 'reg-de-long',
    parts: ['DE89', '3704', '0044', '0532', '0130', '0012'],
    expect: true,
    proves:
      'length-as-minimum (F1): 24 chars whose first 22 are de-1 exactly; an exact-length check would reject it',
  },
  {
    id: 'reg-known-limit',
    parts: ['DE16', 'ABCD', 'EF01', '2345', '6789', 'AB'],
    expect: true,
    proves:
      'HONEST LIMIT: hex-looking, DE=22, mod-97=1; a length-only registry cannot know German BBAN is 18!n',
  },
];

// ── Bitcoin WIF ─────────────────────────────────────────────────────────────
// Bitcoin wiki worked example (private key 0C28FCA3...), uncompressed + compressed.
export const WIF_VALID: Row[] = [
  {
    id: 'wif-u-wiki',
    parts: ['5HueCGU8rMjxEXxiPuD5B', 'Dku4MkFqeZyd4dZ1jvhTVq', 'vbTLvyTJ'],
    expect: true,
    proves: 'uncompressed, v=0x80, 33-byte payload',
  },
  {
    id: 'wif-c-wiki',
    parts: ['KwdMAjGmerYanjeui5SHS7', 'JkmpZvVipYvB2LJGU1ZxJw', 'YvP98617'],
    expect: true,
    proves: 'compressed, 34 bytes, flag 0x01',
  },
  {
    id: 'wif-u-k1',
    parts: ['5HpHagT65TZzG1PH3CSu63', 'k8DbpvD8s5ip4nEB3kEsre', 'AnchuDf'],
    expect: true,
    proves: 'key = 1 uncompressed',
  },
  {
    id: 'wif-c-k1',
    parts: ['KwDiBf89QgGbjEhKnhXJuH', '7LrciVrZi3qYjgd9M7rFU7', '3sVHnoWn'],
    expect: true,
    proves: 'key = 1 compressed',
  },
];
export const WIF_INVALID: Row[] = [
  {
    id: 'wif-u-wiki-bad',
    parts: ['5HueCGU8rMjxEXxiPuD5B', 'Dku4MkFqeZyd4dZ1jvhTVq', 'vbTLvyTK'],
    expect: false,
    proves: 'last char J->K, checksum fails',
  },
  {
    id: 'wif-c-wiki-bad',
    parts: ['KwdMAjGmerYanjeui5SHS7', 'JkmpZvVipYvB2LJGU1ZxJw', 'YvP98618'],
    expect: false,
    proves: 'checksum fails',
  },
  {
    id: 'wif-ver81',
    parts: ['5Km2kuu7vtFDPpxywn4u3N', 'Lu8iSdrqhxWT8tUKjeEXs2', 'fPgNpLf'],
    expect: false,
    proves: 'valid base58check, version 0x81: regex-reachable version witness',
  },
  {
    id: 'wif-testnet',
    parts: ['91avARGdfge8E4tZfYLoxe', 'J5sGBdNJQH4kvjJoQFacbg', 'wmaKkrx'],
    expect: false,
    proves: 'version 0xEF; also outside the mainnet regex (starts with 9)',
  },
  {
    id: 'wif-flag02',
    parts: ['KwDiBf89QgGbjEhKnhXJuH', '7LrciVrZi3qYjgd9M7rFU7', '3sfZr2ym'],
    expect: false,
    proves: 'v=0x80, 34 bytes, compression flag 0x02: flag must be 0x01 (F6)',
  },
  {
    id: 'wif-31',
    parts: ['yNb7j1viLcZunrTHozyfJP', 'TZJrprRSPpY485Lwzq1CFS', 'Bo1up'],
    expect: false,
    proves: 'v=0x80, 31-byte key: length guard (unit-only, 49 chars never reaches the regex)',
  },
];
/** A REAL WIF whose base58 happens to contain `fakE` -> lowercased hits stopword `fake`.
 *  Roughly 1 in 3,000 real keys contain some stopword. A passing checksum must win (F4). */
export const WIF_STOPWORD: Row = {
  id: 'wif-stopword',
  parts: ['L1hGPfwAQKn78fakEMMerB', 'Uj97pCs3gUioDBobuWUu32', 'eyQrBdjb'],
  expect: true,
  proves: 'validate beats stopword for validated patterns',
};
/** Bitcoin genesis coinbase address: valid base58check, version 0x00, 21-byte payload. */
export const P2PKH_GENESIS: Row = {
  id: 'p2pkh-genesis',
  parts: ['1A1zP1eP5QGefi2DMPTf', 'TL5SLmv7DivfNa'],
  expect: false,
  proves: 'passes validateBase58Check, fails validateWif on version',
};

// ── BIP-32 extended keys ────────────────────────────────────────────────────
export const XPRV_VALID: Row[] = [
  {
    id: 'xprv-tv1-m',
    parts: [
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP',
      'qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
    ],
    expect: true,
    proves: 'BIP-32 TV1 m',
  },
  {
    id: 'xprv-tv1-0h',
    parts: [
      'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvU',
      'xt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
    ],
    expect: true,
    proves: 'BIP-32 TV1 m/0H',
  },
  {
    id: 'xprv-tv2-m',
    parts: [
      'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtAL',
      'Gdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
    ],
    expect: true,
    proves: 'BIP-32 TV2 m',
  },
  {
    id: 'zprv-bip84',
    parts: [
      'zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62',
      'XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5',
    ],
    expect: true,
    proves: 'BIP-84 rootpriv, version 04b2430c',
  },
];
export const XPRV_INVALID: Row[] = [
  {
    id: 'xprv-tv1-m-bad',
    parts: [
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP',
      'qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj',
    ],
    expect: false,
    proves: 'checksum fails',
  },
  {
    id: 'xpub-tv1-m',
    parts: [
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe',
      'PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
    ],
    expect: false,
    proves: 'valid base58check, 78 bytes, PUBLIC key: version/marker guard (F7)',
  },
  {
    id: 'tprv-bip49',
    parts: [
      'tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6e',
      'oXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd',
    ],
    expect: false,
    proves: 'testnet: mainnet-only policy, consistent with WIF (F8)',
  },
];

export const ROW_COUNTS = {
  IBAN_VALID: 6,
  IBAN_INVALID: 8,
  IBAN_REGISTRY: 5,
  WIF_VALID: 4,
  WIF_INVALID: 6,
  XPRV_VALID: 4,
  XPRV_INVALID: 3,
} as const;

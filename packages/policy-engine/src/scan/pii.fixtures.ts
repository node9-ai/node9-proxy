// Card-number fixtures for the PII detector, stored as SPLIT PARTS.
//
// Convention (see src/__tests__/scan-golden-corpus.unit.test.ts): no contiguous
// card-shaped literal may exist in the committed source. Every digit group is
// its own string and rows are assembled with `asm()` at test time via
// Array.prototype.join, which esbuild does not constant-fold (string `+` it
// does). This keeps the checkout clean for DLP scanners, `node9 scan`, and
// reviewers, and keeps the literals out of tool-call arguments on machines
// where node9's own realtime PII gate is active.
//
// Ground truth is NOT derived from validateLuhn (that would be the code
// grading itself). Rows marked luhnValid:true are industry-published sandbox
// test numbers (Stripe / Adyen / Amex developer docs). Rows marked false are
// single-digit mutations of those, which is guaranteed to break the check
// digit. Nothing here was computed by the implementation under test.
//
// Assertion hygiene: rows carry an opaque `id`; specs assert on booleans or
// on PiiPattern[] results only, and never interpolate the assembled value into
// a test title or failure message (vitest prints those to CI logs).

export type CardRow = {
  id: string;
  parts: string[];
  luhnValid: boolean;
  /** what this row is a witness for */
  proves: string;
};

/** Assemble split parts. Default separator is empty (unspaced). */
export const asm = (parts: string[], sep = ''): string => parts.join(sep);

// ── 16-digit, Luhn-valid (must BLOCK before and after) ──────────────────────
export const VALID_16: CardRow[] = [
  { id: 'visa-1', parts: ['4111', '1111', '1111', '1111'], luhnValid: true, proves: 'baseline' },
  { id: 'visa-2', parts: ['4242', '4242', '4242', '4242'], luhnValid: true, proves: 'second visa' },
  {
    id: 'mc-1',
    parts: ['5555', '5555', '5555', '4444'],
    luhnValid: true,
    proves: 'sole witness for the -9 correction (M6)',
  },
  {
    id: 'mc-2',
    parts: ['5105', '1051', '0510', '5100'],
    luhnValid: true,
    proves: '51-range branch',
  },
  { id: 'disc-1', parts: ['6011', '1111', '1111', '1117'], luhnValid: true, proves: '6 branch' },
  {
    id: 'disc-2',
    parts: ['6011', '0009', '9013', '9424'],
    luhnValid: true,
    proves: 'second discover',
  },
];

// ── 15-digit Amex, Luhn-valid (ALLOW before → BLOCK after: the fixed FN) ────
export const VALID_15: CardRow[] = [
  {
    id: 'amex-1',
    parts: ['3782', '822463', '10005'],
    luhnValid: true,
    proves: 'sole witness for odd-length parity (M7)',
  },
  { id: 'amex-2', parts: ['3714', '496353', '98431'], luhnValid: true, proves: '34 and 37 both' },
];

// ── same shape, one digit changed, Luhn-invalid (BLOCK before → ALLOW after) ─
export const INVALID_16: CardRow[] = [
  {
    id: 'visa-1-bad',
    parts: ['4111', '1111', '1111', '1112'],
    luhnValid: false,
    proves: 'Luhn consulted',
  },
  { id: 'visa-2-bad', parts: ['4242', '4242', '4242', '4241'], luhnValid: false, proves: 'second' },
  {
    id: 'mc-1-bad',
    parts: ['5555', '5555', '5555', '4445'],
    luhnValid: false,
    proves: 'MC branch gated',
  },
  {
    id: 'disc-1-bad',
    parts: ['6011', '1111', '1111', '1118'],
    luhnValid: false,
    proves: '6 branch gated',
  },
  {
    id: 'visa-1-interior',
    parts: ['4111', '1111', '3111', '1111'],
    luhnValid: false,
    proves: 'not a last-digit-only check',
  },
];
export const INVALID_15: CardRow[] = [
  {
    id: 'amex-1-bad',
    parts: ['3782', '822463', '10006'],
    luhnValid: false,
    proves: 'only proof Luhn runs on the 15-digit branch (M11)',
  },
];

// ── non-card 16-digit strings that match today (the FP class) ───────────────
export const NON_CARD_16: CardRow[] = [
  {
    id: 'gift-card',
    parts: ['6034', '5678', '9012', '3456'],
    luhnValid: false,
    proves: 'widest FP surface (6 prefix)',
  },
  { id: 'order-id', parts: ['4400', '1234', '5678', '9012'], luhnValid: false, proves: 'order id' },
  {
    id: 'txn-ref',
    parts: ['5199', '2300', '0000', '0001'],
    luhnValid: false,
    proves: 'transaction ref',
  },
  {
    id: 'acct-fixture',
    parts: ['6543', '2109', '8765', '4321'],
    luhnValid: false,
    proves: 'test account number',
  },
  {
    id: 'amex-padded-16',
    parts: ['3782', '8224', '6310', '0050'],
    luhnValid: false,
    proves: 'the 3[47] branch at 16 digits only ever caught FPs',
  },
];
/** Luhn-valid NON-card: the honest limitation row. Still blocks after. */
export const NON_CARD_LUHN_VALID: CardRow = {
  id: 'acct-luhn-valid',
  parts: ['6543', '2109', '8765', '4320'],
  luhnValid: true,
  proves: 'Luhn is a checksum, not proof of card-ness (~1 in 10 survive)',
};

// ── composite inputs ────────────────────────────────────────────────────────
const V1 = VALID_16[0].parts;
const V2 = VALID_16[1].parts;
const V1BAD = INVALID_16[0].parts;
const A1 = VALID_15[0].parts;

export const COMPOSITE: { id: string; build: () => string; expectCard: boolean; proves: string }[] =
  [
    // separators
    {
      id: 'sep-space',
      build: () => asm(V1, ' '),
      expectCard: true,
      proves: 'Luhn input is digit-stripped (M2)',
    },
    { id: 'sep-dash', build: () => asm(V1, '-'), expectCard: true, proves: 'dashed' },
    {
      id: 'sep-mixed',
      build: () => [V1[0], '-', V1[1], ' ', V1[2], '-', V1[3]].join(''),
      expectCard: true,
      proves: 'per-gap independent',
    },
    {
      id: 'amex-4-6-5-space',
      build: () => asm(A1, ' '),
      expectCard: true,
      proves: 'real amex grouping',
    },
    { id: 'amex-4-6-5-dash', build: () => asm(A1, '-'), expectCard: true, proves: 'dashed amex' },
    {
      id: 'sep-double-space',
      build: () => asm(V1, '  '),
      expectCard: false,
      proves: 'single-char [-\\s]? limit, pinned',
    },
    {
      id: 'sep-dot',
      build: () => asm(V1, '.'),
      expectCard: false,
      proves: 'dots out of class, pinned',
    },
    {
      id: 'bad-with-spaces',
      build: () => asm(V1BAD, ' '),
      expectCard: false,
      proves: 'strip-then-Luhn',
    },
    // ⚠ the decoy-prefix attack from the first adversarial pass
    {
      id: 'decoy-then-valid',
      build: () => ['4000', ' ', asm(V1, ' ')].join(''),
      expectCard: true,
      proves: 'OVERLAP: a failed match must not swallow a following valid card',
    },
    {
      id: 'invalid-then-valid',
      build: () => ['ref ', asm(V1BAD), ' card ', asm(V2)].join(''),
      expectCard: true,
      proves: 'all matches checked, not the first (M3)',
    },
    {
      id: 'valid-then-invalid',
      build: () => ['card ', asm(V2), ' ref ', asm(V1BAD)].join(''),
      expectCard: true,
      proves: 'order independence',
    },
    {
      id: 'two-invalid',
      build: () => [asm(V1BAD), ' and ', asm(INVALID_16[2].parts)].join(''),
      expectCard: false,
      proves: 'no any-match-wins fallback',
    },
    // boundaries
    {
      id: 'glued-word',
      build: () => ['ref', asm(V1)].join(''),
      expectCard: false,
      proves: 'leading \\b preserved',
    },
    {
      id: 'after-dollar',
      build: () => ['$', asm(V1)].join(''),
      expectCard: true,
      proves: '$ is a boundary',
    },
    {
      id: 'after-hyphen-key',
      build: () => ['order-', asm(V1)].join(''),
      expectCard: true,
      proves: 'must still block',
    },
    {
      id: 'run-17',
      build: () => [asm(V1), '1'].join(''),
      expectCard: false,
      proves: 'trailing \\b (M10)',
    },
    {
      id: 'run-19-sep',
      build: () => [asm(V1, ' '), ' 111'].join(''),
      expectCard: true,
      proves: 'first 16 are a bounded token',
    },
    {
      id: 'visa-13',
      build: () => ['4222', '2222', '22222'].join(''),
      expectCard: false,
      proves: 'KNOWN remaining FN, recorded',
    },
    {
      id: 'fifteen-non-amex',
      build: () => ['4000', '000000', '00006'].join(''),
      expectCard: false,
      proves:
        '15-digit widening is prefix-scoped (M12); this value IS Luhn-valid so only the 34/37 prefix rejects it',
    },
  ];

/** A5: a card that BEGINS A LINE inside a multi-line value. */
export const MULTILINE_CSV = (): string =>
  ['name,card', '\n', 'alice,', asm(V1), '\n', 'bob,', asm(V2), '\n'].join('');

export const ROW_COUNTS = {
  VALID_16: 6,
  VALID_15: 2,
  INVALID_16: 5,
  INVALID_15: 1,
  NON_CARD_16: 5,
  COMPOSITE: 19,
} as const;

// App shields and the general action checks, generated from action templates
// (node9Firewall#390).
//
// finance.json, identity.json and publishing.json are TEMPLATES: the list of
// actions that move money, change access or publish, named the way MCP
// servers name their tools. They are no longer shields of their own. Two
// things are built from them:
//
//  1. An app shield per app (Stripe, PayPal, Square, Plaid, Okta, Auth0):
//     every template rule scoped to
//     that app's MCP server (`server`), plus the app's other doors: its CLI,
//     its API host, its library in a script the agent wrote. One app, one
//     shield: turning Stripe off never touches PayPal.
//  2. The general action checks (actions.money, actions.access,
//     actions.publish): the same template rules for every server NO app
//     shield claims (`notServer`), on by default as a safety net for an
//     internal billing server, a vendor without a shield, Zapier.
//
// A claimed server stays out of the general checks even while its app shield
// is off, so "off" on an app means quiet.

import type { SmartRule } from '../types';
import finance from './builtin/finance.json';
import identity from './builtin/identity.json';
import publishing from './builtin/publishing.json';

export type ActionTemplateName = 'finance' | 'identity' | 'publishing';

interface TemplateFile {
  smartRules: SmartRule[];
}

export const ACTION_TEMPLATES: Readonly<Record<ActionTemplateName, readonly SmartRule[]>> = {
  finance: (finance as TemplateFile).smartRules,
  identity: (identity as TemplateFile).smartRules,
  publishing: (publishing as TemplateFile).smartRules,
};

/** The general check each template feeds, and the word its rules carry. */
export const ACTION_CHECKS: Readonly<
  Record<ActionTemplateName, { checkId: string; slug: string; label: string }>
> = {
  finance: { checkId: 'actions.money', slug: 'money', label: 'Money check' },
  identity: { checkId: 'actions.access', slug: 'access', label: 'Accounts and access check' },
  publishing: { checkId: 'actions.publish', slug: 'publish', label: 'Publishing check' },
};

/** A template rule that names MCP tools (the shell rules of publishing do not). */
function isToolRule(rule: SmartRule): boolean {
  return rule.tool.startsWith('{,mcp__*__}');
}

/** `shield:finance:review-refund` -> `review-refund`. */
function actionPart(ruleName: string | undefined): string {
  const m = /^shield:[^:]+:(.+)$/.exec(ruleName ?? '');
  return m ? m[1] : (ruleName ?? 'rule');
}

/** Swap the template's trailing "(Finance shield)" for the new owner. */
function ownReason(reason: string | undefined, owner: string): string | undefined {
  if (!reason) return reason;
  return reason.replace(/\((?:Finance|Identity|Publishing) shield\)\.?$/, `(${owner}).`);
}

// ── Apps ─────────────────────────────────────────────────────────────────────

// Bounded gap between a program and its subcommand: env prefixes, sudo, flags,
// a path; one command only (; & | end it). Same shape as the publishing rules.
const GAP = '[^;&|]{0,200}?';
const prog = (alt: string) => `(?:^|[^\\w-])(?:${alt})(?![\\w-])`;
// The runtime compiles a rule regex only up to 256 characters (utils/regex.ts)
// and reads a longer one as no match, so a door is split into short
// conditions, all of which must hold, or into one rule per spelling.

/** An HTTP client in the same command as `host` (one command: ; & | end it). */
const httpTo = (host: string) => prog('curl|wget|http|https|xh') + '[^;&|]{0,400}?' + host;

/**
 * The command carries a write: a write method (curl -X / --request, wget
 * --method or --post-data, httpie's `POST`), or a body, which makes curl send
 * POST unless -G / --get turns it into a GET with a query string (how
 * Stripe's docs spell every list call). Case-sensitive on purpose: with `i`,
 * `-G` would also be curl's `-g` (globoff), which changes no method.
 */
const httpWrite = (methods: string): SmartRule['conditions'][number] => ({
  field: 'command',
  op: 'matches',
  value:
    `-X\\s*(?:${methods})|--(?:request|method)[=\\s]+(?:${methods})|--post-(?:data|file)|\\s(?:${methods}|${methods.toLowerCase()})\\s` +
    `|^(?!.*\\s(?:-[a-zA-Z]*G|--get)(?![\\w-])).*(?:\\s-d[\\s'"@]|\\s--data|\\s--json\\s|\\s-F\\s|\\s--form\\s)`,
});
const HTTP_WRITE = httpWrite('POST|DELETE');
/** For APIs that also change things with PUT or PATCH (Okta adds a group
 *  member with PUT, Auth0 updates a user with PATCH). */
const HTTP_WRITE_ANY = httpWrite('POST|PUT|PATCH|DELETE');

/** A Stripe test key in the command: test mode, no money moves. */
const NOT_STRIPE_TEST: SmartRule['conditions'][number] = {
  field: 'command',
  op: 'notMatches',
  value: '\\b[sr]k_test_',
};

/** `requests.post("https://<host>...`, `axios.post('https://<host>...` in a script. */
const postTo = (host: string) => `\\.post\\(\\s*["'\`][^"'\`]{0,80}${host}`;

interface AppShieldSpec {
  name: string;
  label: string;
  description: string;
  template: ActionTemplateName;
  /** Glob for the app's MCP server label (case-insensitive). */
  server: string;
  /** The app's other doors, as bash rules (the code door is a session script
   *  judged as a Bash command, so it is a bash rule too). */
  doors: SmartRule[];
  /** Tools of the vendor's own MCP server that the template's names miss
   *  (Square's single make_api_request); scoped to the server like the
   *  template's. */
  mcpTools?: SmartRule[];
}

const STRIPE_OBJECTS =
  'refunds|payouts|charges|transfers|payment_intents|payment_links|invoices|subscriptions|topups';

export const APP_SHIELD_SPECS: readonly AppShieldSpec[] = [
  {
    name: 'stripe',
    label: 'Stripe',
    description:
      'Asks before money moves in Stripe (refunds, payouts, charges, invoices, subscriptions), whether the agent uses the Stripe MCP server, the stripe CLI, the API or the Stripe library in a script. Reads are never asked about.',
    template: 'finance',
    server: '*stripe*',
    doors: [
      {
        name: 'shield:stripe:review-cli',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value:
              prog('stripe') +
              GAP +
              `\\s(?:${STRIPE_OBJECTS})\\s+(?:create|cancel|capture|confirm|update|pay|finalize_invoice|send_invoice|void_invoice)(?![\\w-])`,
            flags: 'i',
          },
          {
            field: 'command',
            op: 'matches',
            // The stripe CLI works in test mode unless told otherwise.
            value: '\\s--live(?![\\w-])|\\b[sr]k_live_',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'The stripe CLI is about to move money. node9 asks before money moves (Stripe).',
      },
      {
        name: 'shield:stripe:review-cli-request',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value:
              prog('stripe') + GAP + `\\s(?:post|delete)\\s+/?v1/(?:${STRIPE_OBJECTS})(?![\\w-])`,
            flags: 'i',
          },
          {
            field: 'command',
            op: 'matches',
            // The stripe CLI works in test mode unless told otherwise.
            value: '\\s--live(?![\\w-])|\\b[sr]k_live_',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'A raw stripe CLI request is about to move money. node9 asks before money moves (Stripe).',
      },
      {
        name: 'shield:stripe:review-api',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: httpTo(`api\\.stripe\\.com/v1/(?:${STRIPE_OBJECTS})(?![\\w-])`),
            flags: 'i',
          },
          HTTP_WRITE,
          NOT_STRIPE_TEST,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'A request to the Stripe API is about to move money. node9 asks before money moves (Stripe).',
      },
      {
        name: 'shield:stripe:review-code',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Python: stripe.Refund.create(...)
            value:
              '\\bstripe\\.(?:Refund|Payout|Transfer|Charge|PaymentIntent|PaymentLink|Invoice|Subscription|Topup)\\.(?:create|cancel|capture|confirm|modify|pay|finalize_invoice|send_invoice|void_invoice)\\b',
          },
          NOT_STRIPE_TEST,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'This code moves money through the Stripe library. node9 asks before money moves (Stripe).',
      },
      {
        name: 'shield:stripe:review-code-node',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Node: stripe.refunds.create(...)
            value:
              '\\bstripe\\.(?:refunds|payouts|transfers|charges|paymentIntents|paymentLinks|invoices|subscriptions|topups)\\.(?:create|cancel|capture|confirm|update|pay|finalizeInvoice|sendInvoice|voidInvoice)\\s*\\(',
          },
          NOT_STRIPE_TEST,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'This code moves money through the Stripe library. node9 asks before money moves (Stripe).',
      },
      {
        name: 'shield:stripe:review-code-http',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // requests.post("https://api.stripe.com/v1/refunds", ...)
            value: `\\.post\\(\\s*["'\`][^"'\`]{0,80}api\\.stripe\\.com/v1/(?:${STRIPE_OBJECTS})`,
          },
          NOT_STRIPE_TEST,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'This code posts to the Stripe API. node9 asks before money moves (Stripe).',
      },
    ],
  },
  {
    name: 'paypal',
    label: 'PayPal',
    description:
      'Asks before money moves in PayPal (refunds, payouts, captured orders, invoices, subscriptions), whether the agent uses a PayPal MCP server, the API or the PayPal SDK in a script. The sandbox is never asked about, and neither are reads.',
    template: 'finance',
    server: '*paypal*',
    doors: [
      {
        name: 'shield:paypal:review-api',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The live hosts only: api.paypal.com and api-m.paypal.com. The
            // sandbox (api-m.sandbox.paypal.com) moves no money.
            value: httpTo('api(?:-m)?\\.paypal\\.com/v[12]/'),
            flags: 'i',
          },
          {
            field: 'command',
            op: 'matches',
            // The endpoints that move money.
            value:
              '\\.paypal\\.com/v[12]/(?:payments/(?:captures|authorizations|sale|payouts|payment|referenced-payouts)|checkout/orders/[^\\s/]{1,64}/(?:capture|authorize)|invoicing/invoices|billing/subscriptions)',
            flags: 'i',
          },
          HTTP_WRITE,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'A request to the PayPal API is about to move money. node9 asks before money moves (PayPal).',
      },
      {
        name: 'shield:paypal:review-code',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The Node SDKs (checkout-server-sdk, paypal-server-sdk) and the
            // Python paypalrestsdk.
            value:
              '\\b(?:CapturesRefundRequest|OrdersCaptureRequest|AuthorizationsCaptureRequest|PayoutsPostRequest)\\b' +
              '|\\b(?:captureOrder|refundCapturedPayment|captureAuthorizedPayment|createBatchPayout)\\s*\\(' +
              '|\\bpaypalrestsdk\\.(?:Payout|Sale|Capture|Invoice|BillingAgreement)\\b',
          },
        ],
        verdict: 'review',
        reason: 'This code moves money through PayPal. node9 asks before money moves (PayPal).',
      },
      {
        name: 'shield:paypal:review-code-http',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The endpoints that move money; the token call every script
            // starts with (/v1/oauth2/token) is not one.
            value: postTo(
              'api(?:-m)?\\.paypal\\.com/v[12]/(?:payments/(?:captures|authorizations|sale|payouts|payment|referenced-payouts)|checkout/orders/[^\\s/"\'`]{1,64}/(?:capture|authorize)|invoicing/invoices|billing/subscriptions)'
            ),
          },
        ],
        verdict: 'review',
        reason: 'This code posts to the PayPal API. node9 asks before money moves (PayPal).',
      },
    ],
  },
  {
    name: 'square',
    label: 'Square',
    description:
      'Asks before money moves in Square (refunds, payments, paid orders, invoices, subscriptions), whether the agent uses a Square MCP server, the API or the Square SDK in a script. The sandbox host is never asked about, and neither are reads.',
    template: 'finance',
    // Square's servers, never Squarespace (a website builder).
    server: '{*square,*square[-_]*,*squareup*}',
    mcpTools: [
      {
        // Square's official MCP server has one tool for every API call; the
        // service and method name what it does.
        name: 'shield:square:review-mcp-request',
        tool: '{,mcp__*__}make_api_request',
        conditions: [
          {
            field: 'service',
            op: 'matches',
            value:
              '^(?:refunds|payments|orders|invoices|subscriptions|disputes|gift_cards|gift_card_activities|checkout|terminal)$',
            flags: 'i',
          },
          {
            field: 'method',
            op: 'notMatches',
            value: '^(?:list|get|retrieve|search|batch_?retrieve|calculate)',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'A request through the Square MCP server is about to move money. node9 asks before money moves (Square).',
      },
    ],
    doors: [
      {
        name: 'shield:square:review-api',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The live host only; the sandbox is connect.squareupsandbox.com.
            value: httpTo(
              'connect\\.squareup\\.com/v2/(?:refunds|payments|orders/[^\\s/?]{1,64}/pay|invoices|subscriptions|disputes|gift-cards/activities)(?![\\w-]|/search)'
            ),
            flags: 'i',
          },
          HTTP_WRITE_ANY,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'A request to the Square API is about to move money. node9 asks before money moves (Square).',
      },
      {
        name: 'shield:square:review-code',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The Square SDK in the script: Node (`square`) or Python (`square`, `squareup`).
            value:
              '\\bSquareClient\\b|\\bsquare\\.client\\b|from\\s+square[.\\s]|from\\s+["\']square["\']|require\\(\\s*["\']square["\']',
          },
          {
            field: 'command',
            op: 'matches',
            value:
              '\\.refunds(?:Api)?\\.refund(?:Payment|_payment)\\s*\\(|\\.payments(?:Api)?\\.(?:create|complete)(?:Payment|_payment)?\\s*\\(|\\.orders(?:Api)?\\.pay(?:Order|_order)?\\s*\\(|\\.invoices(?:Api)?\\.publish(?:Invoice|_invoice)?\\s*\\(',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'This code moves money through the Square SDK. node9 asks before money moves (Square).',
      },
      {
        name: 'shield:square:review-code-http',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: postTo(
              'connect\\.squareup\\.com/v2/(?:refunds|payments|orders/[^\\s/?"\'`]{1,64}/pay|invoices|subscriptions|disputes|gift-cards/activities)(?![\\w-]|/search)'
            ),
          },
        ],
        verdict: 'review',
        reason: 'This code posts to the Square API. node9 asks before money moves (Square).',
      },
    ],
  },
  {
    name: 'plaid',
    label: 'Plaid',
    description:
      'Asks before money moves through Plaid (transfers, transfer authorizations, payment initiation), whether the agent uses a Plaid MCP server, the API or the Plaid SDK in a script. The sandbox host is never asked about, and neither are reads such as balances or transactions.',
    template: 'finance',
    server: '*plaid*',
    doors: [
      {
        name: 'shield:plaid:review-api',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Every Plaid endpoint is a POST, so the path is what tells a
            // write; the live host only, never sandbox.plaid.com. A script
            // that posts to the URL meets this door too.
            value: httpTo(
              'production\\.plaid\\.com/(?:transfer/(?:create|authorization/create|recurring/create)|payment_initiation/payment/create|bank_transfer/create)(?![\\w-])'
            ),
            flags: 'i',
          },
        ],
        verdict: 'review',
        reason:
          'A request to the Plaid API is about to move money. node9 asks before money moves (Plaid).',
      },
      {
        name: 'shield:plaid:review-code',
        tool: 'bash',
        conditions: [
          { field: 'command', op: 'matches', value: '\\bplaid', flags: 'i' },
          {
            field: 'command',
            op: 'matches',
            value:
              '\\b(?:transfer(?:Authorization|Recurring)?Create|paymentInitiationPaymentCreate|bankTransferCreate|transfer_(?:authorization_|recurring_)?create|payment_initiation_payment_create|bank_transfer_create)\\s*\\(',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'This code moves money through Plaid. node9 asks before money moves (Plaid).',
      },
    ],
  },
  {
    name: 'okta',
    label: 'Okta',
    description:
      'Asks before a user, a group member, a role, a password or a key changes in Okta, whether the agent uses an Okta MCP server, the API or the Okta SDK in a script. Reads and signing in are never asked about.',
    template: 'identity',
    server: '*okta*',
    doors: [
      {
        name: 'shield:okta:review-api',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The management API only: sign-in (/api/v1/authn, /sessions,
            // /oauth2) is not under these paths.
            value: httpTo(
              '[\\w-]+\\.okta(?:-emea)?\\.com/api/v1/(?:users|groups|apps|iam|api-tokens|idps|authorizationServers|policies)(?![\\w-])'
            ),
            flags: 'i',
          },
          HTTP_WRITE_ANY,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'A request to the Okta API is about to change who has access. node9 asks before access changes (Okta).',
      },
      {
        name: 'shield:okta:review-code',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The Okta SDK in the script: a method named createUser alone is
            // in half the applications ever written.
            value: '@okta/okta-sdk|\\bokta\\.Client\\b|from\\s+okta[.\\s]|\\bimport\\s+okta\\b',
          },
          {
            field: 'command',
            op: 'matches',
            value:
              '\\b(?:(?:create|delete|deactivate|suspend|unlock|activate)User|(?:reset|expire)Password|resetFactors|(?:assign|unassign)User(?:To|From)Group|assignRoleTo(?:User|Group))\\s*\\(',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'This code changes who has access in Okta. node9 asks before access changes (Okta).',
      },
      {
        name: 'shield:okta:review-code-py',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '@okta/okta-sdk|\\bokta\\.Client\\b|from\\s+okta[.\\s]|\\bimport\\s+okta\\b',
          },
          {
            field: 'command',
            op: 'matches',
            value:
              '\\b(?:(?:create|delete|deactivate|deactivate_or_delete|suspend|unlock|activate)_user|(?:reset|expire)_password|reset_factors|(?:add|remove)_user_(?:to|from)_group|assign_role_to_(?:user|group))\\s*\\(',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'This code changes who has access in Okta. node9 asks before access changes (Okta).',
      },
    ],
  },
  {
    name: 'auth0',
    label: 'Auth0',
    description:
      'Asks before a user, a role, an application or its permissions change in Auth0, whether the agent uses an Auth0 MCP server, the auth0 CLI, the Management API or the Auth0 SDK in a script. Reads and signing in are never asked about.',
    template: 'identity',
    server: '*auth0*',
    mcpTools: [
      {
        // Auth0's official MCP server: applications (their secrets and
        // callbacks), APIs and their scopes, and Actions (code that runs at
        // every sign-in).
        name: 'shield:auth0:review-tenant-config',
        tool: '{,mcp__*__}{auth0_create_application,auth0_update_application,auth0_create_resource_server,auth0_update_resource_server,auth0_create_action,auth0_update_action,auth0_deploy_action}',
        conditions: [],
        verdict: 'review',
        reason:
          'This changes an Auth0 application, API or sign-in Action. node9 asks before access changes (Auth0).',
      },
    ],
    doors: [
      {
        name: 'shield:auth0:review-cli',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value:
              prog('auth0') +
              GAP +
              '\\s(?:(?:users|roles|apps|orgs)\\s+(?:create|update|delete|rm)|users\\s+roles\\s+(?:assign|add|remove|rm)|roles\\s+permissions\\s+(?:add|remove|rm)|users\\s+blocks\\s+unblock|api\\s+(?:post|put|patch|delete))(?![\\w-])',
            flags: 'i',
          },
        ],
        verdict: 'review',
        reason:
          'The auth0 CLI is about to change who has access. node9 asks before access changes (Auth0).',
      },
      {
        name: 'shield:auth0:review-api',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The Management API only; /oauth/token is signing in.
            value: httpTo(
              '\\.auth0\\.com/api/v2/(?:users|roles|clients|grants|client-grants|organizations|tickets|jobs/users-imports|device-credentials)(?![\\w-])'
            ),
            flags: 'i',
          },
          HTTP_WRITE_ANY,
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'A request to the Auth0 Management API is about to change who has access. node9 asks before access changes (Auth0).',
      },
      {
        name: 'shield:auth0:review-code',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // The Auth0 SDK in the script (Node `auth0`, Python `auth0`).
            value:
              '\\bManagementClient\\b|from\\s+auth0[.\\s]|from\\s+["\']auth0["\']|require\\(\\s*["\']auth0["\']',
          },
          {
            field: 'command',
            op: 'matches',
            value:
              '\\.(?:users|roles|organizations|clients)\\.(?:create|delete|update|assignRoles|deleteRoles|assignUsers|addPermissions|deletePermissions|addMembers|deleteMembers|add_roles|remove_roles|add_users|add_permissions|remove_permissions)\\s*\\(',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason:
          'This code changes who has access in Auth0. node9 asks before access changes (Auth0).',
      },
    ],
  },
];

export interface GeneratedShield {
  name: string;
  description: string;
  aliases: string[];
  smartRules: SmartRule[];
  dangerousWords: string[];
}

/** The app shield: the template's tool rules scoped to the app's server, and
 *  the app's own doors. */
function buildAppShield(spec: AppShieldSpec): GeneratedShield {
  const owner = spec.label;
  const toolRules = ACTION_TEMPLATES[spec.template].filter(isToolRule).map((rule): SmartRule => ({
    ...rule,
    name: `shield:${spec.name}:${actionPart(rule.name)}`,
    server: spec.server,
    reason: ownReason(rule.reason, owner),
  }));
  const ownTools = (spec.mcpTools ?? []).map((rule): SmartRule => ({
    ...rule,
    server: spec.server,
  }));
  return {
    name: spec.name,
    description: spec.description,
    aliases: [],
    smartRules: [...toolRules, ...ownTools, ...spec.doors],
    dangerousWords: [],
  };
}

export const APP_SHIELDS: readonly GeneratedShield[] = APP_SHIELD_SPECS.map(buildAppShield);

/** The app shields' names. node9 turns one on when it finds the app; a history
 *  scan with no hit for it does not pitch it. */
export const APP_SHIELD_NAMES: ReadonlySet<string> = new Set(APP_SHIELD_SPECS.map((s) => s.name));

/** Every MCP server an app shield claims, as one glob: `{*stripe*,*paypal*}`. */
export const APP_SERVER_GLOB = `{${APP_SHIELD_SPECS.map((s) => s.server).join(',')}}`;

// ── General action checks ────────────────────────────────────────────────────

/**
 * The rules behind actions.money / actions.access / actions.publish: the
 * template's MCP tool rules, kept off any server an app shield claims.
 *
 * The publishing template's shell rules (npm publish, twine upload, docker
 * push, gh release) are NOT general: each names a registry, which is an app,
 * and becomes a door of that app's shield. They stay off by default until
 * then, as in 2.37.0, which also keeps the exposure gate's decision that a
 * publish to the project's own registry is logged, not held (node9Firewall#318).
 */
function buildGeneralRules(): SmartRule[] {
  const out: SmartRule[] = [];
  for (const name of Object.keys(ACTION_TEMPLATES) as ActionTemplateName[]) {
    const { slug, label } = ACTION_CHECKS[name];
    for (const rule of ACTION_TEMPLATES[name].filter(isToolRule)) {
      const part = actionPart(rule.name).replace(/^review-/, '');
      out.push({
        ...rule,
        name: `review-action-${slug}-${part}`,
        notServer: APP_SERVER_GLOB,
        reason: ownReason(rule.reason, label),
      });
    }
  }
  return out;
}

export const GENERAL_ACTION_RULES: readonly SmartRule[] = buildGeneralRules();

/** Rule names per general check, for the catalog's `legacy` lists. */
export function generalActionRuleNames(template: ActionTemplateName): string[] {
  const { slug } = ACTION_CHECKS[template];
  return GENERAL_ACTION_RULES.filter((r) => r.name?.startsWith(`review-action-${slug}-`)).map(
    (r) => r.name as string
  );
}

/** The three shields 2.37.0 shipped and this release replaces, with what to
 *  use instead. `node9 shield enable finance` answers with this. */
export const REPLACED_SHIELDS: Readonly<Record<string, string>> = {
  finance:
    'finance is now the Money check (actions.money), on by default. For an app: node9 shield enable stripe (or paypal).',
  identity: 'identity is now the Accounts and access check (actions.access), on by default.',
  publishing: 'publishing is now the Publishing check (actions.publish), on by default.',
};

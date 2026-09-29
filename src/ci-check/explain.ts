// src/ci-check/explain.ts
// ONE place for what a finding means in plain words (design R, 2026-09-28). The signals say
// what the scan saw, in the vocabulary of the check; a reader who does not know GitHub Actions
// cannot tell from them what could happen. Each analyzer hands its facts here and gets back:
//   headline  what is wrong, in one line
//   happens   what an attacker can do, in one or two sentences
//   saw       only the facts found in this repository, each with its technical term in a span
//   fix       at most four steps, most important first
// The same text is shown by the PR comment, the CLI and the hosted page. Repository text (tool
// names, secret names, server names, paths) only ever appears inside a code span made by
// `code()`, which strips backticks and line breaks. No em dash in any string here.

import { safeText } from './suppress';
import type { Explain, Severity } from './types';

const code = (v: string, max = 80): string => `\`${safeText(v, max)}\``;
const codes = (vs: string[], max = 3): string => {
  const shown = vs.slice(0, max).map((v) => code(v));
  const more = vs.length - shown.length;
  return more > 0 ? `${shown.join(', ')} and ${more} more` : shown.join(', ');
};
const sentence = (parts: string[], and = false): string =>
  parts.length <= 1
    ? (parts[0] ?? '')
    : `${parts.slice(0, -1).join(', ')} ${and ? 'and' : 'or'} ${parts[parts.length - 1]}`;

// ── CI-2: an AI agent in a GitHub workflow ──────────────────────────────────

export interface WorkflowFacts {
  severity: Severity;
  /** `allowed_non_write_users: "*"` with github_token: anyone can start the agent. */
  anyone: boolean;
  /** Nothing checks who starts the agent, and untrusted input reaches it. */
  ungated: boolean;
  /** Every agent job is held by an actor check. */
  gated: boolean;
  /** The events that start the workflow. */
  triggers: string[];
  /** The triggers that run with the repository's secrets (pull_request_target, workflow_run). */
  secretTriggers: string[];
  /** The untrusted pull request is checked out into the workspace root, or a subfolder. */
  head: 'root' | 'subdir' | null;
  /** The text of the pull request or issue reaches the agent's prompt. */
  readsText: boolean;
  /** Broad or write-capable tools granted to the agent. */
  tools: string[];
  /** Among them, a tool that runs any command (bare Bash, curl, sh). */
  shell: boolean;
  /** It can push code: a write token with a git or gh tool, or a personal access token. */
  pushCode: boolean;
  /** It can change pull requests or issues (comment, label, approve). */
  editThreads: boolean;
  pat: boolean;
  /** `show_full_output: true`: everything the agent prints is in the public Actions log. */
  publicOutput: boolean;
  /** `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` switched off: keys are in the agent's shell. */
  scrubOff: boolean;
  /** A reusable workflow (`workflow_call`): who can reach it depends on the caller. */
  reusable: boolean;
}

/** What starts it, as a stranger does it: "a pull request", "an issue", "a comment". */
function strangerAction(triggers: string[]): string {
  const acts: string[] = [];
  const add = (a: string) => acts.includes(a) || acts.push(a);
  for (const t of triggers) {
    if (/^pull_request(_target)?$|^workflow_run$/.test(t)) add('a pull request');
    else if (t === 'issues') add('an issue');
    else if (/comment|review/.test(t)) add('a comment');
  }
  return sentence(acts.length ? acts : ['a pull request or issue']);
}

export function explainWorkflow(f: WorkflowFacts): Explain {
  const withSecrets = f.secretTriggers.length > 0 || f.pat;
  const saw: string[] = [];
  if (f.anyone) saw.push('Anyone can start the agent (`allowed_non_write_users: "*"`).');
  else if (f.ungated) saw.push('Nothing checks who starts the agent.');
  else if (f.gated) saw.push('Only people with write access can start it.');
  // Where a stranger can start it, "What can happen" already names how; the trigger list
  // would only repeat it.
  if (f.triggers.length && !f.anyone && !f.ungated)
    saw.push(`It starts on ${codes(f.triggers, 4)}.`);
  if (f.secretTriggers.length)
    saw.push(`It runs with the repository's secrets (${codes(f.secretTriggers)}).`);
  if (f.head === 'root')
    saw.push("It works on the stranger's files, not yours (it checks out the pull request).");
  if (f.head === 'subdir') saw.push('It checks out the pull request into a separate folder.');
  if (f.readsText) saw.push('It reads the text of the pull request or issue.');
  if (f.shell) saw.push(`It can run any command (${codes(f.tools)}).`);
  else if (f.tools.length) saw.push(`It has tools that can change things (${codes(f.tools)}).`);
  if (f.pat) saw.push('It holds a personal access token.');
  else if (f.pushCode) saw.push('It can push code to the repository.');
  if (f.publicOutput) saw.push('Everything it prints is public (`show_full_output: true`).');
  if (f.scrubOff)
    saw.push('Its shell holds your keys (`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` is off).');

  const fix: string[] = [];
  if (f.anyone)
    fix.push('Let only people with write access start it: remove `allowed_non_write_users: "*"`.');
  else if (f.ungated) fix.push('Let only people with write access start it.');
  if (f.head === 'root' && f.secretTriggers.length)
    fix.push("Do not check out the pull request's files in this workflow.");
  if (f.tools.length) fix.push('Give the agent only the tools the job needs.');
  const optOuts = [
    f.publicOutput ? '`show_full_output: true`' : '',
    f.scrubOff ? 'the `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` line' : '',
  ].filter(Boolean);
  if (optOuts.length) fix.push(`Remove ${optOuts.join(' and ')}.`);

  const who = strangerAction(f.triggers);
  if (f.reusable)
    return {
      headline: 'A reusable workflow hands untrusted input to an AI agent',
      happens:
        'Who can reach this agent depends on the workflows that call this one. If a caller runs on pull requests or issues from strangers, they can tell the agent what to do.',
      saw,
      fix: fix.length ? fix : ['Check every workflow that calls this one: only trusted events.'],
    };

  if (f.severity === 'critical' || f.severity === 'high')
    return {
      headline: `Anyone can make this repository's AI agent act with its ${withSecrets ? 'secrets' : 'permissions'}`,
      happens:
        `A stranger opens ${who} with instructions for the agent. The agent follows them with this repository's ${withSecrets ? 'secrets' : 'permissions'}` +
        (f.publicOutput ? ', and everything it prints is public.' : '.'),
      saw,
      fix: fix.slice(0, 4),
    };

  if (f.severity === 'medium') {
    const cannot = [
      f.shell ? '' : 'run commands',
      f.pushCode ? '' : 'push code',
      withSecrets ? '' : 'reach secrets beyond the default token',
    ].filter(Boolean);
    const limits = cannot.length
      ? ` What limits the damage: it cannot ${sentence(cannot)}` +
        (f.editThreads ? ', so at most it can comment on, label or close issues.' : '.')
      : '';
    return {
      headline: "Anyone can steer this repository's AI agent, with limited power",
      happens: `A stranger can open ${who} that tells the agent what to do.${limits}`,
      saw,
      fix: (fix.length ? fix : ['Let only people with write access start it.']).slice(0, 4),
    };
  }

  // advisory: nothing a stranger can do today
  const power = [
    withSecrets ? 'has secrets' : '',
    f.shell ? 'can run commands' : '',
    f.pushCode ? 'can push code' : '',
  ].filter(Boolean);
  const wouldBe = power.length ? `an agent that ${sentence(power, true)}` : 'the agent';
  if (f.gated)
    return {
      headline: 'An AI agent workflow that is protected today',
      happens: `Only people with write access can start it, so it is safe. If that check is ever removed, anyone could steer ${wouldBe}.`,
      saw,
      fix: ['Nothing to do now. Keep the check on who can start it.'],
    };
  if (f.ungated)
    return {
      headline: "Anyone can steer this repository's AI agent, but it can do very little",
      happens: `A stranger can open ${who} that tells the agent what to do. It has no tools or permissions that could do real harm today. Giving it more would change that.`,
      saw,
      fix: [
        'Nothing urgent. Before giving the agent more tools, let only people with write access start it.',
      ],
    };
  if (f.triggers.includes('pull_request') && !f.secretTriggers.length)
    return {
      headline: 'An AI agent runs on pull requests, with no secrets for strangers',
      happens:
        'Pull requests from forks run with a read-only token and no secrets, so a stranger cannot do lasting harm today. It would become dangerous if this workflow were switched to `pull_request_target`.',
      saw,
      fix: ['Keep it on `pull_request`, not `pull_request_target`.'],
    };
  return {
    headline: 'An AI agent workflow that strangers cannot start today',
    happens: `Nothing a stranger writes reaches the agent today. If that changes, they could steer ${wouldBe}.`,
    saw,
    fix: ['Nothing to do now. Keep untrusted events away from this workflow.'],
  };
}

// ── CI-4: secrets the agent can read ─────────────────────────────────────────

export interface SecretFacts {
  severity: Severity;
  secrets: string[];
  /** Strangers can start the agent. */
  injectable: boolean;
  /** It can run any command, so it can print them. */
  shell: boolean;
}

export function explainSecrets(f: SecretFacts): Explain {
  const names = codes(f.secrets);
  const saw = [
    `It can read ${names}.`,
    f.injectable ? 'Strangers can start it.' : 'Strangers cannot start it.',
    f.shell ? 'It can run any command, so it can print them.' : 'It cannot run commands.',
  ];
  const idToken = f.secrets.some((s) => /^id-token/.test(s));
  if (f.severity !== 'advisory')
    return {
      headline: `The agent can leak ${names}`,
      happens: `A stranger who starts the agent can make it print ${f.secrets.length === 1 ? 'this secret and take it' : 'these secrets and take them'}.`,
      saw,
      fix: [
        `Move ${f.secrets.length === 1 ? 'it' : 'them'} to a separate job the agent does not run in.`,
        'Or take away its shell (`Bash`).',
        ...(idToken ? ['Remove `id-token: write` if the agent does not need it.'] : []),
      ],
    };
  return {
    headline: `Secrets the agent can read: ${names}`,
    happens: f.injectable
      ? 'It cannot run commands, so it cannot print them today. Giving it a shell would change that.'
      : `Strangers cannot start the agent, so ${f.secrets.length === 1 ? 'it is' : 'they are'} safe today.`,
    saw,
    fix: ['Nothing urgent. If you can, move them to a separate job the agent does not run in.'],
  };
}

// ── CI-1: broad permissions in a committed settings file ─────────────────────

export interface GrantFacts {
  high: boolean;
  file: string;
  broad: string[];
  bareShell: boolean;
  hasBackstop: boolean;
}

/** A template, example or starter: its settings are copied into other projects. */
export const TEMPLATE_PATH_RE =
  /(^|\/)(templates?|examples?|samples?|starters?|scaffolds?|boilerplates?)\//i;

export function explainGrant(f: GrantFacts): Explain {
  const git = f.broad.some((a) => /^Bash\(git:/.test(a));
  const files = f.broad.some((a) => /^Write|^Edit$/.test(a));
  const template = TEMPLATE_PATH_RE.test(f.file);
  const what = f.bareShell
    ? 'run commands and change files'
    : sentence([git ? 'run git commands' : '', files ? 'change files' : ''].filter(Boolean), true);
  const saw: string[] = [];
  if (template) saw.push('This is a template: every project made from it gets these permissions.');
  saw.push(
    `${code(f.file, 200)} allows ${codes(f.broad, 5)}${f.hasBackstop ? ' and has a deny list' : ' with no deny list'}.`
  );
  if (f.bareShell && f.hasBackstop) saw.push('The deny list blocks only the commands it names.');
  if (git) saw.push('`Bash(git:*)` looks narrow, but git can run other programs.');
  const fix: string[] = [];
  if (f.bareShell)
    fix.push('Allow only the exact commands you need, for example `Bash(npm test)`.');
  if (git)
    fix.push(
      'Replace `Bash(git:*)` with the git commands you use, for example `Bash(git status)`.'
    );
  if (!f.hasBackstop) fix.push('Or add a `deny` list for commands that must always ask.');
  if (!fix.length) fix.push('Allow only the exact tools and commands you need.');
  const who = template
    ? 'Every project made from this template lets'
    : 'Anyone who opens this repository with Claude Code lets';
  return {
    headline: `${template ? 'This template lets agents' : 'Agents in this repository'} ${f.bareShell ? 'run commands' : what} without asking`,
    happens: f.high
      ? `${who} the agent ${what} without asking. If the agent reads a malicious instruction (in an issue, a web page, a library's README), it runs it on that developer's computer at once.`
      : `${who} the agent ${what} without asking. A malicious instruction the agent reads could use that.`,
    saw,
    fix,
  };
}

// ── CI-3: an MCP server that is not pinned ───────────────────────────────────

/** The package an `npx` command line runs, without its version: the first argument after
 *  npx that is not a flag. */
export function npxPackage(argv: string): string | null {
  const t = argv.split(/\s+/);
  const i = t.findIndex((x) => /(^|\/)npx$/.test(x));
  if (i < 0) return null;
  for (let k = i + 1; k < t.length; k++) {
    if (/^-/.test(t[k])) {
      if (/^(-p|--package)$/.test(t[k])) k++; // the next token is a value, not the package
      continue;
    }
    const m = /^(@?[^@\s]+)(@.*)?$/.exec(t[k]);
    return m ? m[1] : null;
  }
  return null;
}

export function explainMcp(f: { name: string; argv: string }): Explain {
  const pkg = npxPackage(f.argv);
  const what = pkg ? code(pkg) : 'the package';
  return {
    headline: `MCP server ${code(f.name, 60)} installs whatever version is newest, every time`,
    happens: `Each run downloads the latest ${what} from npm. If that package is ever taken over, the next version runs on every developer's computer.`,
    saw: [`It starts with ${code(f.argv, 120)}.`],
    fix: [
      pkg ? `Pin an exact version, for example ${code(`${pkg}@x.y.z`)}.` : 'Pin an exact version.',
    ],
  };
}

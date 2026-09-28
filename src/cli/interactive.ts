/** Shared by setup and init: automation must never be asked a question. */
export function isCI(env: NodeJS.ProcessEnv = process.env): boolean {
  return ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'TF_BUILD', 'BUILDKITE'].some(
    (key) => !!env[key] && !/^(0|false|no)$/i.test(env[key]!)
  );
}
export function isInteractive(): boolean {
  return (
    !!process.stdin.isTTY &&
    !!process.stdout.isTTY &&
    !isCI() &&
    process.env.NODE9_NONINTERACTIVE !== '1'
  );
}
export function isPromptCancellation(error: unknown): boolean {
  return error instanceof Error && ['ExitPromptError', 'AbortPromptError'].includes(error.name);
}

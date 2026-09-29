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
/** A problem the user can fix. Setup prints it as one line, never a stack trace. */
export class SetupError extends Error {
  override name = 'SetupError';
}
export function invalidConfig(): SetupError {
  return new SetupError(
    '~/.node9/config.json is not valid JSON. Fix it, or run node9 init --force to replace it with defaults.'
  );
}
/** Installing or removing a login service needs a person at a real terminal. */
export function mayChangeService(env: {
  stdoutTTY: boolean;
  ci: boolean;
  skipSetup?: boolean;
}): boolean {
  return !env.skipSetup && env.stdoutTTY && !env.ci;
}
export function isPromptCancellation(error: unknown): boolean {
  return error instanceof Error && ['ExitPromptError', 'AbortPromptError'].includes(error.name);
}

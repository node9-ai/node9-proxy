// Whether a shell call reads outside content (`gh issue view`, `curl` of a
// page), as the PostToolUse hook classifies it. One helper for the hook
// (log.ts), `scan` and `forecast-cases`, so the three record the same reads.
import { classifyShellExposure } from '@node9/policy-engine';

/** The classification of a Bash call's command, or null for any other tool. */
export function shellFetch(
  tool: string,
  rawInput: unknown
): ReturnType<typeof classifyShellExposure> | null {
  if (tool !== 'Bash' && tool !== 'bash') return null;
  const cmd =
    rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput)
      ? (rawInput as Record<string, unknown>).command
      : undefined;
  return typeof cmd === 'string' && cmd.length > 0 ? classifyShellExposure(cmd) : null;
}

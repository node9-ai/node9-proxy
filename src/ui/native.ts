// src/ui/native.ts
import { spawn, ChildProcess } from 'child_process'; // 1. Added ChildProcess import
import chalk from 'chalk';

const isTestEnv = () => {
  return (
    process.env.NODE_ENV === 'test' ||
    process.env.VITEST === 'true' ||
    !!process.env.VITEST ||
    process.env.CI === 'true' ||
    !!process.env.CI ||
    process.env.NODE9_TESTING === '1'
  );
};

/**
 * Truncates long strings by keeping the start and end.
 */
function smartTruncate(str: string, maxLen: number = 500): string {
  if (str.length <= maxLen) return str;
  const edge = Math.floor(maxLen / 2) - 3;
  return `${str.slice(0, edge)} ... ${str.slice(-edge)}`;
}

function formatArgs(args: unknown): string {
  if (args === null || args === undefined) return '(none)';

  let parsed = args;

  // 1. EXTRA STEP: If args is a string, try to see if it's nested JSON
  // Gemini often wraps the command inside a stringified JSON object
  if (typeof args === 'string') {
    const trimmed = args.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        parsed = args;
      }
    } else {
      return smartTruncate(args, 600);
    }
  }

  // 2. Now handle the object (whether it was passed as one or parsed above)
  if (typeof parsed === 'object' && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;

    const codeKeys = [
      'command',
      'cmd',
      'shell_command',
      'bash_command',
      'script',
      'code',
      'input',
      'sql',
      'query',
      'arguments',
      'args',
      'param',
      'params',
      'text',
    ];
    const foundKey = Object.keys(obj).find((k) => codeKeys.includes(k.toLowerCase()));

    if (foundKey) {
      const val = obj[foundKey];
      const str = typeof val === 'string' ? val : JSON.stringify(val);
      // Visual improvement: add a label so you know what you are looking at
      return `[${foundKey.toUpperCase()}]:\n${smartTruncate(str, 500)}`;
    }

    return Object.entries(obj)
      .slice(0, 5)
      .map(
        ([k, v]) => `  ${k}: ${smartTruncate(typeof v === 'string' ? v : JSON.stringify(v), 300)}`
      )
      .join('\n');
  }

  return smartTruncate(JSON.stringify(parsed), 200);
}

export function sendDesktopNotification(title: string, body: string): void {
  if (isTestEnv()) return;
  try {
    if (process.platform === 'darwin') {
      const script = `display notification "${body.replace(/"/g, '\\"')}" with title "${title.replace(/"/g, '\\"')}"`;
      spawn('osascript', ['-e', script], { detached: true, stdio: 'ignore' }).unref();
    } else if (process.platform === 'linux') {
      spawn('notify-send', [title, body, '--icon=dialog-warning'], {
        detached: true,
        stdio: 'ignore',
      }).unref();
    }
  } catch {
    /* ignore */
  }
}

export async function askNativePopup(
  toolName: string,
  args: unknown,
  agent?: string,
  explainableLabel?: string,
  locked: boolean = false,
  signal?: AbortSignal
): Promise<'allow' | 'deny' | 'always_allow'> {
  if (isTestEnv()) return 'deny';

  const formattedArgs = formatArgs(args);
  const title = locked ? `⚡ Node9 — Locked` : `🛡️ Node9 — Action Approval`;

  let message = '';
  if (locked) message += `⚠️ LOCKED BY ADMIN POLICY\n`;
  message += `Tool:  ${toolName}\n`;
  message += `Agent: ${agent || 'AI Agent'}\n`;
  message += `Rule:  ${explainableLabel || 'Security Policy'}\n\n`;
  message += `${formattedArgs}`;

  process.stderr.write(chalk.yellow(`\n🛡️  Node9: Intercepted "${toolName}" — awaiting user...\n`));

  return new Promise((resolve) => {
    // 2. FIXED: Use ChildProcess type instead of any
    let childProcess: ChildProcess | null = null;

    const onAbort = () => {
      if (childProcess && childProcess.pid) {
        try {
          process.kill(childProcess.pid, 'SIGKILL');
        } catch {
          /* ignore */
        }
      }
      resolve('deny');
    };

    if (signal) {
      if (signal.aborted) return resolve('deny');
      signal.addEventListener('abort', onAbort);
    }

    try {
      if (process.platform === 'darwin') {
        const buttons = locked
          ? `buttons {"Waiting…"} default button "Waiting…"`
          : `buttons {"Block", "Always Allow", "Allow"} default button "Allow" cancel button "Block"`;
        const script = `on run argv\ntell application "System Events"\nactivate\ndisplay dialog (item 1 of argv) with title (item 2 of argv) ${buttons}\nend tell\nend run`;
        childProcess = spawn('osascript', ['-e', script, '--', message, title]);
      } else if (process.platform === 'linux') {
        const argsList = [
          locked ? '--info' : '--question',
          '--modal',
          '--width=450',
          '--title',
          title,
          '--text',
          message,
          '--ok-label',
          locked ? 'Waiting...' : 'Allow',
          '--timeout',
          '300',
        ];
        if (!locked) {
          argsList.push('--cancel-label', 'Block');
          argsList.push('--extra-button', 'Always Allow');
        }
        childProcess = spawn('zenity', argsList);
      } else if (process.platform === 'win32') {
        const b64Msg = Buffer.from(message).toString('base64');
        const b64Title = Buffer.from(title).toString('base64');
        const ps = `Add-Type -AssemblyName PresentationFramework; $msg = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("${b64Msg}")); $title = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("${b64Title}")); $res = [System.Windows.MessageBox]::Show($msg, $title, "${locked ? 'OK' : 'YesNo'}", "Warning", "Button2", "DefaultDesktopOnly"); if ($res -eq "Yes") { exit 0 } else { exit 1 }`;
        childProcess = spawn('powershell', ['-Command', ps]);
      }

      let output = '';
      // 3. FIXED: Specified Buffer type for stream data
      childProcess?.stdout?.on('data', (d: Buffer) => (output += d.toString()));

      childProcess?.on('close', (code: number) => {
        if (signal) signal.removeEventListener('abort', onAbort);
        if (locked) return resolve('deny');
        if (output.includes('Always Allow')) return resolve('always_allow');
        if (code === 0) return resolve('allow');
        resolve('deny');
      });
    } catch {
      resolve('deny');
    }
  });
}

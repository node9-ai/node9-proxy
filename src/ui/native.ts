// src/ui/native.ts
import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import { smartTruncate, extractContext } from '../context-sniper';

export const isTestEnv = () => {
  return (
    process.env.NODE_ENV === 'test' ||
    process.env.VITEST === 'true' ||
    !!process.env.VITEST ||
    process.env.CI === 'true' ||
    !!process.env.CI ||
    process.env.NODE9_TESTING === '1'
  );
};

export function formatArgs(
  args: unknown,
  matchedField?: string,
  matchedWord?: string
): { message: string; intent: 'EDIT' | 'EXEC' } {
  if (args === null || args === undefined) return { message: '(none)', intent: 'EXEC' };

  let parsed = args;

  // Handle stringified JSON (Gemini wraps commands inside a JSON string)
  if (typeof args === 'string') {
    const trimmed = args.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        parsed = args;
      }
    } else {
      return { message: smartTruncate(args, 600), intent: 'EXEC' };
    }
  }

  if (typeof parsed === 'object' && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;

    // Case 1: File edit — detected by presence of old_string + new_string keys
    if (obj.old_string !== undefined && obj.new_string !== undefined) {
      const file = obj.file_path ? path.basename(String(obj.file_path)) : 'file';
      const oldPreview = smartTruncate(String(obj.old_string), 120);
      const newPreview = extractContext(String(obj.new_string), matchedWord).snippet;
      return {
        intent: 'EDIT',
        message:
          `📝 EDITING: ${file}\n📂 PATH: ${obj.file_path}\n\n` +
          `--- REPLACING ---\n${oldPreview}\n\n` +
          `+++ NEW CODE +++\n${newPreview}`,
      };
    }

    // Case 2: We know exactly which field triggered — highlight it
    if (matchedField && obj[matchedField] !== undefined) {
      const otherKeys = Object.keys(obj).filter((k) => k !== matchedField);
      const context =
        otherKeys.length > 0
          ? `⚙️  Context: ${otherKeys.map((k) => `${k}=${smartTruncate(typeof obj[k] === 'object' ? JSON.stringify(obj[k]) : String(obj[k]), 30)}`).join(', ')}\n\n`
          : '';
      const content = extractContext(String(obj[matchedField]), matchedWord).snippet;
      return {
        intent: 'EXEC',
        message: `${context}🛑 [${matchedField.toUpperCase()}]:\n${content}`,
      };
    }

    // Case 3: Hardcoded common keys fallback
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
      return {
        intent: 'EXEC',
        message: `[${foundKey.toUpperCase()}]:\n${smartTruncate(str, 500)}`,
      };
    }

    // Case 4: Pretty-print up to 5 fields
    const msg = Object.entries(obj)
      .slice(0, 5)
      .map(
        ([k, v]) => `  ${k}: ${smartTruncate(typeof v === 'string' ? v : JSON.stringify(v), 300)}`
      )
      .join('\n');
    return { intent: 'EXEC', message: msg };
  }

  return { intent: 'EXEC', message: smartTruncate(JSON.stringify(parsed), 200) };
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

function escapePango(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function buildPlainMessage(
  toolName: string,
  formattedArgs: string,
  agent: string | undefined,
  explainableLabel: string | undefined,
  locked: boolean,
  allowCount: number = 1
): string {
  const lines: string[] = [];

  if (locked) lines.push('⚠️  LOCKED BY ADMIN POLICY\n');

  lines.push(`🤖 ${agent || 'AI Agent'}  |  🔧 ${toolName}`);
  lines.push(`🛡️  ${explainableLabel || 'Security Policy'}`);
  lines.push('');
  lines.push(formattedArgs);

  if (allowCount >= 3) {
    lines.push('');
    lines.push(`💡 Approved ${allowCount - 1}× before — "Always Allow" creates a permanent rule`);
  }

  if (!locked) {
    lines.push('');
    lines.push('↵ Enter = Allow ↵   |   ⎋ Esc = Block ⎋   |   "Always Allow" = never ask again');
  }

  return lines.join('\n');
}

function buildPangoMessage(
  toolName: string,
  formattedArgs: string,
  agent: string | undefined,
  explainableLabel: string | undefined,
  locked: boolean,
  allowCount: number = 1
): string {
  const lines: string[] = [];

  if (locked) {
    lines.push('<span foreground="red" weight="bold">⚠️  LOCKED BY ADMIN POLICY</span>');
    lines.push('');
  }

  lines.push(
    `<b>🤖 ${escapePango(agent || 'AI Agent')}</b>  |  <b>🔧 <tt>${escapePango(toolName)}</tt></b>`
  );
  lines.push(`<i>🛡️  ${escapePango(explainableLabel || 'Security Policy')}</i>`);
  lines.push('');
  lines.push(`<tt>${escapePango(formattedArgs)}</tt>`);

  if (allowCount >= 3) {
    lines.push('');
    lines.push(
      `<span foreground="#f0c040">💡 Approved ${allowCount - 1}× before — "Always Allow" creates a permanent rule</span>`
    );
  }

  if (!locked) {
    lines.push('');
    lines.push(
      '<small>↵ Enter = <b>Allow ↵</b>   |   ⎋ Esc = <b>Block ⎋</b>   |   "Always Allow" = never ask again</small>'
    );
  }

  return lines.join('\n');
}

export async function askNativePopup(
  toolName: string,
  args: unknown,
  agent?: string,
  explainableLabel?: string,
  locked: boolean = false,
  signal?: AbortSignal,
  matchedField?: string,
  matchedWord?: string,
  allowCount: number = 1
): Promise<'allow' | 'deny' | 'always_allow'> {
  if (isTestEnv()) return 'deny';

  const { message: formattedArgs, intent } = formatArgs(args, matchedField, matchedWord);
  const intentLabel = intent === 'EDIT' ? 'Code Edit' : 'Action Approval';
  const title = locked ? `⚡ Node9 — Locked` : `🛡️ Node9 — ${intentLabel}`;

  const message = buildPlainMessage(
    toolName,
    formattedArgs,
    agent,
    explainableLabel,
    locked,
    allowCount
  );

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
          : `buttons {"Block ⎋", "Always Allow", "Allow ↵"} default button "Allow ↵" cancel button "Block ⎋"`;
        const script = `on run argv\ntell application "System Events"\nactivate\ndisplay dialog (item 1 of argv) with title (item 2 of argv) ${buttons}\nend tell\nend run`;
        childProcess = spawn('osascript', ['-e', script, '--', message, title]);
      } else if (process.platform === 'linux') {
        const pangoMessage = buildPangoMessage(
          toolName,
          formattedArgs,
          agent,
          explainableLabel,
          locked,
          allowCount
        );
        const argsList = [
          locked ? '--info' : '--question',
          '--modal',
          '--width=480',
          '--title',
          title,
          '--text',
          pangoMessage,
          '--ok-label',
          locked ? 'Waiting...' : 'Allow  ↵',
          '--timeout',
          '300',
        ];
        if (!locked) {
          argsList.push('--cancel-label', 'Block  ⎋');
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

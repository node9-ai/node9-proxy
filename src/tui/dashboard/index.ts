// src/tui/dashboard/index.ts
//
// Entry point for `node9 monitor`. Renders the Ink App via dynamic
// import so the heavy React runtime is only loaded when this command
// is actually invoked. Other CLI commands stay fast.
//
// Uses the terminal's alternate-screen buffer (like vim, htop, lazygit)
// so re-renders never leak into the user's scrollback. Cleanup is bound
// to every plausible exit path (clean exit, SIGINT, SIGTERM, uncaught
// exception) so a crash never leaves the user's terminal in alt-screen
// mode with their shell prompt invisible.

const ENTER_ALT_SCREEN = '\x1b[?1049h';
const EXIT_ALT_SCREEN = '\x1b[?1049l';

let altScreenActive = false;

function enterAltScreen(): void {
  if (altScreenActive) return;
  process.stdout.write(ENTER_ALT_SCREEN);
  altScreenActive = true;
}

function exitAltScreen(): void {
  if (!altScreenActive) return;
  process.stdout.write(EXIT_ALT_SCREEN);
  altScreenActive = false;
}

export async function startMonitor(): Promise<void> {
  // The dashboard relies on Ink's useInput, which requires a TTY in raw
  // mode. Piping or redirecting stdin (CI, `echo q | node9 monitor`)
  // would surface a noisy React error trace; bail with a clean message.
  if (!process.stdin.isTTY) {
    process.stderr.write(
      'node9 monitor requires an interactive TTY (run it directly in your terminal).\n'
    );
    process.exit(1);
  }
  // Sequential awaits avoid an ESM race in Node when these modules are
  // loaded concurrently from a CJS entry. Promise.all triggered the
  // "module not yet fully loaded" error in dist/cli.js.
  const React = await import('react');
  const { render } = await import('ink');
  const { App } = await import('./App.js');

  // Bind alt-screen cleanup to every plausible exit. Order matters: we
  // need exitAltScreen to fire BEFORE Node prints any final stack trace
  // so the user sees the trace in their normal scrollback, not the
  // erased alt buffer.
  const cleanup = () => exitAltScreen();
  process.on('exit', cleanup);
  process.on('SIGINT', () => {
    cleanup();
    process.exit(130);
  });
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(143);
  });
  process.on('uncaughtException', (err) => {
    cleanup();
    // Re-throw so Node's default handler still prints the trace + exits.
    setImmediate(() => {
      throw err;
    });
  });

  enterAltScreen();

  // Bypass ink's useInput for the quit key. When the [2] view is loading,
  // four async walks (audit log, Claude cost, Codex cost, scan walker) all
  // run concurrently — even though each yields between chunks, the
  // microtask queue stays full enough that ink can fall behind on
  // keypress dispatch. Users press q over and over with no response.
  //
  // This direct stdin listener fires off Node's Poll phase as soon as
  // a keystroke arrives, before anything else. We only handle q (0x71)
  // and Ctrl+C (0x03); every other byte falls through to ink unchanged.
  // Trade-off: q quits even while the user is typing into the LIVE filter
  // (Esc to clear and re-enter that flow). The reliability win is worth
  // the corner-case cost.
  const onStdinByte = (chunk: Buffer | string): void => {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
    if (buf.length === 0) return;
    const byte = buf[0];
    if (byte === 0x71 /* q */ || byte === 0x03 /* Ctrl+C */) {
      exitAltScreen();
      process.stdout.write('\n');
      process.exit(0);
    }
  };
  process.stdin.on('data', onStdinByte);

  try {
    const instance = render(React.createElement(App));
    await instance.waitUntilExit();
  } finally {
    process.stdin.off('data', onStdinByte);
    exitAltScreen();
  }
}

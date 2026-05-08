// src/tui/dashboard/index.ts
//
// Entry point for `node9 dashboard-spike`. Renders the Ink App via
// dynamic import so the heavy React runtime is only loaded when this
// command is actually invoked. Other CLI commands stay fast.

export async function startDashboardSpike(): Promise<void> {
  // The dashboard relies on Ink's useInput, which requires a TTY in raw
  // mode. Piping or redirecting stdin (CI, `echo q | node9 dashboard-spike`)
  // would surface a noisy React error trace; bail with a clean message.
  if (!process.stdin.isTTY) {
    process.stderr.write(
      'node9 dashboard-spike requires an interactive TTY (run it directly in your terminal).\n'
    );
    process.exit(1);
  }
  // Sequential awaits avoid an ESM race in Node when these modules are
  // loaded concurrently from a CJS entry. Promise.all triggered the
  // "module not yet fully loaded" error in dist/cli.js.
  const React = await import('react');
  const { render } = await import('ink');
  const { App } = await import('./App.js');
  const instance = render(React.createElement(App));
  await instance.waitUntilExit();
}

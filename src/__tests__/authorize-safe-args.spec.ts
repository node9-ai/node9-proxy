// node9Firewall#383: arguments that made the engine throw. On the hook a
// throw let the call run; on the MCP gateway and the proxy, which stop a call
// when the engine throws, any such argument made every call fail. The safe
// copy is applied where they all enter: authorizeHeadless.
import { describe, it, expect, vi } from 'vitest';
import { authorizeHeadless } from '../core.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));
vi.mock('../ui/native', () => ({
  askNativePopup: vi.fn().mockResolvedValue('deny'),
  sendDesktopNotification: vi.fn(),
}));

const BLOCKED = 'rm -rf ~/';
const deep = (n: number): unknown => JSON.parse('{"a":'.repeat(n) + '1' + '}'.repeat(n));
const opts = { calledFromDaemon: true };

describe('authorizeHeadless reads a safe copy of the arguments', () => {
  it('judges a stopped command the same beside a field nested 5,000 levels deep', async () => {
    const plain = await authorizeHeadless('Bash', { command: BLOCKED }, undefined, opts);
    expect(plain.approved).toBe(false);
    const nested = await authorizeHeadless(
      'Bash',
      { command: BLOCKED, description: deep(5000) },
      undefined,
      opts
    );
    expect(nested.approved).toBe(false);
    expect(nested.blockedByLabel).toBe(plain.blockedByLabel);
  });

  it('judges it the same beside an object that cannot be turned into a string', async () => {
    const r = await authorizeHeadless(
      'Bash',
      { command: BLOCKED, file_path: JSON.parse('{"toString":1,"valueOf":2}') },
      undefined,
      opts
    );
    expect(r.approved).toBe(false);
  });

  it('does not throw on an MCP call whose only argument is such a value', async () => {
    // Such a call goes to review, which waits for a person: the point here is
    // only that the gate got that far instead of throwing.
    const outcome = (call: Promise<unknown>) =>
      Promise.race([
        call.then(
          () => 'decided',
          (err) => `threw: ${String(err)}`
        ),
        new Promise<string>((resolve) => setTimeout(() => resolve('waiting for a person'), 1500)),
      ]);
    expect(
      await outcome(
        authorizeHeadless('mcp__db__query', { sql: JSON.parse('{"toString":1}') }, undefined, opts)
      )
    ).not.toMatch(/^threw/);
    expect(
      await outcome(authorizeHeadless('mcp__db__query', deep(5000), undefined, opts))
    ).not.toMatch(/^threw/);
  });
});

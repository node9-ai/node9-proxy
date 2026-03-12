/**
 * Node9 SDK — protect() example
 *
 * There are two ways Node9 protects you:
 *
 * 1. CLI Proxy (automatic) — Node9 wraps Claude Code / Gemini CLI at the
 *    process level and intercepts every tool call automatically. No code needed.
 *
 * 2. SDK / protect() (manual) — for developers building their own Node.js apps
 *    with an AI SDK (Anthropic, LangChain, etc.). Wrap any dangerous function
 *    with `protect()` and Node9 will intercept it before execution, showing a
 *    native approval popup and applying your security policy.
 *
 * Usage:
 *   npm install @node9/proxy
 *   npx ts-node examples/demo.ts
 */
import { protect } from '@node9/proxy';
import chalk from 'chalk';

async function main() {
  const deleteDatabase = async (name: string) => {
    console.log(chalk.green(`✅ Success: Database ${name} has been deleted.`));
  };

  // Wrap the dangerous function — Node9 will intercept it before it runs
  const secureDelete = protect('aws.rds.delete_database', deleteDatabase);

  console.log(chalk.cyan("🤖 AI Agent: 'I am going to clean up the production DB...'"));

  try {
    // Node9 will show a native popup asking you to Allow / Block this action.
    // If you click Block (or the policy denies it), an error is thrown.
    await secureDelete('production-db-v1');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(chalk.yellow(`\n🛡️ Node9 blocked it: ${msg}`));
  }
}

main();

import { protect } from '../src/index';
import chalk from 'chalk';

async function main() {
  const deleteDatabase = async (name: string) => {
    console.log(chalk.green(`✅ Success: Database ${name} has been deleted.`));
  };

  // Wrap the dangerous function
  const secureDelete = protect('aws.rds.delete_database', deleteDatabase);

  console.log(chalk.cyan("🤖 AI Agent: 'I am going to clean up the production DB...'"));

  try {
    await secureDelete('production-db-v1');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(chalk.yellow(`\n🛡️ Node9 caught it: ${msg}`));
  }
}

main();

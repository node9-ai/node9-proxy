// src/daemon/index.ts — Node9 localhost approval server (barrel)
// Public API for the daemon module. Internal implementation split into:
//   daemon/state.ts   — shared state, types, utility functions, SSE/broadcast
//   daemon/server.ts  — HTTP server and all route handlers (startDaemon)
//   daemon/service.ts — login service install/uninstall (launchd / systemd)
import fs from 'fs';
import chalk from 'chalk';
import { spawnSync } from 'child_process';

export { startDaemon } from './server';
export {
  DAEMON_PORT,
  DAEMON_HOST,
  DAEMON_PID_FILE,
  DECISIONS_FILE,
  AUDIT_LOG_FILE,
  hasInteractiveClient,
} from './state';
export { installDaemonService, uninstallDaemonService, isDaemonServiceInstalled } from './service';

import { DAEMON_PORT, DAEMON_PID_FILE } from './state';
import { isDaemonServiceInstalled } from './service';

const MAX_PID = 4_194_304;

export function stopDaemon(): void {
  if (!fs.existsSync(DAEMON_PID_FILE)) return console.log(chalk.yellow('Not running.'));
  try {
    const data = JSON.parse(fs.readFileSync(DAEMON_PID_FILE, 'utf-8')) as Record<string, unknown>;
    const pid = data.pid;
    if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0 || pid > MAX_PID) {
      console.log(chalk.gray('Cleaned up invalid PID file.'));
      return;
    }
    process.kill(pid, 'SIGTERM');
    console.log(chalk.green('✅ Stopped.'));
  } catch {
    console.log(chalk.gray('Cleaned up stale PID file.'));
  } finally {
    try {
      fs.unlinkSync(DAEMON_PID_FILE);
    } catch {
      /* non-fatal */
    }
  }
}

export function daemonStatus(): void {
  const serviceInstalled = isDaemonServiceInstalled();
  const serviceLabel = serviceInstalled
    ? chalk.green('installed (starts on login)')
    : chalk.yellow('not installed — run: node9 daemon install');

  let processStatus: string;
  if (fs.existsSync(DAEMON_PID_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(DAEMON_PID_FILE, 'utf-8')) as Record<string, unknown>;
      const pid = data.pid;
      const port = data.port;
      if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0 || pid > MAX_PID) {
        processStatus = chalk.yellow('not running (invalid PID file)');
      } else {
        process.kill(pid, 0);
        processStatus = chalk.green(
          `running  (PID ${pid}, port ${typeof port === 'number' ? port : DAEMON_PORT})`
        );
      }
    } catch {
      processStatus = chalk.yellow('not running (stale PID file)');
    }
  } else {
    // No PID file — check if port is in use (orphaned daemon)
    const r = spawnSync('ss', ['-Htnp', `sport = :${DAEMON_PORT}`], {
      encoding: 'utf8',
      timeout: 500,
    });
    if (r.status === 0 && (r.stdout ?? '').includes(`:${DAEMON_PORT}`)) {
      processStatus = chalk.yellow(`running (orphaned — no PID file)`);
    } else {
      processStatus = chalk.yellow('not running');
    }
  }

  console.log(`\n  Process : ${processStatus}`);
  console.log(`  Service : ${serviceLabel}\n`);
}

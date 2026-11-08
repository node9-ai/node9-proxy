// packages/policy-engine/src/shell/services.ts
// The system services whose stop or kill is a finding of its own
// (`commands.system-processes`, node9Firewall#385 wave 4). Shared by the
// shell detector (processes.ts) and the inline-code judge (inline-code.ts);
// no imports, so neither side depends on the other.
//
// Two tiers, both in the check: infrastructure (other users and programs on
// the machine depend on them) and the servers a deployed application runs
// on. A developer stopping a local database is the false-positive risk of
// the second tier; it is measured before every release and moves to Strict
// if the real commands say so. `init` counts only quoted or in a glob
// (`*"init"*`, a process-matching pattern), since `git init` is everywhere;
// bare `systemd` is prose in too many scripts ("the systemd daemon") and is
// pid 1, matched as the pid; `docker` the client is not `dockerd` the daemon;
// node9's own daemon is `commands.node9-disarm`.

export const INFRASTRUCTURE_SERVICES: readonly string[] = [
  'init',
  'sshd',
  'dockerd',
  'docker-proxy',
  'containerd',
  'containerd-shim',
  'docker-containerd-shim',
  'runc',
  'systemd-journald',
  'journald',
  'systemd-logind',
  'systemd-udevd',
  'udevd',
  'dbus-daemon',
  'polkitd',
  'sssd',
  'kubelet',
  'kube-apiserver',
  'crond',
  'cron',
  'atd',
  'auditd',
  'rsyslogd',
  'syslogd',
  'chronyd',
  'ntpd',
  'NetworkManager',
  'wpa_supplicant',
  'dhclient',
  'avahi-daemon',
  'firewalld',
  'ufw',
  'cupsd',
  'snapd',
  'bluetoothd',
  'Xorg',
  'Xwayland',
  'gdm',
  'sddm',
  'lightdm',
];

export const SERVER_SERVICES: readonly string[] = [
  'nginx',
  'apache2',
  'httpd',
  'mysqld',
  'mariadbd',
  'postgres',
  'postgresql',
  'redis-server',
  'mongod',
];

export const SYSTEM_SERVICES: readonly string[] = [...INFRASTRUCTURE_SERVICES, ...SERVER_SERVICES];

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&');

/** A listed name as a whole word: not `crontab` for `cron`, not `sshd_config`
 *  for `sshd`; `*sshd*`, `"sshd"` and `/usr/sbin/sshd` are the name. */
const SERVICE_WORD_RE = new RegExp(
  `(?:^|[^A-Za-z0-9_.-])(${SYSTEM_SERVICES.map(escape).join('|')})(?![A-Za-z0-9_.-])`,
  'i'
);

/** `init` only as a quoted word or a glob: `"init"`, `'init'`, `*init*`. */
const INIT_PATTERN_RE = /(?:["'*])init(?:["'*])/;

/** The first listed service named in `text` as a whole word, canonical spelling, or null. */
export function serviceNamedIn(text: string): string | null {
  const re = new RegExp(SERVICE_WORD_RE.source, 'gi');
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const lower = m[1].toLowerCase();
    if (lower === 'init' && !INIT_PATTERN_RE.test(text)) continue;
    return SYSTEM_SERVICES.find((s) => s.toLowerCase() === lower) ?? m[1];
  }
  return null;
}

/** Unit names that are not the daemon's process name (`docker.service` runs
 *  dockerd, Debian's `ssh.service` runs sshd). */
const UNIT_ALIASES: Record<string, string> = {
  docker: 'dockerd',
  ssh: 'sshd',
  mysql: 'mysqld',
  mariadb: 'mariadbd',
  redis: 'redis-server',
  mongodb: 'mongod',
  apache: 'apache2',
  rsyslog: 'rsyslogd',
  'systemd-networkd': 'systemd-udevd',
  dbus: 'dbus-daemon',
  avahi: 'avahi-daemon',
  bluetooth: 'bluetoothd',
  cups: 'cupsd',
  chrony: 'chronyd',
};

/** The listed service a unit or process name IS (`nginx.service`, `/usr/sbin/sshd`,
 *  `docker.service`), or null. */
export function serviceOf(name: string): string | null {
  const leaf = name
    .replace(/^.*[\\/]/, '')
    .replace(/\.service$/, '')
    .replace(/@.*$/, '');
  const lower = leaf.toLowerCase();
  return SYSTEM_SERVICES.find((s) => s.toLowerCase() === lower) ?? UNIT_ALIASES[lower] ?? null;
}

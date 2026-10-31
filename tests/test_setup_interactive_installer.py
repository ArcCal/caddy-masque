#!/usr/bin/env python3
"""Regression checks for setup-interactive-caddy-masque-autoarch-cloudflare-dns.sh.

Only shell functions are sourced. apt-get is a recording mock and a compiled
sleeper stands in for the server, so nothing is installed, stopped or bound.
Requires a C compiler (cc) for the process-identification checks.
"""
from pathlib import Path
import subprocess
import tempfile

SCRIPT = Path(__file__).resolve().parents[1] / 'setup-interactive-caddy-masque-autoarch-cloudflare-dns.sh'
TEXT = SCRIPT.read_text()


def shell(command, *args):
    return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=60)


result = shell('apt-get() { printf "%s\\n" "$*"; read -r _ && echo stdin-not-eof; return 0; }; say() { :; }; '
               'install_packages')
calls = [line for line in result.stdout.splitlines() if line.startswith('-o')]
assert result.returncode == 0 and len(calls) == 2, result.stdout + result.stderr
assert all('DPkg::Lock::Timeout=1800' in line for line in calls) and 'stdin-not-eof' not in result.stdout
print('PASS: apt-get waits for a held dpkg lock and receives no terminal input')

main = TEXT[TEXT.index('\nmain() {'):]
assert main.index('    stage_token\n') < main.index('install_packages') < main.index('    build_server\n')
install = TEXT[TEXT.index('\ninstall_server() {'):TEXT.index('\nverify_server() {')]
last_check = install.rindex('check_port_owners require-free || die')
assert install.rindex('provision_service_user') < last_check < install.index('systemctl restart "$SERVICE"')
assert install.count('stop_standalone_servers') == 2
print('PASS: both answers precede packages/build; 443 is rechecked immediately before startup')

with tempfile.TemporaryDirectory() as directory:
    base = Path(directory)
    (base / 'sleeper.c').write_text('#include <unistd.h>\nint main(void) { for (;;) pause(); }\n')
    binary = base / 'caddy-masque'
    subprocess.run(['cc', '-o', str(binary), str(base / 'sleeper.c')], check=True)
    config = str(base / 'Caddyfile')
    processes = []

    def start(*args, executable=binary):
        process = subprocess.Popen([str(executable), *args])
        processes.append(process)
        return process

    def owned(command, *args):
        return shell('BINARY="$1"; CONFIG="$2"; shift 2; ' + command, str(binary), config, *args)

    try:
        for args in (['run', '--config', config], ['run', '--config=' + config, '--adapter', 'caddyfile'],
                     ['run', '-c', config, '--environ'], ['run', '--pidfile', '--config', '--config', config]):
            assert owned('is_standalone_server "$1"', str(start(*args).pid)).returncode == 0, args
        other = base / 'copy' / 'caddy-masque'
        other.parent.mkdir()
        other.write_bytes(binary.read_bytes())
        other.chmod(0o755)
        for args, executable in ((['run'], binary), (['run', '--config', '/etc/caddy/Caddyfile'], binary),
                                 (['run', '--config', config, '--resume'], binary),
                                 (['run', '--config', config, '--config', config], binary),
                                 (['validate', '--config', config], binary), (['run', '--config', config], other)):
            pid = str(start(*args, executable=executable).pid)
            assert owned('is_standalone_server "$1"', pid).returncode != 0, (args, executable)
        print('PASS: only the dedicated executable running the managed Caddyfile is identified')
        for process in processes:
            process.kill()
            process.wait()
        processes.clear()
        ours, foreign = start('run', '--config', config), start('run', '--config', '/etc/caddy/Caddyfile')
        result = owned('stop_standalone_servers && echo stopped')
        assert result.returncode == 0 and 'Sent TERM' in result.stdout, result.stderr
        assert ours.wait(timeout=5) is not None and foreign.poll() is None
        print('PASS: takeover terminates identified manual instances and spares other processes')
    finally:
        for process in processes:
            process.kill()
            process.wait()

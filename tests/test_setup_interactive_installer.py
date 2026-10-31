#!/usr/bin/env python3
"""Regression checks for setup-interactive-caddy-masque-autoarch-cloudflare-dns.sh.

Only shell functions are sourced. apt-get is a recording mock and a compiled
sleeper stands in for the server, so nothing is installed, stopped or bound.
Requires a C compiler (cc) for the process-identification checks.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import time

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

# apt: only list/archive lock failures are retried (DPkg::Lock::Timeout does
# not cover them); other failures return at once.
for script, expected, retried in (
        ('if (( attempts < 3 )); then echo "E: Could not get lock /var/lib/apt/lists/lock." >&2; return 100; fi',
         'status=0 attempts=3', True),
        ('echo "E: Unable to locate package nonexistent" >&2; return 100', 'status=100 attempts=1', False)):
    result = shell('sleep() { echo slept >&2; }; attempts=0; apt-get() { attempts=$((attempts+1)); ' + script +
                   '; }; apt_get update; echo "status=$? attempts=$attempts"')
    assert expected in result.stdout, result.stdout + result.stderr
    assert ('slept' in result.stderr) == retried, result.stderr
print('PASS: apt lock errors are retried for a bounded time and other apt errors are not')

if os.geteuid() == 0:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / 'stubborn.c').write_text('#include <signal.h>\n#include <unistd.h>\n'
                                         'int main(void) { signal(SIGTERM, SIG_IGN); for (;;) pause(); }\n')
        (base / 'bind.c').write_text(
            '#include <netinet/in.h>\n#include <sys/socket.h>\n#include <unistd.h>\n'
            'int main(void){int t=socket(AF_INET,SOCK_STREAM,0),u=socket(AF_INET,SOCK_DGRAM,0),o=1;'
            'setsockopt(t,SOL_SOCKET,SO_REUSEADDR,&o,sizeof o);struct sockaddr_in a={0};a.sin_family=AF_INET;'
            'a.sin_port=htons(443);if(bind(t,(void*)&a,sizeof a)||listen(t,1)||bind(u,(void*)&a,sizeof a))return 1;'
            'for(;;)pause();}\n')
        binary = base / 'caddy-masque'
        subprocess.run(['cc', '-o', str(binary), str(base / 'stubborn.c')], check=True)
        config = str(base / 'Caddyfile')
        args = [str(binary), 'run', '--config', config]

        def owned(command, *extra):
            return shell('BINARY="$1"; CONFIG="$2"; shift 2; ' + command, str(binary), config, *extra)

        # A container's copy shows the same path and argv in /proc.
        contained = subprocess.Popen(['unshare', '-m', '--propagation', 'private', *args])
        stubborn = subprocess.Popen(args)
        try:
            time.sleep(0.3)
            assert owned('is_standalone_server "$1"', str(contained.pid)).returncode != 0
            assert owned('is_standalone_server "$1"', str(stubborn.pid)).returncode == 0
            result = owned('stop_standalone_servers && echo "stopped=$STANDALONE_STOPPED"')
            assert 'Sent KILL' in result.stdout and 'stopped=1' in result.stdout, result.stdout + result.stderr
            assert stubborn.wait(timeout=5) is not None
            assert contained.poll() is None, 'a process in another mount namespace must never be signalled'
        finally:
            for process in (contained, stubborn):
                if process.poll() is None:
                    process.kill()
                    process.wait()
        print('PASS: a namespaced copy is never signalled; a TERM-ignoring instance is KILLed after the grace period')

        # The real port checker accepts an identified instance's TCP and UDP
        # 443 sockets as takeover targets and labels them in its report. The
        # binary is then replaced, so its /proc exe shows "(deleted)".
        subprocess.run(['cc', '-o', str(binary), str(base / 'bind.c')], check=True)
        server = subprocess.Popen(args)
        try:
            time.sleep(0.3)
            assert server.poll() is None, 'port 443 must be free for this test'
            replacement = base / 'replacement'
            replacement.write_bytes(binary.read_bytes())
            binary.unlink()
            replacement.rename(binary)
            assert os.readlink(f'/proc/{server.pid}/exe').endswith(' (deleted)')
            command = ('init_paths; BINARY="$1"; CONFIG="$2"; BUILD_DIR="$3"; '
                       'systemctl() { case "$*" in *ControlGroup*|*" Id "*) echo;; *) return 3;; esac; }; ')
            result = shell(command + 'check_port_owners allow-managed && echo accepted', str(binary), config, directory)
            assert 'accepted' in result.stdout, result.stdout + result.stderr
            result = shell(command + 'check_port_owners require-free', str(binary), config, directory)
            assert result.returncode != 0 and result.stderr.count('[takeover target]') == 2, result.stderr
        finally:
            server.kill()
            server.wait()
        print('PASS: identified instances (also with a replaced binary) are takeover targets in the real port check')
else:
    raise SystemExit('these process and port checks require root in a disposable environment')

#!/usr/bin/env bash
# Past installer mistakes and rules that must not be reintroduced:
# - Use Debian >= 12 and Ubuntu >= 24.04, not a frozen release allowlist.
# - DNS-01 validates TXT records. Do not require A/AAAA records, query them as
#   an installation prerequisite, or compare them with an outbound-IP service.
#   A domain without A/AAAA is valid for DNS-01 certificate issuance.
# - A running same-name service and existing/partial files are takeover/repair
#   cases. The script prepares, stops, replaces, starts and enables the service;
#   the operator must not have to disable it before running this installer.
# - Inspect TCP/443 and UDP/443 separately, even while this service is active.
#   Process names alone do not prove ownership. Report every conflicting PID,
#   executable and unit; never stop an external owner to make the port free.
# - Missing state files and installer markers must not force manual cleanup.
#   Replace only owned paths; never follow destination links into other data.
# - Preserve cached certificates/account state when replacing the executable.
# - Remove stale same-name masks/drop-ins and verify running + boot enablement;
#   copying a unit or calling enable alone does not prove the new process runs.
# - Keep a dedicated non-root identity and only required capabilities. An
#   existing unsafe account needs repair; a writable home allows key planting.
# - Generate 22-character mixed-class passwords and export matching credentials.
#   This installer uses laptop; a stale macbook login is a different account.
# - CPUAccounting= is obsolete on newer systemd; CPUWeight controls scheduling.
# - First certificate issuance is asynchronous. Retry trusted local HTTPS;
#   an early TLS alert is not the final result. Check locally with explicit
#   address + domain SNI instead of depending on public A/AAAA propagation.
# - Stage and validate before replacement, retain private rollback copies,
#   report recovery failures and leave unrelated services/firewall data alone.
# - Set both TMPDIR and GOTMPDIR to private build staging. GOTMPDIR alone does
#   not stop Go from ignoring go.mod when the checkout is directly in /tmp.
# - Check shared parent ownership before following installation paths. Publish
#   client exports through a unique temporary file; a fixed .new directory can
#   make install/mv publish a directory instead of the promised client file.
# - Respect the process's cgroup memory ancestry, not just the cgroup mount root.
# Interactive native-architecture Caddy MASQUE setup with Cloudflare DNS-01.
# Run from an authenticated, complete checkout:
#   sudo bash setup-interactive-caddy-masque-autoarch-cloudflare-dns.sh
# Supports Debian 12+ and Ubuntu 24.04+ on Linux amd64/arm64.
# Runtime files are installed outside the checkout.
# Caddy obtains and renews its certificate using the bundled Cloudflare module.
# Re-running replaces managed configuration and credentials, and preserves
# Caddy's certificate storage. The script stops and replaces its own service.
# A private Rust masque-client TOML file is exported after successful startup.
set +x
set +v
set +a
# Caller-exported names keep their export attribute even with allexport off.
# Keep the optional CF_API_TOKEN input until main consumes it, but never let
# subsequent assignments of generated secrets inherit an export attribute.
export -n account hash password token supplied_cf_token cf_token

usage() {
    cat <<'EOF'
Usage: sudo bash setup-interactive-caddy-masque-autoarch-cloudflare-dns.sh

Interactively build and install a native Linux amd64/arm64 MASQUE server
with the bundled caddy-dns/cloudflare plugin, configure DNS-01 issuance
and automatic renewal in Caddy, and start the hardened systemd service
under the dedicated non-login caddy-masque account with network capabilities.
A private filesystem view exposes managed configuration/site/state and required
TLS, DNS and runtime files under /etc, /run and /var. Execution is limited to
Caddy, ip/nft and trusted OS library directories.
Custom paths need root-maintained systemd bind/execute overrides.
For blocked custom paths, adjust InaccessiblePaths as well.
Restart the service after host resolver/hosts files are atomically replaced.
Memory normally uses at most half visible RAM (max 1 GiB); small hosts may use
up to 75% to keep the service usable. The service has no swap allowance,
and at most 512 tasks. Excess memory can restart the service. Inspect limits
with systemctl show caddy-masque; adjust them with systemctl edit if needed.
Caddy still reads its server keys/token and retains host CAP_NET_ADMIN, which
can change host networking. Abstract Unix sockets also remain in the host network.

Required: Debian 12+ or Ubuntu 24.04+, root, systemd, TUN and Internet.
Have a domain at Cloudflare and a CF_API_TOKEN scoped to that zone
with Zone:DNS:Edit and Zone:Zone:Read. The token is entered without echo and
stored root-owned and service-group-readable (0640) for renewal; it is never
a command argument. Client passwords remain root-only (0600).
TCP/UDP 443 must reach this server. DNS-01 does not require inbound port 80.
Only domain and token are requested. The script selects an IPv4-only tunnel
pool automatically; client LANs must not overlap the reported pool.

This installs packages and writes /usr/local/bin/caddy-masque, /etc/caddy-masque,
/var/lib/caddy-masque, /var/lib/caddy-masque-config, /var/log/caddy-masque,
/var/www/caddy-masque, a systemd unit and private client credentials.
The generated masque-client.toml uses Rust's Linux system mode (full VPN).
Reruns replace managed files and rotate the client password. Existing Caddy
certificate state is retained. DNS-01 validates TXT records; no A/AAAA records
or external public-IP lookup is required by this installer.
Reuse preserves this installer's dedicated Caddy storage. Generic /var/lib/caddy
state and arbitrary external PEM files are not automatically imported.
It preserves the checkout. Run --help without root for this information.
EOF
}

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nError: %s\n' "$*" >&2; exit 1; }
ask() {
    local reply
    printf '%s' "$2" >&2
    IFS= read -r reply || die "input ended; no answer was supplied"
    printf -v "$1" '%s' "$reply"
}

detect_arch() {
    case "$1" in
        x86_64 | amd64) printf 'amd64\n' ;;
        aarch64 | arm64) printf 'arm64\n' ;;
        *) return 1 ;;
    esac
}

# Gate on minimum releases, not a frozen list that rejects newer systems.
# dpkg compares numeric components correctly, including 24.10 and future LTS
# releases. Keep distro identity and runtime capability checks separate.
supported_platform() {
    local minimum version=${2:-}
    case ${1:-} in
        debian) minimum=12 ;;
        ubuntu) minimum=24.04 ;;
        *) return 1 ;;
    esac
    [[ $version =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 1
    dpkg --compare-versions "$version" ge "$minimum"
}

valid_domain() {
    local label
    local -a labels
    [[ ${#1} -le 253 && $1 == *.* && $1 =~ ^[a-z0-9.-]+$ && $1 =~ [a-z]$ ]] || return 1
    IFS=. read -r -a labels <<<"$1"
    for label in "${labels[@]}"; do
        [[ ${#label} -ge 1 && ${#label} -le 63 && $label =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}

valid_token() { [[ $1 =~ ^[A-Za-z0-9_-]{35,50}$ || $1 =~ ^cf(ut|at)_[A-Za-z0-9_-]{32,256}$ ]]; }

init_paths() {
    SRC=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    BINARY=/usr/local/bin/caddy-masque
    STATE=/etc/caddy-masque
    CONFIG="$STATE/Caddyfile"
    TOKEN_FILE="$STATE/cloudflare-token"
    CREDENTIALS="$STATE/client-credentials.txt"
    CLIENT_CONFIG="$STATE/masque-client.toml"
    RUNTIME_VIEW="$STATE/.systemd-run-view"
    SITE=/var/www/caddy-masque
    GO_INSTALL_ROOT=/opt/caddy-masque
    BUILD_CACHE=/var/cache/caddy-masque
    UNIT_DIR=/etc/systemd/system
    SERVICE=caddy-masque.service
    LOCK_DIR=/run/caddy-masque-setup
    BUILD_DIR=''
    GO_STAGE=''
    INSTALLING=''
    SWAP=''
    WAS_ACTIVE=0
    WAS_ENABLE_STATE=disabled
    ENABLE_TOUCHED=0
    STATE_METADATA=''
    STATE_ENTRY_SAVED=0
    HAD_DEPLOYMENT=0
}

managed_directory() {
    local path=$1 mode=$2 owner=$3 group=$4
    check_parent_dirs "$path"
    if [[ -L $path || ( -e $path && ! -d $path ) ]]; then rm -f -- "$path"; fi
    install -d -o "$owner" -g "$group" -m "$mode" -- "$path"
}

# Publish by rename, never truncate a running ELF or follow an old link.
replace_file() {
    local source=$1 destination=$2 mode=$3 owner=$4 group=$5 temporary
    check_parent_dirs "$destination"
    temporary=$(mktemp "${destination}.install.XXXXXXXX")
    install -o "$owner" -g "$group" -m "$mode" -- "$source" "$temporary"
    if [[ -d $destination && ! -L $destination ]]; then rm -rf --one-file-system -- "$destination"; fi
    mv -fT -- "$temporary" "$destination"
}

# Root-owned leaves are not sufficient when a writable ancestor can rename
# them. Inspect lexical and resolved ancestors; never chmod shared directories.
# Dedicated bad leaves remain replaceable after the old service has stopped.
check_parent_dirs() {
    local path=$1 parent resolved owner mode
    [[ $path == /* ]] || die 'installation paths must be absolute'
    parent=${path%/*}; [[ -n $parent ]] || parent=/
    resolved=$(readlink -m -- "$parent") || die "cannot resolve parent of $path"
    for parent in "$parent" "$resolved"; do
        while :; do
            if [[ -e $parent || -L $parent ]]; then
                [[ -d $parent ]] || die "installation parent is not a directory: $parent"
                read -r owner mode < <(stat -Lc '%u %a' -- "$parent") || die "cannot inspect installation parent: $parent"
                if [[ $owner != 0 || ! $mode =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 0022) != 0 )); then
                    die "installation parent must be root-owned and not writable by other accounts: $parent"
                fi
            fi
            [[ $parent != / ]] || break
            parent=${parent%/*}; [[ -n $parent ]] || parent=/
        done
    done
}

prepare_build_directory() {
    local path=$1 owner mode unsafe
    check_parent_dirs "$path"
    if [[ -L $path || ( -e $path && ! -d $path ) ]]; then
        rm -rf --one-file-system -- "$path"
    elif [[ -d $path ]]; then
        read -r owner mode < <(stat -Lc '%u %a' -- "$path") || die "cannot inspect build directory: $path"
        unsafe=$(find -P "$path" -xdev \( -type l -o ! -uid 0 -o -perm /022 \) -print -quit) ||
            die "cannot inspect the existing build directory safely: $path"
        if [[ $owner != 0 || ! $mode =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 0022) != 0 )) ||
            [[ -n $unsafe ]]; then
            # Never adopt compilers or caches previously writable by others.
            rm -rf --one-file-system -- "$path"
        fi
    fi
    install -d -o root -g root -m 0700 -- "$path"
}

# A complete checkout may itself live under an installer's normal build root,
# or contain that root. Never purge or adopt any overlapping source directory.
# Resolve links too; the fallback is freshly created inside this run's private
# staging tree and disappears at cleanup, leaving the checkout unchanged.
build_path_overlaps_source() {
    local path source
    path=$(readlink -m -- "$1") || die 'cannot resolve a build path'
    source=$(readlink -m -- "$SRC") || die 'cannot resolve the source checkout'
    [[ $path == "$source" || $path == "${source%/}/"* || $source == "${path%/}/"* ]]
}

# Cover/home/runtime-view trees and bad dedicated file-name collisions are
# replaced destructively. A checkout stored inside one cannot be preserved by
# installation; neither may a checkout containing such a reserved tree. Reject
# that placement before locks, packages or replacement.
# Resolve only parents: deleting a bad leaf symlink does not delete its target.
check_source_placement() {
    local path parent reserved source
    source=$(readlink -m -- "$SRC") || die 'cannot resolve the source checkout'
    while IFS= read -r path; do
        parent=$(readlink -m -- "${path%/*}") || die 'cannot resolve a reserved installation path'
        reserved="${parent%/}/${path##*/}"
        if [[ $source == "$reserved" || $source == "$reserved/"* || $reserved == "${source%/}/"* ]]; then
            die "source checkout overlaps a replaceable deployment path: $path"
        fi
    done < <(transaction_paths; service_override_paths; printf '%s\n' "$STATE/.home" "$RUNTIME_VIEW")
}

service_override_paths() {
    printf '%s\n' "$UNIT_DIR/$SERVICE.d" "/run/systemd/system/$SERVICE" "/run/systemd/system/$SERVICE.d" \
        "$UNIT_DIR/multi-user.target.wants/$SERVICE" "/run/systemd/system/multi-user.target.wants/$SERVICE"
}

acquire_lock() {
    local lock="$LOCK_DIR/install.lock" owner
    owner=$(id -u)
    [[ ! -L $LOCK_DIR ]] || die "the installer runtime directory must not be a symlink"
    if [[ -e $LOCK_DIR ]]; then
        [[ -d $LOCK_DIR && $(stat -c %u -- "$LOCK_DIR") == "$owner" ]] ||
            die "the installer runtime directory has an unexpected owner or type"
    else
        mkdir -m 0700 -- "$LOCK_DIR"
    fi
    chmod 0700 -- "$LOCK_DIR"
    [[ ! -L $lock ]] || die "the installer lock must not be a symlink"
    if [[ -e $lock ]]; then
        [[ -f $lock && $(stat -c %u:%h -- "$lock") == "$owner:1" ]] ||
            die "the installer lock has an unexpected owner, type or link count"
    fi
    exec 9>>"$lock"
    flock -n 9 || die "another instance of this installer is running"
}

transaction_paths() {
    printf '%s\n' "$BINARY" "$CONFIG" "$TOKEN_FILE" "$CLIENT_CONFIG" \
        "$CREDENTIALS" "$STATE/domain" "$UNIT_DIR/$SERVICE" "$SITE"
    printf '%s\n' /etc/modules-load.d/caddy-masque.conf
}

preflight() {
    local path systemd_version
    [[ $(id -u) == 0 ]] || die "run with sudo bash $0"
    [[ $(uname -s) == Linux ]] || die "only Linux is supported"
    ARCH=$(detect_arch "$(uname -m)") || die "unsupported architecture: $(uname -m); use amd64 or arm64"
    # shellcheck disable=SC1091
    . /etc/os-release
    supported_platform "${ID:-}" "${VERSION_ID:-}" ||
        die "supported systems: Debian 12+ and Ubuntu 24.04+ (found ${ID:-unknown} ${VERSION_ID:-unknown})"
    [[ -f $SRC/go.mod && -d $SRC/third_party/xnet && -d $SRC/third_party/quic-go &&
        -f $SRC/deploy/caddy-masque.service ]] ||
        die "keep this script at the root of the complete caddy-masque checkout"
    check_source_placement
    [[ -d /run/systemd/system ]] || die "systemd must be running as the system service manager"
    systemd_version=$(systemctl --version | awk 'NR == 1 {print $2}')
    if [[ ! $systemd_version =~ ^[0-9]+$ ]] || (( 10#$systemd_version < 249 )); then
        die 'systemd 249+ is required for the generated service sandbox'
    fi
    for path in "$BINARY" "$STATE" "$SITE" "$UNIT_DIR/$SERVICE" "$LOCK_DIR" "$GO_INSTALL_ROOT" "$BUILD_CACHE" \
        /var/lib/caddy-masque /var/lib/caddy-masque-config /var/log/caddy-masque /run/caddy-masque /etc/modules-load.d/caddy-masque.conf; do
        check_parent_dirs "$path"
    done
    command -v flock >/dev/null || die "install util-linux (flock) first"
    acquire_lock
    if [[ ! -c /dev/net/tun ]]; then modprobe tun 2>/dev/null || true; fi
    [[ -c /dev/net/tun ]] || die "enable TUN/TAP in your VPS provider's panel; /dev/net/tun is missing"
    [[ -w /proc/sys/net/ipv4/ip_forward ]] || die "the host must allow network sysctl changes (not a restricted container)"
}

collect_settings() {
    local value saved_domain=
    # Saved state is only a prompt default. Missing metadata, an old marker or
    # a new domain must not prevent authoritative replacement of this service.
    if [[ -d $STATE && ! -L $STATE && -f $STATE/domain && ! -L $STATE/domain ]]; then
        saved_domain=$(cat "$STATE/domain")
        valid_domain "$saved_domain" || saved_domain=''
    fi
    while :; do
        ask value "Server domain${saved_domain:+ [$saved_domain]}: "
        DOMAIN=${value,,}
        DOMAIN=${DOMAIN:-$saved_domain}
        valid_domain "$DOMAIN" && break
        printf 'Enter one DNS hostname, without a URL, port or wildcard.\n' >&2
    done
    USER_NAME=laptop
}

install_packages() {
    say "Installing build and network dependencies"
    DEBIAN_FRONTEND=noninteractive apt-get update -q </dev/null
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y -q --no-install-recommends \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold curl ca-certificates nftables iproute2 dnsutils jq \
        python3 util-linux </dev/null
}

# A same-name symlink can resolve to an unrelated systemd unit. Never accept
# that target's cgroup as ownership proof or stop it under this service's name.
# An entirely inactive alias can be replaced as a dedicated pathname collision.
check_service_identity() {
    local canonical state group pid
    canonical=$(systemctl show -p Id --value "$SERVICE" 2>/dev/null || true)
    if [[ -n $canonical && $canonical != "$SERVICE" ]]; then
        state=$(systemctl show -p ActiveState --value "$SERVICE" 2>/dev/null || true)
        group=$(systemctl show -p ControlGroup --value "$SERVICE" 2>/dev/null || true)
        pid=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)
        if [[ ( $state != inactive && $state != failed ) || -n $group || ( -n $pid && $pid != 0 ) ]]; then
            printf 'Refusing alias %q -> %q (state=%q PID=%q cgroup=%q); unrelated unit was not stopped.\n' \
                "$SERVICE" "$canonical" "$state" "$pid" "$group" >&2
            return 1
        fi
    fi
}

check_port_owners() {
    local mode=${1:-allow-managed} expected_group tcp_status=0 udp_status=0
    check_service_identity || return 1
    expected_group=$(systemctl show -p ControlGroup --value "$SERVICE" 2>/dev/null || true)
    # Query both protocols before deciding. -a also catches connected UDP
    # sockets bound to 443, which a listener-only UDP query would omit.
    ss -H -O -ltnp 'sport = :443' >"$BUILD_DIR/port-tcp" 2>"$BUILD_DIR/port-tcp-error" || tcp_status=$?
    ss -H -O -uanp 'sport = :443' >"$BUILD_DIR/port-udp" 2>"$BUILD_DIR/port-udp-error" || udp_status=$?
    python3 - "$SERVICE" "$expected_group" "$mode" "$BUILD_DIR" "$tcp_status" "$udp_status" <<'PY'
import json, os, re, sys
from pathlib import Path

service, expected, mode, directory, tcp_status, udp_status = sys.argv[1:]
directory = Path(directory)
proc = Path('/proc')
expected = expected.rstrip('/')
managed_group = bool(expected and expected.startswith('/'))
rows = []
errors = []

def quote(value):
    # Process names and paths are not trusted terminal text. Do not print
    # command arguments, which may contain another service's credentials.
    return json.dumps(value, ensure_ascii=True)

def owner(pid):
    base = proc / str(pid)
    try:
        name = (base / 'comm').read_text(errors='replace').rstrip('\n')
    except OSError:
        name = '(unavailable)'
    try:
        executable = os.readlink(base / 'exe')
    except OSError:
        executable = '(unavailable)'
    group = ''
    try:
        entries = [line.split(':', 2) for line in (base / 'cgroup').read_text(errors='replace').splitlines()]
        # On v1 use the systemd hierarchy, not a separately delegated CPU or
        # memory hierarchy that happens to have a similar directory name.
        group = next((p for n, c, p in entries if n == '0' and not c), '')
        if not group:
            group = next((p for _, c, p in entries if 'name=systemd' in c.split(',')), '')
    except (OSError, ValueError):
        pass
    units = [part for part in group.split('/') if part.endswith(('.service', '.scope', '.socket'))]
    unit = units[-1] if units else '(unavailable)'
    ours = managed_group and (group == expected or group.startswith(expected + '/'))
    return pid, name, executable, unit, group, ours

if mode not in ('allow-managed', 'require-free'):
    raise SystemExit('Invalid port-ownership inspection mode.')
for protocol, filename, status in [('TCP', 'tcp', tcp_status), ('UDP', 'udp', udp_status)]:
    try:
        output = (directory / ('port-' + filename)).read_text(errors='replace')
        if status != '0':
            detail = (directory / ('port-' + filename + '-error')).read_text(errors='replace').strip()
            errors.append(protocol + '/443 inspection failed: ' + quote(detail))
    except OSError as exc:
        errors.append(protocol + '/443 inspection failed: ' + quote(str(exc)))
        continue
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if fields[0] in ('tcp', 'tcp6', 'udp', 'udp6'):
            fields = fields[1:]
        state = fields[0] if fields else '(unknown)'
        address = fields[3] if len(fields) >= 5 else '(unavailable)'
        owners = [owner(pid) for pid in sorted({int(p) for p in re.findall(r'\bpid=(\d+)', line)})]
        conflict = mode == 'require-free' or not owners or not all(item[-1] for item in owners) or len(fields) < 5
        rows.append((protocol, state, address, owners, line, conflict))

if errors or any(row[-1] for row in rows):
    print('Port 443 ownership check failed; no external owner was stopped:', file=sys.stderr)
    for error in errors:
        print('  ' + error, file=sys.stderr)
    for protocol in ('TCP', 'UDP'):
        entries = [row for row in rows if row[0] == protocol]
        if not entries:
            state = 'inspection unavailable' if any(e.startswith(protocol + '/') for e in errors) else 'free'
            print('  ' + protocol + '/443: ' + state, file=sys.stderr)
        for _, state, address, owners, raw, conflict in entries:
            print('  ' + protocol + '/443 state=' + quote(state) + ' local=' + quote(address), file=sys.stderr)
            if not owners:
                print('    PID/name/unit unavailable; ownership cannot be verified. ss=' + quote(raw), file=sys.stderr)
            for pid, name, executable, unit, group, ours in owners:
                print(f'    PID={pid} name={quote(name)} executable={quote(executable)} unit={quote(unit)} '
                      + 'cgroup=' + quote(group or '(unavailable)')
                      + (' [managed service]' if ours else ' [external or unidentified]'), file=sys.stderr)
    raise SystemExit(1)
PY
}

check_ports() {
    check_service_identity || die 'the service name resolves to another live systemd unit'
    systemctl is-active --quiet "$SERVICE" && WAS_ACTIVE=1
    WAS_ENABLE_STATE=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)
    WAS_ENABLE_STATE=${WAS_ENABLE_STATE:-disabled}
    if (( WAS_ACTIVE )) || [[ -e $BINARY || -L $BINARY || -e $UNIT_DIR/$SERVICE || -L $UNIT_DIR/$SERVICE || -d $STATE ]]; then HAD_DEPLOYMENT=1; fi
    check_port_owners allow-managed || die 'TCP/UDP 443 is not exclusively free or owned by this caddy-masque service.'
    if ip link show masque0 >/dev/null 2>&1; then
        check_tunnel_owners || die 'masque0 has a foreign or unverifiable process owner; its tunnel was not changed'
    fi
    # Another MASQUE service can share the default tunnel name even when it
    # listens elsewhere. Protect that actual resource conflict separately.
    if systemctl is-active --quiet masque-server.service && ip link show masque0 >/dev/null 2>&1; then
        die 'masque0 is in use by masque-server.service; its tunnel was not deleted.'
    fi
    if (( ! WAS_ACTIVE )); then
        if ip link show masque0 >/dev/null 2>&1; then
            (( HAD_DEPLOYMENT )) || die "masque0 belongs to an unknown deployment; it was not deleted"
        fi
    fi
    return 0
}

# A leftover config/binary does not authorize deleting another workload's live
# tunnel, even when that workload listens on a different port. Linux publishes
# TUN interface names in fdinfo; compare holders with this unit's actual cgroup.
# An unheld interface can still be this deployment's persistent crash leftover.
check_tunnel_owners() {
    local expected_group
    expected_group=$(systemctl show -p ControlGroup --value "$SERVICE" 2>/dev/null || true)
    python3 - "$expected_group" <<'PY'
import json, os, pathlib, sys
proc = pathlib.Path('/proc')
expected = sys.argv[1].rstrip('/')
conflicts = []
for directory in proc.iterdir():
    if not directory.name.isascii() or not directory.name.isdecimal():
        continue
    try:
        for entry in (directory / 'fdinfo').iterdir():
            try:
                fields = entry.read_text(errors='replace').splitlines()
            except FileNotFoundError:
                continue
            if not any(line.split() == ['iff:', 'masque0'] for line in fields):
                continue
            groups = [line.split(':', 2) for line in (directory / 'cgroup').read_text().splitlines()]
            group = next((p for n, c, p in groups if n == '0' and not c), '')
            if not group:
                group = next((p for _, c, p in groups if 'name=systemd' in c.split(',')), '')
            if expected and (group == expected or group.startswith(expected + '/')):
                continue
            try:
                executable = os.readlink(directory / 'exe')
            except OSError:
                executable = '(unavailable)'
            conflicts.append('PID=' + directory.name + ' executable=' + json.dumps(executable) + ' cgroup=' + json.dumps(group))
    except FileNotFoundError:
        continue  # A process exited, or this kernel task has no descriptor table.
    except (OSError, ValueError):
        conflicts.append('PID=' + directory.name + ': cannot verify TUN ownership')
if conflicts:
    print('masque0 ownership check failed; no foreign process was stopped:', file=sys.stderr)
    print('\n'.join('  ' + item for item in conflicts), file=sys.stderr)
    sys.exit(1)
PY
}

check_pool() {
    ip -j -4 route show table all >"$BUILD_DIR/routes.json"
    python3 - "$1" "$BUILD_DIR/routes.json" "$HAD_DEPLOYMENT" <<'PY'
import ipaddress, json, sys
try:
    pool = ipaddress.ip_interface(sys.argv[1])
    private = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if pool.version != 4 or not 16 <= pool.network.prefixlen <= 30 or not any(pool.network.subnet_of(n) for n in private):
        raise ValueError('use an RFC1918 IPv4 pool with prefix /16 through /30')
    if pool.ip in (pool.network.network_address, pool.network.broadcast_address):
        raise ValueError('the server address must be a usable host address')
    for route in json.load(open(sys.argv[2])):
        if sys.argv[3] == '1' and route.get('dev') == 'masque0':
            continue
        dst = route.get('dst', 'default')
        if dst == 'default':
            continue
        net = ipaddress.ip_network(dst, strict=False)
        if net.prefixlen and pool.network.overlaps(net):
            raise ValueError('pool overlaps an existing host route: ' + dst)
except (ValueError, OSError) as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
PY
}

collect_pool() {
    # Prefer the documented pool, then try alternatives if the host uses it.
    # Remote client LANs cannot be discovered here; report the selected pool.
    local candidate
    for candidate in 10.89.0.1/24 10.90.0.1/24 10.91.0.1/24 172.29.89.1/24 192.168.89.1/24; do
        if check_pool "$candidate" 2>"$BUILD_DIR/pool-check.log"; then
            IPV4=$candidate
            say "Selected IPv4 tunnel pool: $IPV4"
            return 0
        fi
    done
    die "all default tunnel pools overlap host routes; use the documented manual deployment with a suitable pool"
}

cleanup_swap() {
    [[ -n $SWAP ]] || return 0
    if swapon --show=NAME --noheadings | grep -Fx -- "$SWAP" >/dev/null; then
        if ! swapoff "$SWAP"; then
            printf 'Temporary swap remains at %s; remove it after reboot.\n' "$SWAP" >&2
            SWAP=
            return 0
        fi
    fi
    rm -f -- "$SWAP"
    SWAP=
}

build_server() {
    local releases go_line go_version go_file go_sha go_root mem_kb swap_kb free_kb info private_tools=0 private_cache=0
    # Apply before even `go version`: inherited toolchain selectors and cache
    # programs must not execute an unrelated helper as root. Proxy/CA settings
    # remain inherited; the actual compile additionally fixes native CPU flags.
    local -x GOTOOLCHAIN=local GOENV=off GOWORK=off GOROOT='' GO111MODULE=on GOAUTH=off
    local -x GOFLAGS='' GOCACHEPROG='' GOEXPERIMENT='' GOFIPS140='' GODEBUG=''
    say "Building the native linux/$ARCH server from this checkout"
    go_line=$(sed -n 's/^go \([0-9]*\.[0-9]*\)\.[0-9]*$/\1/p' "$SRC/go.mod")
    [[ -n $go_line ]] || die "cannot read the Go release line from go.mod"
    # Keep a separate toolchain and caches; never replace the system's Go.
    if build_path_overlaps_source "$GO_INSTALL_ROOT"; then
        GO_INSTALL_ROOT="$BUILD_DIR/toolchains"
        private_tools=1
    fi
    if build_path_overlaps_source "$BUILD_CACHE"; then
        BUILD_CACHE="$BUILD_DIR/build-cache"
        private_cache=1
    fi
    if (( private_tools || private_cache )); then
        [[ -d $BUILD_DIR && ! -L $BUILD_DIR && $(stat -c '%u:%a' -- "$BUILD_DIR") == 0:700 ]] ||
            die 'overlapping source paths require private root-owned build staging'
        say 'Source overlaps persistent build storage; using private staging for the overlapping paths'
    fi
    if (( private_tools )); then
        [[ ! -e $GO_INSTALL_ROOT && ! -L $GO_INSTALL_ROOT ]] || die 'private toolchain staging already exists'
        install -d -o root -g root -m 0700 -- "$GO_INSTALL_ROOT"
    else
        prepare_build_directory "$GO_INSTALL_ROOT"
    fi
    if (( private_cache )); then
        [[ ! -e $BUILD_CACHE && ! -L $BUILD_CACHE ]] || die 'private cache staging already exists'
        install -d -o root -g root -m 0700 -- "$BUILD_CACHE"
    else
        prepare_build_directory "$BUILD_CACHE"
    fi
    free_kb=$(df -Pk "$BUILD_CACHE" | awk 'NR==2 {print $4}')
    [[ $free_kb -ge 5242880 ]] || die "free at least 5 GiB for the toolchain and build caches"
    free_kb=$(df -Pk "$BUILD_DIR" | awk 'NR==2 {print $4}')
    [[ $free_kb -ge 3145728 ]] || die "free at least 3 GiB in /var/tmp for build staging and possible swap"
    releases="$BUILD_DIR/go-releases.json"
    curl --disable --proto '=https' --proto-redir '=https' -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 --max-time 90 \
        'https://go.dev/dl/?mode=json&include=all' -o "$releases"
    go_version=$(jq -r --arg line "go$go_line." 'first(.[] | select(.stable and (.version | startswith($line))) | .version) // empty' "$releases")
    [[ $go_version =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no stable Go $go_line patch release was found"
    go_file="$go_version.linux-$ARCH.tar.gz"
    go_sha=$(jq -r --arg file "$go_file" 'first(.[].files[] | select(.filename == $file) | .sha256) // empty' "$releases")
    [[ $go_sha =~ ^[0-9a-f]{64}$ ]] || die "missing official Go archive checksum"
    go_root="$GO_INSTALL_ROOT/$go_version-$ARCH"
    if [[ -L $go_root || ! -x $go_root/bin/go || ! -x $go_root/pkg/tool/linux_$ARCH/compile || ! -f $go_root/src/runtime/runtime2.go ||
        ! -f $go_root/.caddy-masque-toolchain.sha256 ]] ||
        [[ $(cat "$go_root/.caddy-masque-toolchain.sha256" 2>/dev/null) != "$go_sha" ]] ||
        ! "$go_root/bin/go" version >"$BUILD_DIR/go-version.txt" 2>&1 ||
        ! grep -Fq -- "$go_version linux/$ARCH" "$BUILD_DIR/go-version.txt"; then
        curl --disable --proto '=https' --proto-redir '=https' -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 --max-time 600 \
            "https://go.dev/dl/$go_file" -o "$BUILD_DIR/go.tar.gz"
        printf '%s  %s\n' "$go_sha" "$BUILD_DIR/go.tar.gz" | sha256sum -c --quiet - || die "Go archive checksum mismatch"
        # Publish the complete toolchain using a rename on its own filesystem.
        GO_STAGE=$(mktemp -d "$GO_INSTALL_ROOT/.toolchain-XXXXXX")
        tar -xzf "$BUILD_DIR/go.tar.gz" -C "$GO_STAGE"
        "$GO_STAGE/go/bin/go" version >"$BUILD_DIR/go-version.txt"
        grep -Fq -- "$go_version linux/$ARCH" "$BUILD_DIR/go-version.txt" || die "unexpected downloaded Go version"
        printf '%s\n' "$go_sha" >"$GO_STAGE/go/.caddy-masque-toolchain.sha256"
        if [[ -e $go_root || -L $go_root ]]; then mv -T -- "$go_root" "$GO_STAGE/previous"; fi
        mv -- "$GO_STAGE/go" "$go_root"
        rm -rf -- "$GO_STAGE"
        GO_STAGE=''
    fi
    "$go_root/bin/go" version
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
    if (( mem_kb + swap_kb < 2500000 )); then
        say "Adding 2 GiB of temporary swap for compilation"
        SWAP=$(mktemp /var/tmp/caddy-masque-build-XXXXXX.swap)
        chmod 600 "$SWAP"
        fallocate -l 2G "$SWAP" || dd if=/dev/zero of="$SWAP" bs=1M count=2048 status=none
        mkswap -q "$SWAP"
        swapon "$SWAP" || die "cannot enable temporary swap; add memory/swap and run again"
    fi
    mkdir -m 0700 -- "$BUILD_DIR/go-tmp"
    # Go uses TMPDIR to identify the system temp root and ignores go.mod there.
    # GOTMPDIR only moves compiler scratch files; set both so /tmp checkouts
    # remain valid modules without moving or changing the user's source tree.
    if ! (cd -- "$SRC" && env -u GOFLAGS -u GOOS -u GOARCH -u GOROOT -u GOWORK \
        -u GOCACHEPROG -u GOEXPERIMENT -u GOFIPS140 -u GODEBUG \
        GOOS=linux GOARCH="$ARCH" GOAMD64=v1 GOARM64=v8.0 GO111MODULE=on \
        CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOENV=off \
        TMPDIR="$BUILD_DIR/go-tmp" GOTMPDIR="$BUILD_DIR/go-tmp" \
        GOCACHE="$BUILD_CACHE/build" GOMODCACHE="$BUILD_CACHE/mod" \
        "$go_root/bin/go" build -p 1 -mod=readonly -trimpath -ldflags '-s -w' -o "$BUILD_DIR/caddy-masque" ./cmd/caddy); then
        die "build failed; the installed binary was not replaced. Check disk/memory and access to proxy.golang.org"
    fi
    cleanup_swap
    "$BUILD_DIR/caddy-masque" list-modules >"$BUILD_DIR/modules.txt"
    local module
    for module in masque http.handlers.masque dns.providers.cloudflare; do
        grep -Fxq -- "$module" "$BUILD_DIR/modules.txt" || die "built server is missing $module; installation stopped"
    done
    info=$("$go_root/bin/go" version -m "$BUILD_DIR/caddy-masque")
    check_build_replacement "$info" golang.org/x/net ./third_party/xnet || die 'built server is missing its patched HTTP/2 replacement'
    check_build_replacement "$info" github.com/quic-go/quic-go ./third_party/quic-go || die 'built server is missing its patched QUIC replacement'
    grep -Eq "^[[:space:]]*build[[:space:]]+GOARCH=$ARCH$" <<<"$info" || die 'built server has the wrong architecture'
    grep -Eq '^[[:space:]]*build[[:space:]]+CGO_ENABLED=0$' <<<"$info" || die 'built server unexpectedly requires CGO'
}

check_build_replacement() {
    awk -F '\t' -v module="$2" -v replacement="$3" '
        ($2 == "dep" || $2 == "mod") && $3 == module {pending=1; next}
        pending {if ($2 == "=>" && $3 == replacement) found=1; pending=0}
        END {exit !found}
    ' <<<"$1"
}

stage_token() {
    local token=${CF_API_TOKEN:-}
    say "Configuring Caddy Cloudflare DNS-01 issuance and renewal"
    if [[ -n $token ]]; then
        : # The shell-local inherited token skips the only token prompt.
    elif [[ -d $STATE && ! -L $STATE && -f $TOKEN_FILE && ! -L $TOKEN_FILE ]]; then
        printf 'CF_API_TOKEN (hidden; Enter keeps the saved token): ' >&2
    else
        printf 'CF_API_TOKEN (hidden; zone-scoped DNS Edit + Zone Read): ' >&2
    fi
    if [[ -z $token ]]; then
        IFS= read -r -s token || die "no Cloudflare token supplied"
        printf '\n' >&2
    fi
    if [[ -z $token && -d $STATE && ! -L $STATE && -f $TOKEN_FILE && ! -L $TOKEN_FILE ]]; then token=$(cat "$TOKEN_FILE"); fi
    valid_token "$token" || die "invalid Cloudflare API token format; use a token, not a global API key"
    printf '%s\n' "$token" >"$BUILD_DIR/cloudflare-token"
    chmod 0600 "$BUILD_DIR/cloudflare-token"
    unset token
}

stage_config() {
    # This installer is authoritative for its managed configuration. Regenerate
    # the account/export together, even when prior metadata is incomplete.
    local account hash password
        account=$("$BUILD_DIR/caddy-masque" masque-passwd --name "$USER_NAME")
        hash=$(awk '/^user / {print $3}' <<<"$account")
        password=$(awk '/^password = / {gsub(/"/, "", $3); print $3}' <<<"$account")
        [[ $hash == "\$argon2id\$"* && -n $password ]] || die "account generation failed"
        cat >"$BUILD_DIR/Caddyfile" <<EOF
# Managed by setup-interactive-caddy-masque-autoarch-cloudflare-dns.sh
# Caddy owns certificate issuance and renewal using Cloudflare DNS-01.
{
    # DNS-01 needs no HTTP listener; avoid taking over an unrelated port 80.
    auto_https disable_redirects
    masque {
        ipv4 $IPV4
        user $USER_NAME $hash
    }
}

# Catch-all authority supports clients connecting by IP with domain TLS SNI.
$DOMAIN, :443 {
    tls {
        dns cloudflare {file.$TOKEN_FILE}
    }
    masque
    root * $SITE
    file_server
}
EOF
        cat >"$BUILD_DIR/client-credentials.txt" <<EOF
Server domain: $DOMAIN
User name: $USER_NAME
Password: $password
Server password hash: $hash
URI template: https://$DOMAIN/.well-known/masque/ip/{target}/{ipproto}/
Transport: auto (h3, h2 or http/1.1); IPv6 in tunnel: disabled
EOF
    unset account hash password
    # Validate with the staged token, leaving the live token/config untouched.
    # Caddy's file placeholder resolves to the API token when config is loaded.
    python3 - "$BUILD_DIR/Caddyfile" "$BUILD_DIR/validate.Caddyfile" "$TOKEN_FILE" "$BUILD_DIR/cloudflare-token" <<'PYCODE'
import pathlib, sys
source, target, token_path, staged_path = sys.argv[1:]
text = pathlib.Path(source).read_text()
placeholder = '{file.' + token_path + '}'
if placeholder not in text:
    sys.exit('The managed Caddyfile must retain the Cloudflare token file placeholder.')
pathlib.Path(target).write_text(text.replace(placeholder, '{file.' + staged_path + '}'))
PYCODE
    # Provisioning does not start the TUN/network or obtain a certificate.
    if ! "$BUILD_DIR/caddy-masque" validate --config "$BUILD_DIR/validate.Caddyfile" --adapter caddyfile >"$BUILD_DIR/validation.log" 2>&1; then
        python3 - "$BUILD_DIR/validation.log" "$BUILD_DIR/cloudflare-token" <<'PYCODE'
import pathlib, sys
message = pathlib.Path(sys.argv[1]).read_text()
token = pathlib.Path(sys.argv[2]).read_text().strip()
print(message.replace(token, '[REDACTED]'), file=sys.stderr)
PYCODE
        die "Caddy configuration validation failed; the installed server was not changed"
    fi
}

runtime_memory_limits() {
    # Normally allow half visible RAM, at most 1 GiB. On small VPSs a 256 MiB
    # floor may use up to 75%; refuse a cap below 64 MiB instead of no limit.
    # Python integers avoid overflow on cgroup-v1's huge unlimited sentinel.
    python3 - <<'PY'
import pathlib
total = next(int(line.split()[1]) * 1024 for line in pathlib.Path('/proc/meminfo').read_text().splitlines()
             if line.startswith('MemTotal:'))
paths = [pathlib.Path('/sys/fs/cgroup/memory.max'),
         pathlib.Path('/sys/fs/cgroup/memory/memory.limit_in_bytes')]
for line in pathlib.Path('/proc/self/cgroup').read_text().splitlines():
    _, controllers, relative = line.split(':', 2)
    if not controllers or 'memory' in controllers.split(','):
        base = pathlib.Path('/sys/fs/cgroup') if not controllers else pathlib.Path('/sys/fs/cgroup/memory')
        directory = base / relative.lstrip('/')
        if '..' in directory.parts:
            continue
        filename = 'memory.max' if not controllers else 'memory.limit_in_bytes'
        while directory == base or base in directory.parents:
            paths.append(directory / filename)
            if directory == base:
                break
            directory = directory.parent
for path in set(paths):
    if path.exists():
        value = path.read_text().strip()
        if value != 'max':
            if not value.isascii() or not value.isdecimal():
                raise SystemExit('Cannot determine a safe cgroup memory limit.')
            total = min(total, int(value))
budget = total // (1024 * 1024)
maximum = min(1024, max(256, budget // 2), budget * 3 // 4)
if maximum < 64:
    raise SystemExit('Insufficient memory for the confined Caddy service.')
print(maximum, maximum * 3 // 4, maximum * 7 // 10)
PY
}

stage_service() {
    local ip_binary nft_binary memory_max memory_high go_limit
    ip_binary=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v ip) || die "iproute2 is required"
    nft_binary=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v nft) || die "nftables is required"
    ip_binary=$(readlink -e -- "$ip_binary")
    nft_binary=$(readlink -e -- "$nft_binary")
    read -r memory_max memory_high go_limit < <(runtime_memory_limits)
    # Keep this installer's paths separate from the manual deployment template.
    # Caddy appends /caddy to each XDG base directory.
    sed \
        -e "s|/usr/local/bin/caddy|$BINARY|g" \
        -e "s|/etc/caddy/Caddyfile|$CONFIG|g" \
        -e 's|/var/lib/caddy,|/var/lib/caddy-masque/caddy,|' \
        -e 's|/var/lib/caddy-config\.|/var/lib/caddy-masque-config/caddy.|' \
        -e 's|XDG_CONFIG_HOME=/var/lib/caddy-config|XDG_CONFIG_HOME=/var/lib/caddy-masque-config|' \
        -e 's|XDG_DATA_HOME=/var/lib |XDG_DATA_HOME=/var/lib/caddy-masque |' \
        -e 's|^StateDirectory=.*|StateDirectory=caddy-masque caddy-masque-config|' \
        -e 's|^LogsDirectory=.*|LogsDirectory=caddy-masque|' \
        "$SRC/deploy/caddy-masque.service" >"$BUILD_DIR/$SERVICE"
    cat >>"$BUILD_DIR/$SERVICE" <<EOF

# Installer-specific containment. Directory binds preserve atomic config/token
# replacements. TemporaryFileSystem also makes namespace setup fail closed.
[Service]
TemporaryFileSystem=/etc:ro,noexec /var:ro,noexec
# systemd 249's API-VFS /run mount overrides a tmpfs entry. A trusted directory
# bind has higher priority and preserves the intended private runtime view.
BindReadOnlyPaths=$RUNTIME_VIEW:/run
# Set noexec on the overlays themselves; same-path NoExecPaths would bind the
# host directories over them. Private tmpfs also bounds temporary disk usage.
PrivateTmp=no
TemporaryFileSystem=/tmp:rw,noexec,nosuid,nodev,mode=1777,size=64M /var/tmp:rw,noexec,nosuid,nodev,mode=1777,size=64M
TemporaryFileSystem=/dev/shm:rw,noexec,nosuid,nodev,mode=1777,size=16M
BindReadOnlyPaths=$STATE $SITE /etc/ssl
BindReadOnlyPaths=-/etc/resolv.conf -/etc/hosts -/etc/nsswitch.conf -/etc/passwd -/etc/group
BindReadOnlyPaths=-/etc/gai.conf -/etc/services -/etc/protocols -/etc/localtime -/etc/ld.so.cache
BindReadOnlyPaths=-/run/systemd/notify -/run/systemd/resolve -/run/resolvconf
BindPaths=/var/lib/caddy-masque /var/lib/caddy-masque-config /var/log/caddy-masque /run/caddy-masque
InaccessiblePaths=-/opt -/srv -/mnt -/media -/boot -/etc/ssl/private
InaccessiblePaths=-$CREDENTIALS -$CLIENT_CONFIG -$STATE/domain
NoExecPaths=/
# Bind mounts and private tmp/shm mounts need explicit noexec entries too.
NoExecPaths=/run $STATE $SITE
NoExecPaths=/var/lib/caddy-masque /var/lib/caddy-masque-config /var/log/caddy-masque /run/caddy-masque
NoExecPaths=/etc/ssl -/run/systemd/resolve -/run/resolvconf -/run/systemd/notify
NoExecPaths=-/etc/resolv.conf -/etc/hosts -/etc/nsswitch.conf -/etc/passwd -/etc/group
NoExecPaths=-/etc/gai.conf -/etc/services -/etc/protocols -/etc/localtime -/etc/ld.so.cache
ExecPaths=$BINARY $ip_binary $nft_binary -/usr/lib -/usr/lib64 -/lib -/lib64
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
# MDWE and noexec mounts alone do not block executable memfd payloads.
SystemCallFilter=~memfd_create
PrivateIPC=yes
RemoveIPC=yes
KeyringMode=private
LimitCORE=0
# CPUWeight enables the CPU controller; omit obsolete CPUAccounting=.
CPUWeight=50
MemoryAccounting=yes
MemoryHigh=${memory_high}M
MemoryMax=${memory_max}M
MemorySwapMax=0
Environment=GOMEMLIMIT=${go_limit}MiB
TasksAccounting=yes
TasksMax=512
OOMPolicy=kill
EOF
}

stage_client_config() {
    local record="$BUILD_DIR/client-credentials.txt"
    [[ -f $record ]] || die "saved client credentials are missing; cannot reconstruct the client password"
    python3 - "$record" "$BUILD_DIR/Caddyfile" "$BUILD_DIR/masque-client.toml" "$DOMAIN" <<'PY'
import json, pathlib, re, sys
record_path, config_path, output_path, domain = sys.argv[1:]
record = {}
for line in pathlib.Path(record_path).read_text().splitlines():
    key, sep, value = line.partition(': ')
    if sep:
        record[key] = value
user = record.get('User name', '')
password = record.get('Password', '')
stored_hash = record.get('Server password hash', '')
config = pathlib.Path(config_path).read_text()
hashes = re.findall(r'^\s*user\s+' + re.escape(user) + r'\s+(\S+)\s*$', config, re.MULTILINE)
if (record.get('Server domain') != domain or not user or not password or
        not stored_hash or hashes != [stored_hash]):
    sys.exit('Saved credentials no longer match the server user; refusing to export a stale client configuration.')
values = {
    'uri_template': 'https://' + domain + '/.well-known/masque/ip/{target}/{ipproto}/',
    'username': user,
    'password': password,
    'mode': 'system',
    'transport': 'auto',
    'target': '*',
    'ipproto': '*',
    'ipv6': False,
    'dns': ['1.1.1.1', '9.9.9.9'],
}
text = ('# Rust masque-client: Linux whole-system VPN (requires root).\n'
        '# Copy to the client and keep this password file mode 0600.\n'
        '# On macOS, set mode = "socks" for the default 127.0.0.1:1080 proxy.\n')
text += ''.join(key + ' = ' + json.dumps(value, ensure_ascii=False) + '\n' for key, value in values.items())
text += '\n# Used only when mode = "socks"; system mode ignores this section.\n'
text += '[socks]\nlisten = ["127.0.0.1:1080"]\n'
pathlib.Path(output_path).write_text(text)
PY
    chmod 0600 "$BUILD_DIR/masque-client.toml"
}

configure_firewall() {
    local rules
    say "Checking the host firewall"
    if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        die "firewalld is active; configure TCP/UDP 443 and bidirectional masque0 forwarding before a manual deployment"
    fi
    if command -v iptables >/dev/null; then
        rules=$(iptables -S FORWARD) || die "cannot inspect the host's forwarding policy"
        if grep -Fxq -- '-P FORWARD DROP' <<<"$rules"; then
            # Do not silently bypass an existing Docker/host isolation policy.
            die "iptables FORWARD defaults to DROP; configure persistent masque0 forwarding before using this installer"
        fi
    fi
}


# Repair only the named local identity, under shadow-utils locking. Reuse safe
# numeric IDs; never recursively chown an arbitrary previous home directory.
provision_service_user() {
    python3 - <<'PY'
import contextlib
import ctypes
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time

NAME = 'caddy-masque'
SERVICE_HOME = '/etc/caddy-masque/.home'
SERVICE_SHELL = '/usr/sbin/nologin'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
DATABASES = ('passwd', 'group', 'shadow', 'gshadow')


def rows(text):
    return [line.split(':') for line in text.splitlines() if line and not line.startswith('#')]


def number(value):
    return int(value) if value.isascii() and value.isdecimal() else None


def getent(database, key=None):
    args = ['/usr/bin/getent', database]
    if key is not None:
        args.append(str(key))
    result = subprocess.run(args, env=ENV, capture_output=True, text=True)
    if result.returncode not in (0, 2):
        raise RuntimeError('Cannot safely query NSS ' + database + '.')
    return result.stdout


def replace_named(text, replacement):
    """Replace all duplicate own-name records, preserving every other raw line."""
    output = []
    inserted = False
    for line in text.splitlines(keepends=True):
        if line.rstrip('\r\n').split(':', 1)[0] == NAME:
            if not inserted:
                output.append(replacement + '\n')
                inserted = True
        else:
            output.append(line)
    if not inserted:
        if output and not output[-1].endswith('\n'):
            output[-1] += '\n'
        output.append(replacement + '\n')
    return ''.join(output)


def strip_memberships(text, gshadow=False):
    """Remove this one account from supplementary/admin lists, never other names."""
    output = []
    for line in text.splitlines(keepends=True):
        raw = line.rstrip('\r\n')
        fields = raw.split(':')
        if fields[0] == NAME or raw.startswith('#') or len(fields) != 4:
            output.append(line)
            continue
        old = fields.copy()
        for index in ((2, 3) if gshadow else (3,)):
            fields[index] = ','.join(member for member in fields[index].split(',') if member != NAME)
        output.append((':'.join(fields) + ('\n' if line.endswith('\n') else '')) if fields != old else line)
    return ''.join(output)


def plan(databases, nss_passwd, nss_group, query):
    """No filesystem or ownership changes: compute only this identity's repair."""
    local_users = rows(databases['passwd'])
    local_groups = rows(databases['group'])
    users = local_users + rows(nss_passwd)
    groups = local_groups + rows(nss_group)
    own_users = [r for r in local_users if r[0] == NAME and len(r) == 7]
    own_groups = [r for r in local_groups if r[0] == NAME and len(r) == 4]
    current = own_users[0] if own_users else None

    def unique_uid(uid):
        return uid is not None and 0 < uid < 4294967295 and not any(
            len(r) == 7 and r[0] != NAME and number(r[2]) == uid for r in users) and not any(
            len(r) == 7 and r[0] != NAME for r in rows(query('passwd', uid)))

    def unique_gid(gid):
        return gid is not None and 0 < gid < 4294967295 and not any(
            len(r) == 4 and r[0] != NAME and number(r[2]) == gid for r in groups) and not any(
            len(r) == 7 and r[0] != NAME and number(r[3]) == gid for r in users) and not any(
            len(r) == 4 and r[0] != NAME for r in rows(query('group', gid)))

    def unused(database, extra):
        # NSS enumeration can omit directory-service records. Query every
        # candidate numerically too, instead of assuming enumeration is complete.
        occupied = {number(r[2]) for r in (users if database == 'passwd' else groups) if len(r) >= 3}
        for candidate in list(range(999, 99, -1)) + list(range(60000, 999, -1)):
            if candidate not in occupied and candidate not in extra and not query(database, candidate):
                return candidate
        raise RuntimeError('No unused system ' + ('UID' if database == 'passwd' else 'GID') + ' is available.')

    old_uid = number(current[2]) if current else None
    uid = old_uid if unique_uid(old_uid) else unused('passwd', set())
    old_gids = [number(own_groups[0][2])] if own_groups else []
    if current:
        old_gids.append(number(current[3]))
    gid = next((candidate for candidate in old_gids if unique_gid(candidate)), None)
    if gid is None:
        # A GID used only as another account's primary GID is occupied even
        # if the corresponding /etc/group entry is missing.
        primary = {number(r[3]) for r in users if len(r) == 7 and r[0] != NAME}
        gid = unused('group', primary)
    shell = current[6] if current and current[6] in (SERVICE_SHELL, '/sbin/nologin', '/bin/false') else SERVICE_SHELL
    gecos = current[4] if current else 'MASQUE VPN service'
    output = dict(databases)
    output['passwd'] = replace_named(databases['passwd'], f'{NAME}:x:{uid}:{gid}:{gecos}:{SERVICE_HOME}:{shell}')
    output['group'] = replace_named(strip_memberships(databases['group']), f'{NAME}:x:{gid}:')
    # This is an operating-system service account, not the VPN client's
    # Argon2 account: disable login passwords entirely, including old hashes.
    output['shadow'] = replace_named(databases['shadow'], f'{NAME}:!:{int(time.time()) // 86400}::::::')
    output['gshadow'] = replace_named(strip_memberships(databases['gshadow'], True), f'{NAME}:!::')
    return output, uid, gid


@contextlib.contextmanager
def account_lock():
    # glibc lckpwdf is also used by Debian/Ubuntu shadow-utils. In
    # particular it serializes with useradd/usermod's commonio locks.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.lckpwdf() != 0:
        raise OSError(ctypes.get_errno(), 'Cannot lock the account databases')
    try:
        yield
    finally:
        libc.ulckpwdf()


def read_databases(etc):
    data, metadata, attributes = {}, {}, {}
    for name in DATABASES:
        path = etc / name
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            if name not in ('shadow', 'gshadow'):
                raise RuntimeError('The local ' + name + ' database is missing.')
            data[name], metadata[name], attributes[name] = '', None, {}
            continue
        with os.fdopen(descriptor, 'rb') as stream:
            meta = os.fstat(stream.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
                raise RuntimeError('The local ' + name + ' database must be a single-link regular file.')
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                raise RuntimeError('The local ' + name + ' database must be root-owned and not writable by others.')
            data[name] = stream.read().decode('utf-8', 'surrogateescape')
            metadata[name] = meta
            attributes[name] = {key: os.getxattr(stream.fileno(), key) for key in os.listxattr(stream.fileno())}
    return data, metadata, attributes


def write_private(path, text, meta, attributes):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(text.encode('utf-8', 'surrogateescape'))
            stream.flush()
            os.fchown(descriptor, meta.st_uid if meta else 0, meta.st_gid if meta else 0)
            os.fchmod(descriptor, stat.S_IMODE(meta.st_mode) if meta else 0o600)
            for key, value in attributes.items():
                os.setxattr(descriptor, key, value)
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def publish(etc, original, replacement, metadata, attributes, replace=os.replace):
    """Atomic per-file publication, private backups and ordinary-error rollback."""
    private = Path(tempfile.mkdtemp(prefix='.masque-account-', dir=etc))
    changed = [name for name in ('group', 'gshadow', 'shadow', 'passwd') if replacement[name] != original[name]]
    published = []
    rollback_failed = False
    try:
        for name in changed:
            if metadata[name] is not None:
                write_private(private / (name + '.old'), original[name], metadata[name], attributes[name])
            write_private(private / (name + '.new'), replacement[name], metadata[name], attributes[name])
        # Do not overwrite a non-cooperating writer that changed a database
        # after it was read, even though the normal shadow lock is held.
        for name in changed:
            actual = (etc / name).lstat() if (etc / name).exists() else None
            before = metadata[name]
            if before is None:
                if actual is not None:
                    raise RuntimeError('The account database changed during preparation.')
            elif actual is None or (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (
                    before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                raise RuntimeError('The account database changed during preparation.')
        for name in changed:
            replace(private / (name + '.new'), etc / name)
            published.append(name)
        descriptor = os.open(etc, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        yield
    except BaseException:
        for name in reversed(published):
            try:
                if metadata[name] is None:
                    (etc / name).unlink()
                else:
                    os.replace(private / (name + '.old'), etc / name)
            except OSError:
                rollback_failed = True
        if rollback_failed:
            raise RuntimeError('Account rollback was incomplete; private recovery files remain at ' + str(private))
        raise
    finally:
        if not rollback_failed:
            shutil.rmtree(private)


def flush_nss_cache():
    # These invalidate caches, not identities or access configuration.
    if Path('/usr/sbin/nscd').exists():
        for database in ('passwd', 'group'):
            subprocess.run(['/usr/sbin/nscd', '-i', database], env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if Path('/usr/sbin/sss_cache').exists():
        subprocess.run(['/usr/sbin/sss_cache', '-u', NAME, '-g', NAME], env=ENV,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Service account preparation requires root.')
    etc = Path('/etc')
    with account_lock():
        original, metadata, attributes = read_databases(etc)
        nss_passwd, nss_group = getent('passwd'), getent('group')
        replacement, uid, gid = plan(original, nss_passwd, nss_group, getent)
        try:
            with publish(etc, original, replacement, metadata, attributes):
                flush_nss_cache()
                if getent('passwd', NAME).strip() != next(r for r in replacement['passwd'].splitlines() if r.startswith(NAME + ':')):
                    raise RuntimeError('External NSS overrides the local service account; its configuration cannot be safely rewritten here.')
                if getent('group', NAME).strip() != f'{NAME}:x:{gid}:':
                    raise RuntimeError('External NSS overrides the local service group; its configuration cannot be safely rewritten here.')
                groups = subprocess.run(['/usr/bin/id', '-G', NAME], env=ENV, text=True, capture_output=True, check=True).stdout.split()
                if groups != [str(gid)]:
                    raise RuntimeError('An external NSS provider still grants supplementary groups to the service account.')
        except BaseException:
            flush_nss_cache()
            raise
    print(f'{uid} {gid}')


if __name__ == '__main__':
    main()
PY
}

install_server() {
    local path index=0
    # Recheck after a potentially long build, before replacing files or
    # stopping the old service. An external owner may have appeared meanwhile.
    check_port_owners allow-managed || die 'Port 443 ownership changed; replacement was not started.'
    if ip link show masque0 >/dev/null 2>&1; then
        check_tunnel_owners || die 'masque0 ownership changed; replacement was not started'
    fi
    # Capture the state at cutover, not before a long build. Preserve any
    # administrator start/stop/enable change made while compilation was running.
    WAS_ACTIVE=0
    systemctl is-active --quiet "$SERVICE" && WAS_ACTIVE=1
    WAS_ENABLE_STATE=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)
    WAS_ENABLE_STATE=${WAS_ENABLE_STATE:-disabled}
    say "Taking over caddy-masque: stopping the old service and replacing managed files"
    install -d -m 0700 "$BUILD_DIR/backup"
    mkdir -p "$(dirname -- "$BINARY")" "$UNIT_DIR"
    # Preserve entries as entries, including dangling links or directories at
    # file names. Do not follow a bad configuration-container symlink at all.
    if [[ -L $STATE || ( -e $STATE && ! -d $STATE ) ]]; then
        cp -a -- "$STATE" "$BUILD_DIR/backup/state-entry"
        STATE_ENTRY_SAVED=1
    elif [[ -d $STATE ]]; then
        STATE_METADATA=$(stat -c '%u:%g:%a' -- "$STATE")
    fi
    while IFS= read -r path; do
        index=$((index + 1))
        printf '%s\n' "$path" >"$BUILD_DIR/backup/entry-$index.path"
        if (( STATE_ENTRY_SAVED )) && [[ $path == "$STATE/"* ]]; then continue; fi
        if [[ -e $path || -L $path ]]; then cp -a -- "$path" "$BUILD_DIR/backup/entry-$index"; fi
    done < <(transaction_paths; service_override_paths)

    # Copying a large cover tree can take time too. Reject a new foreign owner
    # before entering the transaction: no old-service stop or rollback is then
    # needed when ownership changed while the private backup was being copied.
    check_port_owners allow-managed || die 'Port 443 ownership changed during backup; replacement was not started.'
    if ip link show masque0 >/dev/null 2>&1; then
        check_tunnel_owners || die 'masque0 ownership changed during backup; replacement was not started'
    fi
    INSTALLING=1
    # Preserve the old unit's stop behavior while it is still available. A
    # stale/missing/masked inactive unit is repaired below without a fresh-only
    # gate; an active old daemon must stop before its unit is rewritten.
    if systemctl is-active --quiet "$SERVICE"; then
        check_service_identity || die 'the service name changed before the old daemon could be stopped'
        systemctl stop "$SERVICE"
        check_port_owners require-free || die 'TCP/UDP 443 was not released by the old service'
    fi
    # The canonical unit replaces a local mask/malformed unit before PID 1 is
    # asked to stop it. Clear this service's overrides and enable links only.
    while IFS= read -r path; do rm -rf --one-file-system -- "$path"; done < <(service_override_paths)
    replace_file "$BUILD_DIR/$SERVICE" "$UNIT_DIR/$SERVICE" 0644 root root
    systemctl daemon-reload
    systemctl stop "$SERVICE"
    check_port_owners require-free || die 'TCP/UDP 443 is still occupied after stopping the managed service.'
    if ip link show masque0 >/dev/null 2>&1; then
        check_tunnel_owners || die 'masque0 still has a process owner after stopping this service'
        (( HAD_DEPLOYMENT )) || die 'A tunnel with unknown ownership was not deleted.'
        ip link delete masque0
    fi
    if nft list table inet caddy-masque >/dev/null 2>&1; then
        (( HAD_DEPLOYMENT )) || die 'A firewall table with unknown ownership was not deleted.'
        nft delete table inet caddy-masque
    fi
    provision_service_user
    managed_directory "$STATE" 0750 root caddy-masque
    # Both are installer-owned empty sources; remove stale content and planted
    # keys. The non-root daemon cannot rewrite its own home or /run view.
    rm -rf --one-file-system -- "$RUNTIME_VIEW" "$STATE/.home"
    managed_directory "$RUNTIME_VIEW" 0755 root root
    managed_directory "$STATE/.home" 0555 root root
    # Force PID 1 to detect a top-level ownership change and recursively repair
    # mixed old UID/root state. Preserve certificate/account/storage CONTENTS.
    for path in /var/lib/caddy-masque /var/lib/caddy-masque-config /var/log/caddy-masque; do
        managed_directory "$path" 0700 root root
    done
    managed_directory /run/caddy-masque 0700 root root
    # The cover tree is owned by this installer too. Stale symlinks must not
    # turn a public file server into a way to read the token or private keys.
    rm -rf --one-file-system -- "$SITE"
    managed_directory "$SITE" 0755 root root
    printf '<!doctype html><html lang="en"><meta charset="utf-8"><title>Welcome</title><h1>Welcome</h1></html>\n' >"$BUILD_DIR/index.html"
    replace_file "$BUILD_DIR/index.html" "$SITE/index.html" 0644 root root
    # Persist plaintext before its new hash. A later failure either restores
    # both or retains private rollback copies for an explicit recovery report.
    replace_file "$BUILD_DIR/client-credentials.txt" "$CREDENTIALS" 0600 root root
    printf '%s\n' "$DOMAIN" >"$BUILD_DIR/domain"
    replace_file "$BUILD_DIR/domain" "$STATE/domain" 0600 root root
    replace_file "$BUILD_DIR/cloudflare-token" "$TOKEN_FILE" 0640 root caddy-masque
    replace_file "$BUILD_DIR/Caddyfile" "$CONFIG" 0640 root caddy-masque
    replace_file "$BUILD_DIR/caddy-masque" "$BINARY" 0755 root root
    # Drop an old plaintext export until the validated replacement is published.
    rm -rf --one-file-system -- "$CLIENT_CONFIG"
    mkdir -p /etc/modules-load.d
    printf 'tun\n' >"$BUILD_DIR/modules.conf"
    replace_file "$BUILD_DIR/modules.conf" /etc/modules-load.d/caddy-masque.conf 0644 root root
    systemctl daemon-reload
    if systemctl is-failed --quiet "$SERVICE"; then systemctl reset-failed "$SERVICE"; fi
    if ! systemctl restart "$SERVICE"; then
        check_port_owners require-free || true
        die 'caddy-masque failed to start; inspect the port-owner report and service journal.'
    fi
}

verify_server() {
    local ready=
    say "Checking trusted HTTPS, listeners, TUN and managed forwarding/NAT"
    # DNS propagation and initial ACME issuance can take several minutes.
    for _ in {1..60}; do
        if systemctl is-active --quiet "$SERVICE" &&
            curl --disable --noproxy '*' -fsS --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" >/dev/null; then
            ready=1
            break
        fi
        sleep 5
    done
    [[ -n $ready ]] || die "HTTPS startup failed; inspect journalctl -u $SERVICE -n 60 --no-pager"
    [[ -n $(ss -ltnH 'sport = :443') && -n $(ss -lunH 'sport = :443') ]] || die "TCP and UDP 443 must both be listening"
    ip link show masque0 >/dev/null || die "masque0 is missing"
    [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]] || die "IPv4 forwarding is disabled"
    nft list table inet caddy-masque >/dev/null || die "managed nftables/NAT table is missing"
}

cleanup() {
    local result=$? path backup index=0 state_uid state_gid state_mode rollback_failed=0
    trap - EXIT
    set +e
    if [[ -n $INSTALLING && $result != 0 ]]; then
        printf '\nInstallation failed; restoring the previous managed files and service.\n' >&2
        if [[ $(systemctl show -p Id --value "$SERVICE" 2>/dev/null || true) == "$SERVICE" ]]; then
            systemctl stop "$SERVICE" || rollback_failed=1
            if (( ENABLE_TOUCHED )); then systemctl disable "$SERVICE" || rollback_failed=1; fi
        else
            rollback_failed=1
        fi
        while IFS= read -r path; do
            index=$((index + 1))
            if (( STATE_ENTRY_SAVED )) && [[ $path == "$STATE/"* ]]; then continue; fi
            backup="$BUILD_DIR/backup/entry-$index"
            rm -rf --one-file-system -- "$path" || rollback_failed=1
            if [[ -e $backup || -L $backup ]]; then
                cp -a -- "$backup" "$path" || rollback_failed=1
            fi
        done < <(transaction_paths; service_override_paths)
        if (( STATE_ENTRY_SAVED )); then
            rm -rf --one-file-system -- "$STATE" || rollback_failed=1
            cp -a -- "$BUILD_DIR/backup/state-entry" "$STATE" || rollback_failed=1
        elif [[ -n $STATE_METADATA ]]; then
            IFS=: read -r state_uid state_gid state_mode <<<"$STATE_METADATA"
            chown "$state_uid:$state_gid" "$STATE" || rollback_failed=1
            chmod "$state_mode" "$STATE" || rollback_failed=1
        fi
        systemctl daemon-reload || rollback_failed=1
        # The saved wants links already restore persistent/runtime enablement.
        # Re-enabling could act on a vendor alias revealed by restoring an old
        # missing unit. Recheck the canonical identity after daemon-reload before
        # restarting; an unrestartable old deployment requires private recovery.
        if (( WAS_ACTIVE )); then
            if [[ $(systemctl show -p Id --value "$SERVICE" 2>/dev/null || true) == "$SERVICE" ]]; then
                systemctl start "$SERVICE" || rollback_failed=1
            else
                rollback_failed=1
            fi
        fi
        if (( WAS_ACTIVE )); then
            systemctl is-active --quiet "$SERVICE" || rollback_failed=1
        elif systemctl is-active --quiet "$SERVICE"; then
            rollback_failed=1
        fi
        [[ $(systemctl is-enabled "$SERVICE" 2>/dev/null || true) == "$WAS_ENABLE_STATE" ]] || rollback_failed=1
        printf 'Packages and Caddy certificate state are retained for retry.\n' >&2
    fi
    cleanup_swap
    [[ -z $GO_STAGE ]] || rm -rf -- "$GO_STAGE"
    if (( rollback_failed )); then
        printf 'Automatic recovery was incomplete. Private backups remain in %s/backup.\n' "$BUILD_DIR" >&2
    else
        [[ -z $BUILD_DIR ]] || rm -rf -- "$BUILD_DIR"
    fi
    exit "$result"
}

main() {
    # Prevent a caller's bash -x from disclosing the token or generated password.
    set +x
    set +v
    set +a
    set -euo pipefail
    export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
    unset CDPATH
    # Keep an explicitly supplied token shell-local throughout package/build
    # commands; it is consumed by stage_token without entering child environments.
    local supplied_cf_token=${CF_API_TOKEN:-}
    unset CF_API_TOKEN
    local CF_API_TOKEN=$supplied_cf_token
    export -n CF_API_TOKEN supplied_cf_token
    umask 077
    case "${1:-}" in
        -h | --help) usage; return 0 ;;
        '') ;;
        *) usage >&2; return 2 ;;
    esac
    [[ $# -eq 0 ]] || die "no positional arguments are accepted"
    init_paths
    preflight
    collect_settings
    BUILD_DIR=$(mktemp -d /var/tmp/caddy-masque-setup-XXXXXX)
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Reject known conflicts before package work when the inspection tools are
    # already installed. A fresh host first obtains those required tools.
    if command -v ss >/dev/null && command -v python3 >/dev/null; then
        check_ports
        install_packages
    else
        install_packages
        check_ports
    fi
    collect_pool
    configure_firewall
    build_server
    stage_token
    stage_config
    stage_service
    stage_client_config
    install_server
    verify_server
    # Publish the client file only after the server passes its startup checks.
    replace_file "$BUILD_DIR/masque-client.toml" "$CLIENT_CONFIG" 0600 root root
    ENABLE_TOUCHED=1
    systemctl enable --force "$SERVICE"
    [[ $(systemctl is-enabled "$SERVICE") == enabled ]] || die 'persistent boot enablement was not established'
    systemctl is-active --quiet "$SERVICE"
    INSTALLING=
    say "Server installed: https://$DOMAIN/"
    [[ ! -f $CREDENTIALS ]] || sed '/^Server password hash: /d' "$CREDENTIALS"
    printf '\nClient credentials: %s (root only). Save them privately.\n' "$CREDENTIALS"
    printf 'Rust client configuration: %s (mode 0600). Copy it to the client.\n' "$CLIENT_CONFIG"
    printf 'On the Linux client: sudo masque-client --config ./masque-client.toml\n'
    printf 'Provider firewall: allow TCP 443 and UDP 443; TCP 80 is optional for HTTPS redirects.\n'
    printf 'Status: systemctl status %s\n' "$SERVICE"
    printf 'Containment: systemctl show %s -p MemoryMax -p TasksMax -p NoExecPaths\n' "$SERVICE"
    printf 'Private filesystem view: managed configuration/site/state and required system files; custom paths need root-maintained unit overrides.\n'
    printf 'CAP_NET_ADMIN is still required in the host network namespace; this profile is not full host isolation.\n'
    printf 'Caddy automatically renews certificates; keep %s valid, root-owned and readable only by the service group.\n' "$TOKEN_FILE"
    printf 'Check that client LANs do not overlap the server tunnel pool in %s.\n' "$CONFIG"
    printf 'Verify a real client tunnel, DNS, TCP/UDP traffic and reconnect from another device.\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

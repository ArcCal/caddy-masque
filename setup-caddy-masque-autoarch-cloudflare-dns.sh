#!/usr/bin/env bash
# Interactive native-architecture Caddy MASQUE setup with Cloudflare DNS-01.
# Run from an authenticated, complete checkout:
#   sudo bash setup-caddy-masque-autoarch-cloudflare-dns.sh
# Supports Debian 12/13 and Ubuntu 22.04/24.04 on Linux amd64/arm64.
# Only this file is added to the repository. Runtime files are installed outside it.
# Caddy obtains and renews its certificate using the bundled Cloudflare module.
# Re-running preserves this installer's Caddyfile, users and certificate lineage.
# Existing unrelated Caddyfiles are refused; migrate those manually.
# A private Rust masque-client TOML file is exported after successful startup.

usage() {
    cat <<'EOF'
Usage: sudo bash setup-caddy-masque-autoarch-cloudflare-dns.sh

Interactively build and install a native Linux amd64/arm64 MASQUE server
with the bundled caddy-dns/cloudflare plugin, configure DNS-01 issuance
and automatic renewal in Caddy, and start the hardened systemd service.

Required: Debian 12/13 or Ubuntu 22.04/24.04, root, systemd, TUN and Internet.
Have a DNS-only domain at Cloudflare and a CF_API_TOKEN scoped to that zone
with Zone:DNS:Edit and Zone:Zone:Read. The token is entered without echo and
stored in a mode-0600 file for renewal; it is never a command argument.
TCP/UDP 443 must reach this server. DNS-01 does not require inbound port 80.
Only domain and token are requested. The script selects an IPv4-only tunnel
pool automatically; client LANs must not overlap the reported pool.

This installs packages and writes /usr/local/bin/caddy, /etc/caddy,
/etc/caddy-masque, a systemd unit, a cover page and private client credentials.
The generated masque-client.toml uses Rust's Linux system mode (full VPN).
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
    CONFIG=/etc/caddy/Caddyfile
    BINARY=/usr/local/bin/caddy
    STATE=/etc/caddy-masque
    TOKEN_FILE=/etc/caddy/cloudflare-token
    CREDENTIALS="$STATE/client-credentials.txt"
    CLIENT_CONFIG="$STATE/masque-client.toml"
    SITE=/var/www/site
    GO_INSTALL_ROOT=/opt/caddy-masque
    BUILD_CACHE=/var/cache/caddy-masque
    UNIT_DIR=/etc/systemd/system
    SERVICE=caddy-masque.service
    BUILD_DIR=''
    INSTALLING=''
    SWAP=''
    WAS_ACTIVE=0
    WAS_ENABLED=0
    HAD_CONFIG=0
}

preflight() {
    [[ $(id -u) == 0 ]] || die "run with sudo bash $0"
    [[ $(uname -s) == Linux ]] || die "only Linux is supported"
    ARCH=$(detect_arch "$(uname -m)") || die "unsupported architecture: $(uname -m); use amd64 or arm64"
    # shellcheck disable=SC1091
    . /etc/os-release
    case "$ID:$VERSION_ID" in
        debian:12 | debian:13 | ubuntu:22.04 | ubuntu:24.04) ;;
        *) die "supported systems: Debian 12/13 and Ubuntu 22.04/24.04 (found $ID $VERSION_ID)" ;;
    esac
    [[ -f $SRC/go.mod && -d $SRC/third_party/xnet && -d $SRC/third_party/quic-go && -f $SRC/deploy/caddy-masque.service ]] ||
        die "keep this script at the root of the complete caddy-masque checkout"
    [[ -d /run/systemd/system ]] || die "systemd must be running as the system service manager"
    command -v flock >/dev/null || die "install util-linux (flock) first"
    exec 9>/run/lock/caddy-masque-setup.lock
    flock -n 9 || die "another instance of this installer is running"
    if [[ ! -c /dev/net/tun ]]; then modprobe tun 2>/dev/null || true; fi
    [[ -c /dev/net/tun ]] || die "enable TUN/TAP in your VPS provider's panel; /dev/net/tun is missing"
    [[ -w /proc/sys/net/ipv4/ip_forward ]] || die "the host must allow network sysctl changes (not a restricted container)"
    if [[ -e $CONFIG ]]; then
        HAD_CONFIG=1
        [[ -f $STATE/domain && -f $CONFIG ]] &&
            [[ $(head -n 1 "$CONFIG") == '# Managed by setup-caddy-masque-autoarch-cloudflare-dns.sh' ]] ||
            die "an unrelated $CONFIG exists; back it up and migrate it manually before using this installer"
    fi
}

collect_settings() {
    local value saved_domain=
    if (( HAD_CONFIG )); then
        saved_domain=$(cat "$STATE/domain")
        valid_domain "$saved_domain" || die "invalid saved domain in $STATE/domain"
    fi
    while :; do
        ask value "Server domain${saved_domain:+ [$saved_domain]}: "
        DOMAIN=${value,,}
        DOMAIN=${DOMAIN:-$saved_domain}
        valid_domain "$DOMAIN" && break
        printf 'Enter one DNS hostname, without a URL, port or wildcard.\n' >&2
    done
    [[ -z $saved_domain || $DOMAIN == "$saved_domain" ]] || die "this installation uses $saved_domain; domain migration requires a manual configuration change"
    USER_NAME=laptop
}

install_packages() {
    say "Installing build and network dependencies"
    DEBIAN_FRONTEND=noninteractive apt-get update -q </dev/null
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y -q \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold curl ca-certificates nftables iproute2 dnsutils jq \
        python3 util-linux </dev/null
}

check_ports() {
    local unit port
    for unit in masque-server caddy nginx apache2; do
        if systemctl is-active --quiet "$unit.service"; then
            die "$unit is running; stop the conflicting service before continuing"
        fi
    done
    systemctl is-active --quiet "$SERVICE" && WAS_ACTIVE=1
    systemctl is-enabled --quiet "$SERVICE" && WAS_ENABLED=1
    # An existing managed server may own these ports; preserve it during build.
    if (( ! WAS_ACTIVE )); then
        for port in 80 443; do
            [[ -z $(ss -ltnH "sport = :$port") ]] || die "TCP port $port is already in use"
        done
        [[ -z $(ss -lunH 'sport = :443') ]] || die "UDP port 443 is already in use"
        ! ip link show masque0 >/dev/null 2>&1 || die "masque0 already exists; resolve the existing tunnel before installing"
    elif (( ! HAD_CONFIG )); then
        die "an unmanaged caddy-masque service is already running"
    fi
    return 0
}

check_pool() {
    ip -j -4 route show table all >"$BUILD_DIR/routes.json"
    python3 - "$1" "$BUILD_DIR/routes.json" <<'PY'
import ipaddress, json, sys
try:
    pool = ipaddress.ip_interface(sys.argv[1])
    private = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if pool.version != 4 or not 16 <= pool.network.prefixlen <= 30 or not any(pool.network.subnet_of(n) for n in private):
        raise ValueError('use an RFC1918 IPv4 pool with prefix /16 through /30')
    if pool.ip in (pool.network.network_address, pool.network.broadcast_address):
        raise ValueError('the server address must be a usable host address')
    for route in json.load(open(sys.argv[2])):
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
    (( ! HAD_CONFIG )) || return 0
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

check_dns() {
    local resolved answer
    say "Checking public DNS (use Cloudflare DNS-only, the grey cloud)"
    PUBLIC_IP=$(curl -4 -fsS --retry 2 --connect-timeout 10 --max-time 20 https://api.ipify.org) ||
        die "cannot check upstream IPv4 connectivity"
    resolved=$(dig +short A "$DOMAIN" @1.1.1.1)
    grep -Fxq -- "$PUBLIC_IP" <<<"$resolved" || die "$DOMAIN must have a DNS-only A record pointing to $PUBLIC_IP"
    # Every advertised address must reach this host. A stray AAAA breaks clients.
    while IFS= read -r answer; do
        [[ $answer =~ ^[0-9.]+$ ]] || continue
        [[ $answer == "$PUBLIC_IP" ]] || die "$DOMAIN also advertises another IPv4 address ($answer); correct its DNS first"
    done <<<"$resolved"
    resolved=$(dig +short AAAA "$DOMAIN" @1.1.1.1)
    if [[ $resolved == *:* ]]; then
        PUBLIC_IPV6=$(curl -6 -fsS --connect-timeout 10 --max-time 20 https://api6.ipify.org) ||
            die "$DOMAIN has an AAAA record but this server cannot reach the IPv6 Internet; correct or remove that record"
        python3 - "$resolved" "$PUBLIC_IPV6" <<'PY' || die "the AAAA records must point to this server's working public IPv6 address"
import ipaddress, sys
expected = ipaddress.ip_address(sys.argv[2])
assert all(ipaddress.ip_address(v) == expected for v in sys.argv[1].splitlines() if ':' in v)
PY
    fi
}

cleanup_swap() {
    [[ -n $SWAP ]] || return 0
    if swapon --show=NAME --noheadings | grep -Fxq -- "$SWAP"; then
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
    local releases go_line go_version go_file go_sha go_root mem_kb swap_kb free_kb
    say "Building the native linux/$ARCH server from this checkout"
    go_line=$(sed -n 's/^go \([0-9]*\.[0-9]*\)\.[0-9]*$/\1/p' "$SRC/go.mod")
    [[ -n $go_line ]] || die "cannot read the Go release line from go.mod"
    # Keep a separate toolchain and caches; never replace the system's Go.
    install -d -m 0755 "$GO_INSTALL_ROOT" "$BUILD_CACHE"
    free_kb=$(df -Pk "$BUILD_CACHE" | awk 'NR==2 {print $4}')
    [[ $free_kb -ge 5242880 ]] || die "free at least 5 GiB for the toolchain and build caches"
    free_kb=$(df -Pk "$BUILD_DIR" | awk 'NR==2 {print $4}')
    [[ $free_kb -ge 3145728 ]] || die "free at least 3 GiB in /var/tmp for build staging and possible swap"
    releases="$BUILD_DIR/go-releases.json"
    curl -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 --max-time 90 \
        'https://go.dev/dl/?mode=json&include=all' -o "$releases"
    go_version=$(jq -r --arg line "go$go_line." 'first(.[] | select(.stable and (.version | startswith($line))) | .version) // empty' "$releases")
    [[ $go_version =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no stable Go $go_line patch release was found"
    go_file="$go_version.linux-$ARCH.tar.gz"
    go_sha=$(jq -r --arg file "$go_file" 'first(.[].files[] | select(.filename == $file) | .sha256) // empty' "$releases")
    [[ $go_sha =~ ^[0-9a-f]{64}$ ]] || die "missing official Go archive checksum"
    go_root="$GO_INSTALL_ROOT/$go_version-$ARCH"
    if [[ ! -x $go_root/bin/go ]]; then
        curl -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 --max-time 600 \
            "https://go.dev/dl/$go_file" -o "$BUILD_DIR/go.tar.gz"
        printf '%s  %s\n' "$go_sha" "$BUILD_DIR/go.tar.gz" | sha256sum -c --quiet - || die "Go archive checksum mismatch"
        tar -xzf "$BUILD_DIR/go.tar.gz" -C "$BUILD_DIR"
        mv -- "$BUILD_DIR/go" "$go_root"
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
    if ! (cd -- "$SRC" && env -u GOFLAGS -u GOOS -u GOARCH -u GOROOT -u GOWORK \
        GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOENV=off \
        GOCACHE="$BUILD_CACHE/build" GOMODCACHE="$BUILD_CACHE/mod" \
        "$go_root/bin/go" build -p 1 -mod=readonly -trimpath -ldflags '-s -w' -o "$BUILD_DIR/caddy" ./cmd/caddy); then
        die "build failed; the installed binary was not replaced. Check disk/memory and access to proxy.golang.org"
    fi
    cleanup_swap
    "$BUILD_DIR/caddy" list-modules >"$BUILD_DIR/modules.txt"
    local module
    for module in masque http.handlers.masque dns.providers.cloudflare; do
        grep -Fxq -- "$module" "$BUILD_DIR/modules.txt" || die "built server is missing $module; installation stopped"
    done
}

stage_token() {
    local token
    say "Configuring Caddy Cloudflare DNS-01 issuance and renewal"
    if [[ -f $TOKEN_FILE ]]; then
        printf 'CF_API_TOKEN (hidden; Enter keeps the saved token): ' >&2
    else
        printf 'CF_API_TOKEN (hidden; zone-scoped DNS Edit + Zone Read): ' >&2
    fi
    IFS= read -r -s token || die "no Cloudflare token supplied"
    printf '\n' >&2
    if [[ -z $token && -f $TOKEN_FILE ]]; then token=$(cat "$TOKEN_FILE"); fi
    valid_token "$token" || die "invalid Cloudflare API token format; use a token, not a global API key"
    printf '%s\n' "$token" >"$BUILD_DIR/cloudflare-token"
    chmod 0600 "$BUILD_DIR/cloudflare-token"
    unset token
}

stage_config() {
    if (( HAD_CONFIG )); then
        cp -- "$CONFIG" "$BUILD_DIR/Caddyfile"
        say "Keeping existing users and Caddyfile"
    else
        local account hash password
        account=$("$BUILD_DIR/caddy" masque-passwd --name "$USER_NAME")
        hash=$(awk '/^user / {print $3}' <<<"$account")
        password=$(awk '/^password = / {gsub(/"/, "", $3); print $3}' <<<"$account")
        [[ $hash == "\$argon2id\$"* && -n $password ]] || die "account generation failed"
        cat >"$BUILD_DIR/Caddyfile" <<EOF
# Managed by setup-caddy-masque-autoarch-cloudflare-dns.sh
# Caddy owns certificate issuance and renewal using Cloudflare DNS-01.
{
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
Server IPv4: $PUBLIC_IP
User name: $USER_NAME
Password: $password
Server password hash: $hash
URI template: https://$DOMAIN/.well-known/masque/ip/{target}/{ipproto}/
Transport: auto (h3, h2 or http/1.1); IPv6 in tunnel: disabled
EOF
        unset account hash password
    fi
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
    if ! "$BUILD_DIR/caddy" validate --config "$BUILD_DIR/validate.Caddyfile" --adapter caddyfile >"$BUILD_DIR/validation.log" 2>&1; then
        python3 - "$BUILD_DIR/validation.log" "$BUILD_DIR/cloudflare-token" <<'PYCODE'
import pathlib, sys
message = pathlib.Path(sys.argv[1]).read_text()
token = pathlib.Path(sys.argv[2]).read_text().strip()
print(message.replace(token, '[REDACTED]'), file=sys.stderr)
PYCODE
        die "Caddy configuration validation failed; the installed server was not changed"
    fi
}

stage_client_config() {
    local record="$CREDENTIALS"
    if (( ! HAD_CONFIG )); then record="$BUILD_DIR/client-credentials.txt"; fi
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
    say "Checking the host firewall"
    if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        die "firewalld is active; configure TCP/UDP 443 and bidirectional masque0 forwarding before a manual deployment"
    fi
    if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 443/udp
        ufw route allow in on masque0
        ufw route allow out on masque0
    elif command -v iptables >/dev/null && iptables -S FORWARD | grep -Fxq -- '-P FORWARD DROP'; then
        # Do not silently bypass an existing Docker/host isolation policy.
        die "iptables FORWARD defaults to DROP (often Docker); configure persistent masque0 forwarding before using this installer"
    fi
}


install_server() {
    local path
    say "Installing the validated server (restarting disconnects existing clients)"
    install -d -m 0700 "$BUILD_DIR/backup"
    for path in "$BINARY" "$CONFIG" "$TOKEN_FILE" "$CLIENT_CONFIG" "$UNIT_DIR/$SERVICE"; do
        if [[ -e $path ]]; then cp -p -- "$path" "$BUILD_DIR/backup/$(basename -- "$path")"; fi
    done
    INSTALLING=1
    install -d -m 0755 "$(dirname -- "$BINARY")" "$(dirname -- "$CONFIG")" "$SITE" "$UNIT_DIR"
    if [[ ! -e $SITE/index.html ]]; then
        printf '<!doctype html><html lang="en"><meta charset="utf-8"><title>Welcome</title><h1>Welcome</h1><p>This site is under construction.</p></html>\n' >"$SITE/index.html"
        chmod 0644 "$SITE/index.html"
    fi
    # Rename within the destination filesystem, including while the old binary runs.
    install -m 0755 "$BUILD_DIR/caddy" "$BINARY.masque-new"
    mv -f -- "$BINARY.masque-new" "$BINARY"
    install -d -m 0700 "$STATE"
    install -m 0600 "$BUILD_DIR/cloudflare-token" "$TOKEN_FILE"
    install -m 0600 "$BUILD_DIR/Caddyfile" "$CONFIG"
    install -m 0644 "$SRC/deploy/caddy-masque.service" "$UNIT_DIR/$SERVICE"
    if (( ! HAD_CONFIG )); then
        install -m 0600 "$BUILD_DIR/client-credentials.txt" "$CREDENTIALS"
        printf '%s\n' "$DOMAIN" >"$STATE/domain"
        chmod 0600 "$STATE/domain"
    fi
    systemctl daemon-reload
    systemctl enable "$SERVICE"
    systemctl restart "$SERVICE"
}

verify_server() {
    local ready=
    say "Checking trusted HTTPS, listeners, TUN and managed forwarding/NAT"
    # DNS propagation and initial ACME issuance can take several minutes.
    for _ in {1..60}; do
        if systemctl is-active --quiet "$SERVICE" &&
            curl --noproxy '*' -fsS --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" >/dev/null; then
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
    local result=$? path backup rollback_failed=0
    trap - EXIT
    set +e
    if [[ -n $INSTALLING && $result != 0 ]]; then
        printf '\nInstallation failed; restoring the previous binary, Caddyfile and service.\n' >&2
        systemctl stop "$SERVICE" || rollback_failed=1
        rm -f -- "$CLIENT_CONFIG.new" || rollback_failed=1
        for path in "$BINARY" "$CONFIG" "$TOKEN_FILE" "$CLIENT_CONFIG" "$UNIT_DIR/$SERVICE"; do
            backup="$BUILD_DIR/backup/$(basename -- "$path")"
            if [[ -e $backup ]]; then
                if ! { cp -p -- "$backup" "$path.masque-restore" && mv -f -- "$path.masque-restore" "$path"; }; then
                    rollback_failed=1
                fi
            else
                rm -f -- "$path" || rollback_failed=1
            fi
        done
        if (( ! HAD_CONFIG )); then rm -f -- "$CREDENTIALS" "$STATE/domain" || rollback_failed=1; fi
        systemctl daemon-reload || rollback_failed=1
        if (( ! WAS_ENABLED )); then systemctl disable "$SERVICE" || rollback_failed=1; fi
        if (( WAS_ACTIVE )); then systemctl start "$SERVICE" || rollback_failed=1; fi
        printf 'Packages, Caddy certificate state and any firewall changes are retained for retry.\n' >&2
    fi
    cleanup_swap
    if (( rollback_failed )); then
        printf 'Automatic recovery was incomplete. Private backups are retained in %s/backup.\n' "$BUILD_DIR" >&2
    else
        [[ -z $BUILD_DIR ]] || rm -rf -- "$BUILD_DIR"
    fi
    exit "$result"
}

main() {
    # Prevent a caller's bash -x from disclosing the token or generated password.
    set +x
    set -euo pipefail
    export LC_ALL=C
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
    install_packages
    check_ports
    collect_pool
    check_dns
    configure_firewall
    build_server
    stage_token
    stage_config
    stage_client_config
    install_server
    verify_server
    # Publish the client file only after the server passes its startup checks.
    install -m 0600 "$BUILD_DIR/masque-client.toml" "$CLIENT_CONFIG.new"
    mv -f -- "$CLIENT_CONFIG.new" "$CLIENT_CONFIG"
    INSTALLING=
    say "Server installed: https://$DOMAIN/"
    [[ ! -f $CREDENTIALS ]] || sed '/^Server password hash: /d' "$CREDENTIALS"
    printf '\nClient credentials: %s (root only). Save them privately.\n' "$CREDENTIALS"
    printf 'Rust client configuration: %s (mode 0600). Copy it to the client.\n' "$CLIENT_CONFIG"
    printf 'On the Linux client: sudo masque-client --config ./masque-client.toml\n'
    printf 'Provider firewall: allow TCP 443 and UDP 443; TCP 80 is optional for HTTPS redirects.\n'
    printf 'Status: systemctl status %s\n' "$SERVICE"
    printf 'Caddy automatically renews certificates; keep %s valid and private.\n' "$TOKEN_FILE"
    printf 'Check that client LANs do not overlap the server tunnel pool in %s.\n' "$CONFIG"
    printf 'Verify a real client tunnel, DNS, TCP/UDP traffic and reconnect from another device.\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

#!/usr/bin/env bash
# One-step install of Caddy with the MASQUE VPN on Debian 12/13 or Ubuntu
# 22.04/24.04, from this source tree. Run as root in the source directory:
#
#   bash deploy/install-server.sh vpn.example.com [user]
#
# It installs Go if needed, builds and installs /usr/local/bin/caddy,
# writes /etc/caddy/Caddyfile with a cover website and one user with a
# random password, and starts the caddy-masque service. Caddy gets the
# certificate itself (TCP 80 and 443 must be reachable, and the domain must
# point at this server). The user's name and password are printed at the end
# and kept in /root/masque-credentials.txt.
#
# Running it again rebuilds and restarts; the Caddyfile, the users and the
# certificate are kept. Add users with `caddy masque-passwd` (README).
set -euo pipefail

DOMAIN=${1:-}
USER_NAME=${2:-macbook}
SRC=$(cd "$(dirname "$0")/.." && pwd)
CONFIG=/etc/caddy/Caddyfile
SITE=/var/www/site
CREDENTIALS=/root/masque-credentials.txt
# The Go release line go.mod asks for; the newest patch release of it is
# installed (it carries the standard library's security fixes).
GO_MOD_VERSION=$(sed -n 's/^go \([0-9.]*\)$/\1/p' "$SRC/go.mod")
GO_LINE=${GO_MOD_VERSION%.*}

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31mError: %s\033[0m\n' "$*" >&2; exit 1; }

[ -n "$DOMAIN" ] || die "usage: bash deploy/install-server.sh YOUR_DOMAIN [USER_NAME]"
[ "$(id -u)" = 0 ] || die "run this as root (sudo -i first)"
if [ ! -f "$SRC/go.mod" ] || ! grep -q caddy-masque "$SRC/go.mod"; then die "run this in the caddy-masque source directory"; fi
. /etc/os-release
case "$ID" in
    debian | ubuntu) ;;
    *) die "only Debian and Ubuntu are supported; this is $PRETTY_NAME" ;;
esac

say "Checking the system"
# The tunnel is a TUN device. Containers of the OpenVZ and LXC kind often lack
# it until the hosting provider's panel turns it on.
[ -c /dev/net/tun ] || modprobe tun 2>/dev/null || true
[ -c /dev/net/tun ] || die "there is no /dev/net/tun (TUN device). On OpenVZ- and LXC-type VPSes, turn on TUN/TAP in the provider's panel first, then reboot"
[ -d /proc/sys/net/ipv4 ] && [ -w /proc/sys/net/ipv4/ip_forward ] ||
    die "cannot change /proc/sys/net (is this a restricted container?). The tunnel needs forwarding turned on, so this must run on a system that can change kernel network settings"

say "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q curl ca-certificates nftables iproute2 dnsutils jq

say "Checking that $DOMAIN points at this server"
PUBLIC_IP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || curl -4 -fsS --max-time 10 https://ip.sb || true)
RESOLVED=$(dig +short A "$DOMAIN" @1.1.1.1 | tail -1)
echo "This server's public IPv4: ${PUBLIC_IP:-unknown}; $DOMAIN resolves to: ${RESOLVED:-(no A record)}"
if [ -z "$RESOLVED" ]; then
    die "$DOMAIN has no A record yet. Add an A record pointing at ${PUBLIC_IP:-the public IP of this server} at your DNS provider, then run this again in a few minutes"
fi
if [ -n "$PUBLIC_IP" ] && [ "$RESOLVED" != "$PUBLIC_IP" ]; then
    die "$DOMAIN resolves to $RESOLVED, not to this server's $PUBLIC_IP. Fix the A record, then run this again (with Cloudflare, set the proxy status to DNS only, the grey cloud)"
fi

say "Installing the newest patch release of Go $GO_LINE (skipped if already installed)"
export PATH=/usr/local/go/bin:$PATH
# The official release list: the newest stable release of the line, and the
# SHA-256 of its archive.
GO_RELEASES=$(curl -fsSL --max-time 60 'https://go.dev/dl/?mode=json&include=all') || die "cannot get the official list of Go releases"
GO_VERSION=$(jq -r --arg l "go$GO_LINE." 'first(.[] | select(.stable and (.version | startswith($l))) | .version) // empty' <<<"$GO_RELEASES")
[ -n "$GO_VERSION" ] || die "the official list of Go releases has no stable release of $GO_LINE"
GO_VERSION=${GO_VERSION#go}
if ! go version 2>/dev/null | grep -q "go$GO_VERSION "; then
    case "$(uname -m)" in
        x86_64) GOARCH=amd64 ;;
        aarch64) GOARCH=arm64 ;;
        *) die "unsupported CPU: $(uname -m)" ;;
    esac
    GO_FILE="go$GO_VERSION.linux-$GOARCH.tar.gz"
    # A directory of our own: nobody else can put a file in its place.
    GO_TMP=$(mktemp -d)
    curl -fsSL "https://go.dev/dl/$GO_FILE" -o "$GO_TMP/$GO_FILE" || die "downloading Go failed"
    GO_SHA256=$(jq -r --arg f "$GO_FILE" 'first(.[].files[] | select(.filename == $f) | .sha256) // empty' <<<"$GO_RELEASES")
    [ -n "$GO_SHA256" ] || die "the official list of Go releases has no $GO_FILE"
    echo "$GO_SHA256  $GO_TMP/$GO_FILE" | sha256sum -c --quiet - || die "the Go archive's SHA-256 is wrong; not installed"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TMP/$GO_FILE"
    rm -rf "$GO_TMP"
fi
go version

say "Building (a few minutes the first time)"
# Building Caddy needs about 2 GB of memory; small servers get a temporary
# swap file of their own, removed afterwards.
SWAP=""
cleanup_swap() {
    [ -n "$SWAP" ] || return 0
    if swapon --show=NAME --noheadings | grep -qxF "$SWAP" && ! swapoff "$SWAP"; then
        printf 'Note: turning off the temporary swap file %s failed, so it was not removed; you can remove it by hand after a reboot\n' "$SWAP"
        SWAP=""
        return 0
    fi
    rm -f "$SWAP"
    SWAP=""
}
# The build goes to a directory of our own (mode 700): in a shared /tmp, another
# user could replace the file between the build and its installation as root.
BUILD_DIR=$(mktemp -d)
cleanup() {
    cleanup_swap
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
if [ $((mem_kb + swap_kb)) -lt 2500000 ]; then
    echo "Little memory: adding 2 GB of temporary swap space for the build"
    SWAP=$(mktemp /caddy-build-XXXXXX.swap) # a new file, mode 600
    fallocate -l 2G "$SWAP" 2>/dev/null || dd if=/dev/zero of="$SWAP" bs=1M count=2048 status=none
    mkswap -q "$SWAP"
    swapon "$SWAP"
fi
(cd "$SRC" && GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BUILD_DIR/caddy" ./cmd/caddy)
cleanup_swap
install -m 755 "$BUILD_DIR/caddy" /usr/local/bin/caddy
caddy version

say "Ports"
# masque-vpn's own server, or another web server, would hold 443.
for unit in masque-server caddy nginx apache2; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        die "$unit is running and would hold ports 80/443. Stop it first: systemctl disable --now $unit"
    fi
done
for p in 80 443; do
    if ss -ltnH "sport = :$p" | grep -q . && ! systemctl is-active --quiet caddy-masque; then
        die "TCP port $p is in use ($(ss -ltnpH "sport = :$p" | head -1)); stop the program using it first"
    fi
done

say "Cover website"
if [ -f "$SITE/index.html" ]; then
    echo "$SITE/index.html already exists; kept"
else
    mkdir -p "$SITE"
    cat >"$SITE/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 40rem; margin: 15vh auto; padding: 0 1.5rem; color: #333; }
  h1 { font-weight: 600; }
  p { line-height: 1.6; color: #666; }
</style>
</head>
<body>
<h1>Welcome</h1>
<p>This site is under construction. Please check back later.</p>
</body>
</html>
EOF
    echo "Put a simple home page in place; to use your own pages, put the files in $SITE (with an index.html)"
fi

say "Configuration"
if [ -f "$CONFIG" ]; then
    echo "$CONFIG already exists; kept (with its users unchanged)"
    # The service puts Caddy's admin API on a socket only root can use
    # (CADDY_ADMIN in deploy/caddy-masque.service); an admin option here
    # replaces that.
    if grep -qE '^[[:space:]]*admin([[:space:]]|$)' "$CONFIG"; then
        echo "Note: $CONFIG sets Caddy's admin endpoint itself, so the service's root-only socket /run/caddy-masque/admin.sock is not used."
        echo "      Unless that endpoint is a unix socket only root can reach (or off), remove the admin line: on localhost:2019"
        echo "      every local user and process can read the configuration, password hashes included, and change it."
    fi
    # Earlier versions wrote the site for the domain only: clients that name
    # the server by its IP address (the Mac app's IP field) got no tunnel.
    if ! grep -qE '(^|[[:space:],]):443([[:space:],{]|$)' "$CONFIG"; then
        echo "Note: no site in $CONFIG answers for other host names, so clients that connect by IP address (the Mac app's IP field)"
        echo "      get no tunnel. Add ', :443' after the domain on the site's first line (for example: $DOMAIN, :443 {),"
        echo "      then: systemctl reload caddy-masque"
    fi
else
    IPV6_LINE="# ipv6 fd89:6d61:7371::1/64"
    # Offer IPv6 in the tunnel only when this server reaches the IPv6 Internet.
    if [ -d /proc/sys/net/ipv6 ] && ip -6 route show default | grep -q .; then
        IPV6_LINE="ipv6 fd89:6d61:7371::1/64"
    fi
    read -r HASH PASSWORD < <(caddy masque-passwd --name "$USER_NAME" |
        awk '/^user / {h=$3} /^password =/ {gsub(/"/, "", $3); p=$3} END {print h, p}')
    if [ -z "$HASH" ] || [ -z "$PASSWORD" ]; then die "creating the user failed"; fi
    mkdir -p /etc/caddy
    umask 077
    cat >"$CONFIG" <<EOF
# Caddy with the MASQUE VPN, written by deploy/install-server.sh.
# After changes: systemctl reload caddy-masque (tunnels stay up).
{
	masque {
		ipv4 10.89.0.1/24
		$IPV6_LINE
		# One line per device, from: caddy masque-passwd --name NAME
		user $USER_NAME $HASH
	}
}

# ":443" also answers HTTPS requests for any other host name, such as the
# server's IP address in a client's uri_template; no certificate is
# requested for it, clients check the certificate for $DOMAIN.
$DOMAIN, :443 {
	masque
	root * $SITE
	file_server
}
EOF
    cat >"$CREDENTIALS" <<EOF
MASQUE VPN, $(date '+%Y-%m-%d')
Server domain: $DOMAIN
Server IP:     ${PUBLIC_IP:-}
User name:     $USER_NAME
Password:      $PASSWORD
EOF
    chmod 600 "$CONFIG" "$CREDENTIALS"
    umask 022
fi
caddy validate --config "$CONFIG" >/dev/null 2>&1 ||
    { caddy validate --config "$CONFIG" || true; die "$CONFIG has errors; see the output above"; }

say "Firewall"
# A host firewall that drops forwarded packets makes the tunnel connect and
# carry nothing; open it for the tunnel's interface (the name in the default
# configuration).
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw allow 443/udp >/dev/null
    ufw route allow in on masque0 >/dev/null
    echo "ufw is running: opened TCP 80, TCP 443 and UDP 443, and allowed forwarding from masque0"
elif command -v iptables >/dev/null && iptables -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
    echo "Warning: the iptables FORWARD default policy is DROP (most likely set by Docker), so tunnel traffic will be dropped."
    echo "         Allow it with: iptables -I DOCKER-USER -i masque0 -j ACCEPT (without Docker: iptables -I FORWARD -i masque0 -j ACCEPT), and make the rule persist across reboots"
else
    echo "No firewall found that would block forwarding"
fi

say "Starting the service"
install -m 644 "$SRC/deploy/caddy-masque.service" /etc/systemd/system/caddy-masque.service
systemctl daemon-reload
systemctl enable --now caddy-masque
systemctl restart caddy-masque
sleep 3
if ! systemctl is-active --quiet caddy-masque; then
    journalctl -u caddy-masque -n 30 --no-pager -o cat
    die "caddy-masque did not start; see the log above for why"
fi

say "Checking (the first time, this waits for Caddy to get the certificate)"
ok=""
for _ in $(seq 30); do
    if curl -fsS --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" 2>/dev/null | grep -qi '<title>'; then
        ok=1
        break
    fi
    sleep 2
done
if [ -n "$ok" ]; then
    echo "Website OK: https://$DOMAIN/"
else
    echo "Warning: https://$DOMAIN/ did not return a web page from this server (most likely the certificate has not been issued yet); see the log: journalctl -u caddy-masque -n 50 -o cat"
fi
# The service keeps the forwarding and NAT rules in place (and puts them back
# if a firewall reload removes them); they must be there now.
if nft list table inet caddy-masque >/dev/null 2>&1 && [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]; then
    echo "Forwarding and NAT rules are in place"
else
    echo "Warning: the forwarding or NAT rules are missing (nft list table inet caddy-masque), so the tunnel will not carry traffic. See the log: journalctl -u caddy-masque -n 50 -o cat"
fi
ss -lunH 'sport = :443' | grep -q . && echo "UDP 443 (HTTP/3) is listening"
ss -ltnH 'sport = :443' | grep -q . && echo "TCP 443 (HTTP/2, HTTP/1.1) is listening"

say "Done"
cat <<EOF

Enter this in the client (MasqueVPN on the Mac, or masque-client):
$(if [ -f "$CREDENTIALS" ]; then sed -n '2,$p' "$CREDENTIALS"; else echo "  (the users are in the existing $CONFIG)"; fi)
  (The IP may be left out.)

This is also saved in $CREDENTIALS (readable only by root).

Also make sure the cloud provider's firewall (security group) allows:
  TCP 443, UDP 443 (VPN and website)  TCP 80 (getting and renewing the certificate)
Without UDP 443 it still works, but only over the slower TCP.

Useful commands:
  systemctl status caddy-masque              status
  journalctl -u caddy-masque -f -o cat       live log
  curl -s --unix-socket /run/caddy-masque/admin.sock http://localhost/metrics | grep caddy_masque
                                             live tunnels, traffic, failed logins (Prometheus format)
  caddy masque-passwd --name NEW_USER        add another user (one per device),
                                             add the user line it prints to $CONFIG,
                                             then systemctl reload caddy-masque
EOF

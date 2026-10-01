#!/usr/bin/env bash
# End-to-end test of Caddy with the masque app and handler, with the
# unchanged client of masque-vpn, in Linux network namespaces. Needs root,
# iproute2, nftables, curl, openssl, iperf3 and python3.
#
#   mq-cli  (client, 203.0.113.2)  ──┐
#   mq-cli2 (bad clients)          ──┤  mq-inet: router + target host
#   mq-srv  (Caddy, 198.51.100.2)  ──┘           192.0.2.80, 2001:db8:80::80
#
# IPv6 checks are skipped when the kernel has IPv6 disabled.
#
# A private CA made with openssl stands in for a public one; the clients are
# told to trust it through the test-only `ca` setting.
#
# Usage: sudo tests/e2e-netns.sh
#   CADDY       the Caddy binary with this module (default: built here)
#   CLIENT_BIN  masque-vpn's masque-client (default: ../masque-vpn/target/debug)
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/caddy-masque-e2e.XXXXXX)
CADDY=${CADDY:-}
if [ -z "$CADDY" ]; then
    CADDY=$WORK/caddy
    (cd "$ROOT" && go build -o "$CADDY" ./cmd/caddy) || { echo "building Caddy failed"; exit 1; }
fi
CLIENT_BIN=${CLIENT_BIN:-$ROOT/../masque-vpn/target/debug/masque-client}
[ -x "$CLIENT_BIN" ] || { echo "no masque-client at $CLIENT_BIN (set CLIENT_BIN)"; exit 1; }
NS_I=mq-inet NS_S=mq-srv NS_C=mq-cli NS_C2=mq-cli2 NS_L=mq-lan NS_L2=mq-lan2
TARGET=192.0.2.80 TARGET6=2001:db8:80::80
SERVER=198.51.100.2 SERVER6=2001:db8:5::2
CLIENT=203.0.113.2 CLIENT6=2001:db8:c::2
PASS=0 FAIL=0 SKIP=0
SERVER_PID="" CLIENT_PID=""
HAVE_V6=0
[ -d /proc/sys/net/ipv6 ] && HAVE_V6=1


in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

ok() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

# check "description" command...   passes when the command succeeds
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
# check_not "description" command...   passes when the command fails
check_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }
# IPv6 variants that are skipped when the kernel has IPv6 disabled
skip() { echo "  SKIP  $* (IPv6 is disabled on this host)"; SKIP=$((SKIP + 1)); }
check6() { if [ $HAVE_V6 = 1 ]; then check "$@"; else skip "$1"; fi; }
check6_not() { if [ $HAVE_V6 = 1 ]; then check_not "$@"; else skip "$1"; fi; }

# wait_log file pattern timeout [min_count]
wait_log() {
    local file=$1 pattern=$2 timeout=$3 min=${4:-1} i
    for ((i = 0; i < timeout * 5; i++)); do
        [ "$(grep -cE -- "$pattern" "$file" 2>/dev/null)" -ge "$min" ] && return 0
        sleep 0.2
    done
    return 1
}

cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    sleep 0.5
    for ns in $NS_L $NS_L2 $NS_C $NS_C2 $NS_S $NS_I; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
        ip netns del "$ns" 2>/dev/null
    done
    rm -rf "/etc/netns/$NS_L" "/etc/netns/$NS_L2" "/etc/netns/$NS_S"
    if [ "$FAIL" -ne 0 ]; then
        # The logs explain the failures; show them where only the output
        # can be seen, as on a CI server.
        for log in "$WORK"/*.log; do
            echo "== last lines of $log"
            tail -n 25 "$log"
        done
        echo "logs kept in $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# The target replies with the source address it sees: the client's own
# address means traffic went direct, the server's means it used the VPN.
seen_as() { in_ns $NS_C curl --noproxy "*" -s --max-time "${2:-3}" "http://$TARGET:8080/" | grep -qx "$1"; }
seen_as6() { in_ns $NS_C curl --noproxy "*" -s --max-time "${2:-3}" "http://[$TARGET6]:8080/" | grep -qx "$1"; }

echo "== topology"
for ns in $NS_I $NS_S $NS_C $NS_C2 $NS_L $NS_L2; do
    ip netns del "$ns" 2>/dev/null
    ip netns add "$ns"
    in_ns "$ns" ip link set lo up
done
link() { # link <ns-a> <if-a> <addr-a> <ns-b> <if-b> <addr-b>
    ip link add "$2" type veth peer name "$5"
    ip link set "$2" netns "$1"
    ip link set "$5" netns "$4"
    in_ns "$1" ip addr add "$3" dev "$2"
    in_ns "$4" ip addr add "$6" dev "$5"
    in_ns "$1" ip link set "$2" up
    in_ns "$4" ip link set "$5" up
}
link $NS_I i-srv 198.51.100.1/24 $NS_S s-wan $SERVER/24
link $NS_I i-cli 203.0.113.1/24 $NS_C c-wan $CLIENT/24
# The client's uplink is a LAN segment (a bridge in mq-inet) that a second
# device shares, for a gateway with one network card.
in_ns $NS_I ip link add br-cli type bridge
in_ns $NS_I ip addr del 203.0.113.1/24 dev i-cli
in_ns $NS_I ip link set i-cli master br-cli
in_ns $NS_I ip addr add 203.0.113.1/24 dev br-cli
in_ns $NS_I ip link set br-cli up
ip link add i-lan2 type veth peer name l2-eth
ip link set i-lan2 netns $NS_I
ip link set l2-eth netns $NS_L2
in_ns $NS_I ip link set i-lan2 master br-cli
in_ns $NS_I ip link set i-lan2 up
in_ns $NS_L2 ip addr add 203.0.113.9/24 dev l2-eth
in_ns $NS_L2 ip link set l2-eth up
in_ns $NS_L2 ip route add default via $CLIENT
mkdir -p "/etc/netns/$NS_L2"
echo "nameserver $CLIENT" >"/etc/netns/$NS_L2/resolv.conf"
link $NS_I i-cli2 203.0.114.1/24 $NS_C2 c2-wan 203.0.114.2/24
# A LAN behind the client machine, for gateway mode. The device's gateway
# and DNS server are the client machine.
link $NS_C c-lan 192.168.77.1/24 $NS_L l-eth 192.168.77.2/24
in_ns $NS_L ip route add default via 192.168.77.1
mkdir -p "/etc/netns/$NS_L"
echo "nameserver 192.168.77.1" >"/etc/netns/$NS_L/resolv.conf"
in_ns $NS_S ip route add default via 198.51.100.1
in_ns $NS_C ip route add default via 203.0.113.1
in_ns $NS_C2 ip route add default via 203.0.114.1
in_ns $NS_I ip addr add $TARGET/32 dev lo
in_ns $NS_I sysctl -qw net.ipv4.ip_forward=1
if [ $HAVE_V6 = 1 ]; then
    in_ns $NS_I sysctl -qw net.ipv6.conf.all.forwarding=1
    in_ns $NS_I ip -6 addr add $TARGET6/128 dev lo nodad
    in_ns $NS_I ip -6 addr add 2001:db8:5::1/64 dev i-srv nodad
    in_ns $NS_S ip -6 addr add $SERVER6/64 dev s-wan nodad
    in_ns $NS_S ip -6 route add default via 2001:db8:5::1
    in_ns $NS_I ip -6 addr add 2001:db8:c::1/64 dev br-cli nodad
    in_ns $NS_C ip -6 addr add $CLIENT6/64 dev c-wan nodad
    in_ns $NS_C ip -6 route add default via 2001:db8:c::1
fi

cat >"$WORK/whoami.py" <<'EOF'
import http.server, socket, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # /bytes/N sends N zero bytes; anything else, the client's address.
        if self.path.startswith("/bytes/"):
            n = int(self.path[7:])
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            chunk = bytes(65536)
            while n > 0:
                self.wfile.write(chunk[:min(n, len(chunk))])
                n -= len(chunk)
            return
        body = (self.client_address[0] + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
class S(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
S((sys.argv[1], 8080), H).serve_forever()
EOF
ip netns exec $NS_I python3 "$WORK/whoami.py" $TARGET &
[ $HAVE_V6 = 1 ] && ip netns exec $NS_I python3 "$WORK/whoami.py" $TARGET6 &

# DNS for SOCKS mode: target.test is the target; other names do not exist.
cat >"$WORK/dns.py" <<'EOF'
import socket, struct, sys
v4, v6 = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
def answer(q, peer):
    pos, labels = 12, []
    while q[pos]:
        n = q[pos]
        labels.append(q[pos + 1:pos + 1 + n].decode().lower())
        pos += 1 + n
    pos += 1
    qtype = struct.unpack("!H", q[pos:pos + 2])[0]
    rdata, rcode = None, 3
    if ".".join(labels) == "target.test":
        rcode = 0
        if qtype == 1:
            rdata = socket.inet_pton(socket.AF_INET, v4)
        elif qtype == 28 and v6:
            rdata = socket.inet_pton(socket.AF_INET6, v6)
    elif ".".join(labels) == "source.test" and qtype == 1:
        rcode = 0
        rdata = socket.inet_pton(socket.AF_INET, peer)
    r = q[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 1, 1 if rdata else 0, 0, 0) + q[12:pos + 4]
    if rdata:
        r += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return r
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((v4, 53))
while True:
    q, a = s.recvfrom(4096)
    s.sendto(answer(q, a[0]), a)
EOF
ip netns exec $NS_I python3 "$WORK/dns.py" $TARGET $([ $HAVE_V6 = 1 ] && echo $TARGET6) &
# UDP echo on port 7.
cat >"$WORK/udp_echo.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 7))
while True:
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
EOF
ip netns exec $NS_I python3 "$WORK/udp_echo.py" $TARGET &
[ $HAVE_V6 = 1 ] && ip netns exec $NS_I python3 "$WORK/udp_echo.py" $TARGET6 &
in_ns $NS_I iperf3 -s -B $TARGET -D
sleep 0.5


echo "== certificates, users and configuration"
PKI=$WORK/pki
mkdir -p "$PKI"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=Test Public CA" \
    -addext basicConstraints=critical,CA:TRUE -keyout "$PKI/ca.key" -out "$PKI/ca.pem" 2>/dev/null
# issue_server_cert <name>: a certificate for vpn.test and the server's IP,
# written as fullchain.pem and privkey.pem like certbot does.
issue_server_cert() {
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=vpn.test" \
        -keyout "$PKI/$1.key" -out "$PKI/$1.csr" 2>/dev/null
    printf 'subjectAltName=DNS:vpn.test,IP:%s\n' "$SERVER" >"$PKI/$1.ext"
    openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial -days 30 \
        -extfile "$PKI/$1.ext" -out "$PKI/$1.pem" 2>/dev/null
    cat "$PKI/$1.pem" "$PKI/ca.pem" >"$PKI/fullchain.pem"
    cp "$PKI/$1.key" "$PKI/privkey.pem"
}
issue_server_cert first

# new_user <name>: prints "<hash> <password>".
new_user() {
    "$CADDY" masque-passwd --name "$1" | awk '/^user / {h=$3} /^password =/ {gsub(/"/, "", $3); p=$3} END {print h, p}'
}
read -r LAPTOP_HASH LAPTOP_PW < <(new_user laptop)
read -r TABLET_HASH TABLET_PW < <(new_user tablet)

SITE="$WORK/site"
mkdir -p "$SITE"
printf '<!doctype html>\n<title>e2e cover page</title>\n<h1>hello</h1>\n' >"$SITE/index.html"
# write_server_config [users...] [-- extra masque options...]
POOL4=10.89.0.1/24
write_server_config() {
    local users=() extra=() u
    while [ $# -gt 0 ] && [ "$1" != -- ]; do users+=("$1"); shift; done
    [ $# -gt 0 ] && shift
    extra=("$@")
    {
        echo '{'
        echo "    storage file_system $WORK/caddy-data"
        echo '    masque {'
        echo "        ipv4 $POOL4"
        [ $HAVE_V6 = 1 ] && echo '        ipv6 fd89:6d61:7371::1/64'
        for u in "${users[@]}"; do
            case $u in
            laptop) echo "        user laptop $LAPTOP_HASH" ;;
            tablet) echo "        user tablet $TABLET_HASH" ;;
            esac
        done
        for u in "${extra[@]}"; do echo "        $u"; done
        echo '    }'
        echo '}'
        echo "https://vpn.test, https://$SERVER {"
        echo "    tls $PKI/fullchain.pem $PKI/privkey.pem"
        echo '    masque'
        echo "    root * $SITE"
        echo '    try_files {path} /index.html'
        echo '    file_server'
        echo '}'
    } >"$WORK/Caddyfile"
}
write_server_config laptop

client_config() { # $1 = file, $2 = user, $3 = password, then extra lines
    local file=$1 user=$2 password=$3
    shift 3
    cat >"$file" <<EOF
uri_template = "https://$SERVER:443/.well-known/masque/ip/{target}/{ipproto}/"
server_name = "vpn.test"
ca = "$PKI/ca.pem"
username = "$user"
password = "$password"
$(printf '%s\n' "$@")
EOF
    chmod 600 "$file"
}
client_config "$WORK/client.toml" laptop "$LAPTOP_PW"
client_config "$WORK/client-h2.toml" laptop "$LAPTOP_PW" 'transport = "h2"'
client_config "$WORK/client-h1.toml" laptop "$LAPTOP_PW" 'transport = "http/1.1"'
client_config "$WORK/client-scoped.toml" laptop "$LAPTOP_PW" "target = \"$TARGET\"" 'ipproto = "6"'
client_config "$WORK/client-named.toml" laptop "$LAPTOP_PW" 'target = "target.test"' 'transport = "h2"'
client_config "$WORK/client-noname.toml" laptop "$LAPTOP_PW" 'target = "nothing.test"'
client_config "$WORK/wrong-password.toml" laptop "not-the-password"
client_config "$WORK/unknown-user.toml" mallory "$LAPTOP_PW"
# The server's own name lookups (scoped requests by name) use the target's DNS.
mkdir -p "/etc/netns/$NS_S"
echo "nameserver $TARGET" >"/etc/netns/$NS_S/resolv.conf"

# Fetches from the server as an outside visitor (mq-cli2 has no tunnel);
# prints the response headers and body.
visit() {
    ip netns exec $NS_C2 curl --noproxy "*" -sS -i --max-time 5 --cacert "$PKI/ca.pem" --resolve "vpn.test:443:$SERVER" "$@" \
        2>>"$WORK/curl.err"
}
# The SHA-256 fingerprint of the certificate the server presents.
served_cert() {
    ip netns exec $NS_C2 openssl s_client -connect "$SERVER:443" -servername vpn.test </dev/null 2>/dev/null |
        openssl x509 -noout -fingerprint -sha256 2>/dev/null
}

# Caddy's home, config and data directories, inside the test's directory.
CADDY_ENV=(env HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/xdg-config" XDG_DATA_HOME="$WORK/xdg-data")
ready_count() { grep -c '"masque ready"' "$WORK/server.log" 2>/dev/null; }
start_server() { # waits for the next "masque ready"
    local want=$(($(ready_count) + 1))
    # `ip netns exec`, `exec` and `env` run in place, so $! is Caddy's own
    # PID. The soft open file limit starts at 1024, as under systemd.
    ip netns exec $NS_S bash -c 'ulimit -Sn 1024; exec "$@"' _ \
        "${CADDY_ENV[@]}" "$CADDY" run --config "$WORK/Caddyfile" --adapter caddyfile >>"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    wait_log "$WORK/server.log" '"masque ready"' 15 "$want"
}
# shellcheck disable=SC2120 # called with --force through check
reload_server() { # extra arguments go to caddy reload
    in_ns $NS_S "${CADDY_ENV[@]}" "$CADDY" reload --config "$WORK/Caddyfile" --adapter caddyfile "$@" >>"$WORK/reload.log" 2>&1
}
stop_server() {
    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=""
}

start_client() { # $1 = config, $2 = log
    ip netns exec $NS_C env RUST_LOG=info "$CLIENT_BIN" -c "$1" >"$2" 2>&1 &
    CLIENT_PID=$!
}

stop_client() {
    kill -TERM "$CLIENT_PID"
    wait "$CLIENT_PID" 2>/dev/null
    CLIENT_PID=""
}

echo "== the masque-passwd command"
check "prints a user line with an Argon2id hash" test "${LAPTOP_HASH:0:10}" = '$argon2id$'
check "and a 24-character password" test "${#LAPTOP_PW}" = 24
check "accepts a password on stdin" bash -c "echo 'a long enough password' | '$CADDY' masque-passwd --name x --stdin | grep -q '^user x \\\$argon2id'"
check_not "refuses a short one" bash -c "echo short | '$CADDY' masque-passwd --name x --stdin"
check_not "refuses a bad user name" "$CADDY" masque-passwd --name 'a b'

echo "== configuration checks"
caddy_validate() { "${CADDY_ENV[@]}" "$CADDY" validate --config "$1" --adapter caddyfile >"$WORK/validate.log" 2>&1; }
check "the test configuration is valid" caddy_validate "$WORK/Caddyfile"
bad_config() { # $1 = masque option line
    sed "s|^    masque {|    masque {\n        $1|" "$WORK/Caddyfile" >"$WORK/bad.Caddyfile"
    caddy_validate "$WORK/bad.Caddyfile"
}
check_not "an unknown option is refused" bad_config "bogus 1"
check_not "a bad password hash is refused" bad_config 'user eve $argon2id$v=19$nonsense'
check_not "a duplicate user is refused" bad_config "user laptop $LAPTOP_HASH"
check_not "an MTU below 1280 with IPv6 (or 576) is refused" bad_config "mtu 500"
check_not "a bad blocked prefix is refused" bad_config "block 10.0.0.0/33"
sed "s|ipv4 $POOL4|ipv4 10.89.0.0/24|" "$WORK/Caddyfile" >"$WORK/bad.Caddyfile"
check_not "an ipv4 that is not a host address is refused" caddy_validate "$WORK/bad.Caddyfile"
printf '{\n    storage file_system %s\n}\nhttps://vpn.test {\n    tls %s %s\n    masque\n}\n' \
    "$WORK/caddy-data" "$PKI/fullchain.pem" "$PKI/privkey.pem" >"$WORK/bad.Caddyfile"
check_not "the handler without the global option is refused" caddy_validate "$WORK/bad.Caddyfile"
check_not "validating never creates the TUN device" in_ns $NS_S ip link show masque0

echo "== before connecting"
check "target reachable directly (seen as the client)" seen_as $CLIENT
check6 "IPv6 target reachable directly (seen as the client)" seen_as6 $CLIENT6

echo "== connect (transport = auto, which is HTTP/3 here)"
check "Caddy starts" start_server
check "Caddy raises its open file limit" \
    awk '/Max open files/ { exit !($4 > 1024) }' "/proc/$SERVER_PID/limits"
check "Caddy serves HTTP/3 with datagrams on :443" grep -q '"serving HTTP/3 with HTTP datagrams".*:443' "$WORK/server.log"
check "the server lets its own ICMP errors out of the tunnel (accept_local)" \
    test "$(in_ns $NS_S sysctl -n net.ipv4.conf.masque0.accept_local 2>/dev/null)" = 1
start_client "$WORK/client.toml" "$WORK/client.log"
check "client brings the tunnel up over HTTP/3" wait_log "$WORK/client.log" 'tunnel up.*HTTP/3' 15
check "server logs the session" wait_log "$WORK/server.log" "session started" 5
if ! grep -q "tunnel up" "$WORK/client.log"; then
    echo "-- client log"; tail -n 20 "$WORK/client.log"
    echo "-- server log"; tail -n 20 "$WORK/server.log"
fi

echo "== traffic through the tunnel"
check "HTTP to target goes through the VPN (seen as the server)" seen_as $SERVER
check "ping target" in_ns $NS_C ping -c3 -i0.2 -W2 $TARGET
check "ping with 1300-byte payload" in_ns $NS_C ping -c2 -s1300 -W2 $TARGET
check "ping the tunnel gateway" in_ns $NS_C ping -c1 -W2 10.89.0.1
unreach=$(in_ns $NS_C ping -c1 -W2 10.1.2.3 2>&1)
if grep -qi unreachable <<<"$unreach"; then ok "blocked private destination is reported unreachable"; else bad "blocked private destination: $unreach"; fi
check6 "IPv6 to target goes through the VPN (seen as the server)" seen_as6 $SERVER6
check6 "ping IPv6 target with a 1232-byte payload (1280-byte packets)" in_ns $NS_C ping -6 -c2 -s1232 -W2 $TARGET6
check6 "ping the IPv6 tunnel gateway" in_ns $NS_C ping -6 -c1 -W2 fd89:6d61:7371::1
if in_ns $NS_C iperf3 -c $TARGET -t 5 -J >"$WORK/iperf.json" 2>&1; then
    mbps=$(python3 -c "import json;d=json.load(open('$WORK/iperf.json'));print(round(d['end']['sum_received']['bits_per_second']/1e6))")
    ok "iperf3 TCP through the tunnel: ${mbps} Mbit/s"
else
    bad "iperf3 through the tunnel"
fi


echo "== the website outsiders see"
TITLE='<title>e2e cover page</title>'
visit --http1.1 https://vpn.test/ >"$WORK/page-h1.txt"
check "the page is served over HTTP/1.1" grep -q "$TITLE" "$WORK/page-h1.txt"
check "HTTP/3 is advertised with Alt-Svc" grep -qi '^alt-svc: h3=":443"' "$WORK/page-h1.txt"
check "Caddy's Server header" grep -qi '^server: Caddy' "$WORK/page-h1.txt"
visit --http2 https://vpn.test/ >"$WORK/page-h2.txt"
check "the page is served over HTTP/2" grep -q "$TITLE" "$WORK/page-h2.txt"
visit https://vpn.test/no/such/page >"$WORK/page-missing.txt"
check "any path gets the page" grep -q "$TITLE" "$WORK/page-missing.txt"
visit --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: connect-ip' -H 'Capsule-Protocol: ?1' \
    'https://vpn.test/.well-known/masque/ip/*/*/' >"$WORK/page-connect.txt"
check "a CONNECT-IP upgrade without credentials gets the page" grep -q "$TITLE" "$WORK/page-connect.txt"
check_not "and is not upgraded" grep -qi '^upgrade:' "$WORK/page-connect.txt"
visit --http1.1 -u "mallory:wrong-password-123" -H 'Connection: Upgrade' -H 'Upgrade: connect-ip' \
    'https://vpn.test/.well-known/masque/ip/*/*/' >"$WORK/page-connect-bad.txt"
check "with wrong credentials too" grep -q "$TITLE" "$WORK/page-connect-bad.txt"
visit --http1.1 -u "laptop:$LAPTOP_PW" -H 'Connection: Upgrade' -H 'Upgrade: connect-ip' -H 'Content-Length: 0' \
    'https://vpn.test/.well-known/masque/ip/*/*/' >"$WORK/page-connect-content.txt"
check "an authenticated request with content headers gets 400" grep -q '^HTTP/1.1 400' "$WORK/page-connect-content.txt"
visit --http1.1 -u "laptop:$LAPTOP_PW" -H 'Connection: Upgrade' -H 'Upgrade: connect-ip' \
    'https://vpn.test/.well-known/masque/ip/nothing.test/*/' >"$WORK/page-connect-dns.txt"
check "a target name that does not resolve gets 502" grep -q '^HTTP/1.1 502' "$WORK/page-connect-dns.txt"
check "with Proxy-Status dns_error (RFC 9209)" grep -qi '^proxy-status: caddy-masque; error=dns_error' "$WORK/page-connect-dns.txt"
visit --http1.1 -u "laptop:$LAPTOP_PW" -H 'Connection: Upgrade' -H 'Upgrade: connect-ip' \
    'https://vpn.test/.well-known/masque/ip/10.1.2.0%2F24/*/' >"$WORK/page-connect-403.txt"
check "a target that is all blocked gets 403" grep -q '^HTTP/1.1 403' "$WORK/page-connect-403.txt"
visit --http1.1 -u "laptop:$LAPTOP_PW" -H 'Connection: Upgrade' -H 'Upgrade: connect-ip' \
    'https://vpn.test/.well-known/masque/ip/*/0/' >"$WORK/page-connect-ext.txt"
check "an IPv6 extension header as ipproto gets 400" grep -q '^HTTP/1.1 400' "$WORK/page-connect-ext.txt"

echo "== many connections at once"
# More TCP connections than the soft open file limit the server started
# with (1024, as under systemd), all held open while a visitor and the
# tunnel must keep working.
cat >"$WORK/hold.py" <<'EOF'
import socket, sys, time
held = []
for _ in range(int(sys.argv[2])):
    try:
        held.append(socket.create_connection((sys.argv[1], 443), timeout=3))
    except OSError:
        break
print(len(held), flush=True)
time.sleep(float(sys.argv[3]))
EOF
in_ns $NS_C2 bash -c 'ulimit -n 4096; exec python3 "$0" "$1" 1500 8' "$WORK/hold.py" $SERVER >"$WORK/hold.txt" &
HOLD_PID=$!
wait_log "$WORK/hold.txt" '^[0-9]+$' 10
check "1500 connections are held open" grep -qx 1500 "$WORK/hold.txt"
visit --http2 https://vpn.test/ >"$WORK/page-busy.txt"
check "the page is still served" grep -q "$TITLE" "$WORK/page-busy.txt"
check "the tunnel still carries traffic" seen_as $SERVER
check_not "the server never ran out of file descriptors" grep -qi "too many open files" "$WORK/server.log"
kill "$HOLD_PID" 2>/dev/null
wait "$HOLD_PID" 2>/dev/null


echo "== rejected clients"
in_ns $NS_C2 timeout 8 "$CLIENT_BIN" -c "$WORK/wrong-password.toml" >"$WORK/wrong-password.log" 2>&1
# The request goes to the website, which answers CONNECT with 405.
check "a wrong password is refused" grep -q "refused the CONNECT-IP request: 405" "$WORK/wrong-password.log"
check_not "a wrong password never brings a tunnel up" grep -q "tunnel up" "$WORK/wrong-password.log"
in_ns $NS_C2 timeout 8 "$CLIENT_BIN" -c "$WORK/unknown-user.toml" >"$WORK/unknown-user.log" 2>&1
check_not "an unknown user never brings a tunnel up" grep -q "tunnel up" "$WORK/unknown-user.log"
check "server logs the failed logins" wait_log "$WORK/server.log" 'authentication failed.*"user":"mallory"' 2
check "no leftover rules in the rejected clients' namespace" bash -c "! ip netns exec $NS_C2 ip rule | grep -q 51889"

echo "== a second instance"
# It cannot take the TUN device, and must not disturb the running one.
sed 's|^https://vpn.test, https://[0-9.]* {|https://vpn.test:8443 {|; s|^{|{\n    admin off\n    http_port 8080|' \
    "$WORK/Caddyfile" >"$WORK/second.Caddyfile"
in_ns $NS_S "${CADDY_ENV[@]}" timeout 15 "$CADDY" run --config "$WORK/second.Caddyfile" --adapter caddyfile >"$WORK/second-server.log" 2>&1
check "a start-up error ends Caddy with a non-zero status" test $? = 1
check "and names the cause" grep -q "creating TUN device masque0" "$WORK/second-server.log"
check "the running server is not disturbed" bash -c "kill -0 $SERVER_PID && ip netns exec $NS_S nft list table inet caddy-masque >/dev/null"
check "and its tunnel still carries traffic" seen_as $SERVER 5

echo "== certificate reload"
before=$(served_cert)
issue_server_cert second
# The Caddyfile is unchanged, so only a forced reload reads the files again.
check "caddy reload --force succeeds" reload_server --force
after=$(served_cert)
if [ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; then
    ok "new connections get the renewed certificate"
else
    bad "certificate did not change: '$before' / '$after'"
fi
check "the tunnel survives the reload" seen_as $SERVER 5
check_not "the client did not reconnect" wait_log "$WORK/client.log" "tunnel up" 1 2

echo "== server crash: no leak, then reconnect"
kill -9 "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null
check_not "while the server is down, traffic does not leak outside the tunnel" seen_as $CLIENT 2
check6_not "while the server is down, IPv6 does not leak either" seen_as6 $CLIENT6 2
check "server restarts" start_server
t0=$(date +%s)
check "client reconnects after the restart" wait_log "$WORK/client.log" "tunnel up" 45 2
echo "        (reconnected $(($(date +%s) - t0)) s after the server came back)"
check "traffic flows again after reconnecting" seen_as $SERVER 5

echo "== revocation"
write_server_config
reload_server
check "server ends the revoked session" wait_log "$WORK/server.log" "ending session: user removed" 5
check "revoked user is refused on reconnect" wait_log "$WORK/client.log" "refused the CONNECT-IP request: 405" 15
check_not "revoked user's traffic does not leak" seen_as $CLIENT 2
write_server_config laptop
reload_server
check "user is accepted again after re-adding" wait_log "$WORK/client.log" "tunnel up" 45 3
check "traffic flows after re-adding" seen_as $SERVER 5
stop_client

for t in h2:HTTP/2 h1:HTTP/1.1; do
    name=${t%%:*} proto=${t#*:}
    echo "== transport = $proto"
    start_client "$WORK/client-$name.toml" "$WORK/client-$name.log"
    check "tunnel up over $proto" wait_log "$WORK/client-$name.log" "tunnel up.*$proto" 15
    check "HTTP to target goes through the VPN" seen_as $SERVER 5
    check "ping with 1300-byte payload" in_ns $NS_C ping -c2 -s1300 -W2 $TARGET
    check6 "IPv6 to target goes through the VPN" seen_as6 $SERVER6 5
    if in_ns $NS_C iperf3 -c $TARGET -t 3 -J >"$WORK/iperf-$name.json" 2>&1; then
        mbps=$(python3 -c "import json;d=json.load(open('$WORK/iperf-$name.json'));print(round(d['end']['sum_received']['bits_per_second']/1e6))")
        ok "iperf3 TCP over $proto: ${mbps} Mbit/s"
    else
        bad "iperf3 over $proto"
    fi
    check "the tunnel survives a config reload" reload_server
    check "and still carries traffic" seen_as $SERVER 5
    check_not "without reconnecting" wait_log "$WORK/client-$name.log" "tunnel up" 1 2
    write_server_config
    reload_server
    # HTTP/1.1 gets the web page (200), the others 405 for CONNECT.
    check "removing the user ends the $proto session" wait_log "$WORK/client-$name.log" \
        "refused the CONNECT-IP request: 405|did not accept the CONNECT-IP request" 15
    write_server_config laptop
    reload_server
    stop_client
done

echo "== UDP blocked: auto falls back to TCP"
in_ns $NS_I nft -f - <<'EOF'
table inet mq-block {
    chain forward {
        type filter hook forward priority filter; policy accept;
        udp dport 443 drop
    }
}
EOF
start_client "$WORK/client.toml" "$WORK/client-fallback.log"
check "client reports HTTP/3 unavailable" wait_log "$WORK/client-fallback.log" "HTTP/3 unavailable" 15
check "tunnel up over HTTP/2" wait_log "$WORK/client-fallback.log" "tunnel up.*HTTP/2" 15
check "traffic flows over the fallback" seen_as $SERVER 5
stop_client
in_ns $NS_I nft delete table inet mq-block

echo "== scoped request (target = $TARGET, ipproto = 6)"
start_client "$WORK/client-scoped.toml" "$WORK/client-scoped.log"
check "tunnel up" wait_log "$WORK/client-scoped.log" "tunnel up" 15
check "server advertises one route" wait_log "$WORK/client-scoped.log" "routes=1" 1
check "TCP to the target goes through the VPN" seen_as $SERVER 5
check "only the target is routed into the tunnel" bash -c \
    "ip netns exec $NS_C ip route get $TARGET | grep -q masque0 && ! ip netns exec $NS_C ip route get 203.0.114.2 | grep -q masque0"
check "other destinations stay reachable directly" in_ns $NS_C ping -c1 -W2 203.0.114.2
check "ICMP to the target is allowed in any scope" in_ns $NS_C ping -c1 -W2 $TARGET
check_not "UDP to the target is not (ipproto = 6)" bash -c \
    "ip netns exec $NS_C python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'x',('$TARGET',7));print(s.recv(9))\""
stop_client

echo "== scoped request by name (target = target.test)"
start_client "$WORK/client-named.toml" "$WORK/client-named.log"
check "the server resolves the name: tunnel up" wait_log "$WORK/client-named.log" "tunnel up" 15
check "TCP to the name's address goes through the VPN" seen_as $SERVER 5
stop_client
start_client "$WORK/client-noname.toml" "$WORK/client-noname.log"
check "a name that does not resolve is refused" wait_log "$WORK/client-noname.log" "could not resolve the target host name" 15
stop_client

echo "== clients reaching each other"
client_config "$WORK/client-tablet-c2.toml" tablet "$TABLET_PW" 'ipv6 = false'
tunnel_address_in() { in_ns "$1" ip -4 -o addr show dev masque0 | awk '{ sub("/.*", "", $4); print $4 }'; }
write_server_config laptop tablet
reload_server
start_client "$WORK/client.toml" "$WORK/client-c2c.log"
ip netns exec $NS_C2 env RUST_LOG=info "$CLIENT_BIN" -c "$WORK/client-tablet-c2.toml" >"$WORK/client-tablet-c2.log" 2>&1 &
TABLET_PID=$!
check "two clients are up" bash -c "$(declare -f wait_log); wait_log '$WORK/client-c2c.log' 'tunnel up' 15 && wait_log '$WORK/client-tablet-c2.log' 'tunnel up' 15"
LAPTOP_ADDR=$(tunnel_address_in $NS_C)
check_not "by default, one cannot reach the other ($LAPTOP_ADDR)" in_ns $NS_C2 ping -c1 -W2 "$LAPTOP_ADDR"
write_server_config laptop tablet -- allow_client_to_client
reload_server
# Running sessions get the new routes; nobody reconnects.
check "with allow_client_to_client after a reload, it can" bash -c \
    "for i in \$(seq 10); do ip netns exec $NS_C2 ping -c1 -W1 $LAPTOP_ADDR >/dev/null 2>&1 && exit 0; sleep 0.5; done; exit 1"
check "the server advertised the new routes" grep -q "more routes with the new configuration" "$WORK/server.log"
check_not "without reconnecting" wait_log "$WORK/client-c2c.log" "tunnel up" 1 2
write_server_config laptop tablet -- 'block 192.0.2.0/24'
reload_server
# Routes the tunnels were given stay while they are open (RFC 9484 §4): the
# server closes them, and the clients reconnect to the new routes.
check "routes withdrawn by a reload close the tunnels" \
    wait_log "$WORK/server.log" "the new configuration withdraws routes of the tunnel" 5
check "the client reconnects" wait_log "$WORK/client-c2c.log" "tunnel up" 20 2
check "and the newly blocked destination is unreachable" bash -c \
    "! ip netns exec $NS_C curl --noproxy '*' -s --max-time 3 http://$TARGET:8080/"
kill -TERM "$TABLET_PID"; wait "$TABLET_PID" 2>/dev/null
stop_client
write_server_config laptop
reload_server

echo "== an idle HTTP/2 tunnel (Caddy's default idle timeouts are one minute)"
start_client "$WORK/client-h2.toml" "$WORK/client-h2-idle.log"
check "tunnel up over HTTP/2" wait_log "$WORK/client-h2-idle.log" "tunnel up.*HTTP/2" 15
sleep 70
check "after 70 s without traffic it still carries traffic" seen_as $SERVER 5
check_not "without reconnecting" wait_log "$WORK/client-h2-idle.log" "tunnel up" 1 2
stop_client

echo "== client shutdown cleans up"
check_not "tunnel interface removed" in_ns $NS_C ip link show masque0
check_not "policy routing rules removed" bash -c "ip netns exec $NS_C ip rule | grep -q 51889"
check6_not "IPv6 policy routing rules removed" bash -c "ip netns exec $NS_C ip -6 rule | grep -q 51889"
check "direct connectivity restored" seen_as $CLIENT
check6 "direct IPv6 connectivity restored" seen_as6 $CLIENT6

echo "== SOCKS mode: only programs that use the proxy"
# A SOCKS5 client for UDP ASSOCIATE: sends one datagram, prints the answer.
cat >"$WORK/socks_udp.py" <<'EOF'
import socket, struct, sys
proxy, port, dst, dport, msg = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5].encode()
c = socket.create_connection((proxy, port), timeout=5)
c.sendall(b"\x05\x01\x00")
assert c.recv(2) == b"\x05\x00"
c.sendall(b"\x05\x03\x00\x01" + bytes(6))
r = b""
while len(r) < 10:
    r += c.recv(10 - len(r))
assert r[1] == 0, "reply %d" % r[1]
relay = (socket.inet_ntoa(r[4:8]), struct.unpack("!H", r[8:10])[0])
try:
    to = b"\x01" + socket.inet_aton(dst)
except OSError:
    to = b"\x03" + bytes([len(dst)]) + dst.encode()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(5)
u.sendto(b"\x00\x00\x00" + to + struct.pack("!H", dport) + msg, relay)
d, _ = u.recvfrom(4096)
off = 4 + (4 if d[3] == 1 else 16) + 2
print(d[off:].decode())
EOF
# Its own directory, readable by the unprivileged user that runs it.
mkdir -p "$WORK/socks"
chmod 711 "$WORK"
client_config "$WORK/socks/client.toml" laptop "$LAPTOP_PW" 'mode = "socks"' "dns = [\"$TARGET\"]" \
    '[socks]' 'listen = ["127.0.0.1:1080"]'
chown -R 65534:65534 "$WORK/socks"
ip netns exec $NS_C setpriv --reuid=65534 --regid=65534 --clear-groups env RUST_LOG=info \
    "$CLIENT_BIN" -c "$WORK/socks/client.toml" >"$WORK/client-socks.log" 2>&1 &
CLIENT_PID=$!
check "the SOCKS client runs without root" wait_log "$WORK/client-socks.log" "tunnel up" 15
check "and listens on 127.0.0.1:1080" grep -q "SOCKS5 proxy on 127.0.0.1:1080" "$WORK/client-socks.log"
check_not "no tunnel interface on the machine" in_ns $NS_C ip link show masque0
check_not "no policy routing rules" bash -c "ip netns exec $NS_C ip rule | grep -q 51889"
check "programs that do not use the proxy go direct" seen_as $CLIENT
# curl with an explicit proxy; the environment's proxy settings must not interfere.
socks_curl() { in_ns $NS_C env -u NO_PROXY -u no_proxy curl -s --max-time "${SOCKS_TIMEOUT:-5}" -x "socks5h://127.0.0.1:1080" "$@"; }
socks_sees() { socks_curl "$2" | grep -Eqx "$1"; }
check "by IPv4 address through the proxy: the target sees the server" socks_sees $SERVER "http://$TARGET:8080/"
# With IPv6 in the tunnel, the name's IPv6 address is tried first.
check "by name, resolved through the tunnel" socks_sees "$SERVER|$SERVER6" "http://target.test:8080/"
check6 "by IPv6 address" socks_sees $SERVER6 "http://[$TARGET6]:8080/"
check_not "an unknown name fails" socks_curl "http://nothing.test:8080/"
check_not "private destinations are refused" socks_curl "http://10.1.2.3:8080/"
check "UDP ASSOCIATE to an address" bash -c \
    "ip netns exec $NS_C python3 $WORK/socks_udp.py 127.0.0.1 1080 $TARGET 7 hello-udp | grep -qx hello-udp"
check "UDP ASSOCIATE to a name" bash -c \
    "ip netns exec $NS_C python3 $WORK/socks_udp.py 127.0.0.1 1080 target.test 7 by-name | grep -qx by-name"
stats=$(SOCKS_TIMEOUT=60 socks_curl -o /dev/null -w '%{size_download} %{time_total} %{speed_download}' \
    "http://$TARGET:8080/bytes/100000000")
code=$?
if [ $code = 0 ]; then
    ok "download through the proxy: $(python3 -c "print(round(${stats##* } * 8 / 1e6))") Mbit/s"
else
    bad "download through the proxy (curl exit $code; bytes, seconds, bytes/s: $stats)"
fi
stop_client
check "the SOCKS client exits cleanly" grep -q "disconnected" "$WORK/client-socks.log"

echo "== LAN gateway: devices behind the client machine"
# A DNS query from the LAN device: prints the rcode, answer count and addresses.
cat >"$WORK/dnsq.py" <<'EOF'
import random, socket, struct, sys
server, name, qtype = sys.argv[1], sys.argv[2], {"A": 1, "AAAA": 28}[sys.argv[3]]
q = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(q, (server, 53))
r, _ = s.recvfrom(4096)
an = struct.unpack("!H", r[6:8])[0]
pos = 12
while r[pos]:
    pos += 1 + r[pos]
pos += 5
addrs = []
for _ in range(an):
    if r[pos] & 0xC0 == 0xC0:
        pos += 2
    else:
        while r[pos]:
            pos += 1 + r[pos]
        pos += 1
    t, c, ttl, l = struct.unpack("!HHIH", r[pos:pos + 10])
    pos += 10
    if t == 1:
        addrs.append(socket.inet_ntoa(r[pos:pos + 4]))
    elif t == 28:
        addrs.append(socket.inet_ntop(socket.AF_INET6, r[pos:pos + 16]))
    pos += l
print("rcode=%d answers=%d %s" % (r[3] & 15, an, " ".join(addrs)))
EOF
lan_curl() { in_ns $NS_L curl --noproxy "*" -s --max-time "${LAN_TIMEOUT:-5}" "$@"; }
lan_sees() { lan_curl "$2" | grep -qx "$1"; }
dns_says() { in_ns $NS_L python3 "$WORK/dnsq.py" "$1" "$2" "$3" | grep -q -- "$4"; }
check_not "without the client, the LAN device has no Internet" lan_curl "http://$TARGET:8080/"
client_config "$WORK/client-gw.toml" laptop "$LAPTOP_PW" 'ipv6 = false' "dns = [\"$TARGET\"]" \
    '[gateway]' 'interface = "c-lan"'
start_client "$WORK/client-gw.toml" "$WORK/client-gw.log"
check "the client comes up as a LAN gateway" wait_log "$WORK/client-gw.log" "LAN gateway ready" 10
check "and brings the tunnel up" wait_log "$WORK/client-gw.log" "tunnel up" 15
check "with IPv4 only (ipv6 = false)" bash -c "grep 'tunnel up' '$WORK/client-gw.log' | grep -vq 'fd89:'"
check "the LAN device reaches the Internet through the VPN" lan_sees $SERVER "http://$TARGET:8080/"
check "by name, through the gateway's DNS forwarder" lan_sees $SERVER "http://target.test:8080/"
check "DNS to another server is answered by the forwarder" dns_says 8.8.8.8 target.test A "answers=1 $TARGET"
check "AAAA queries get no records (no IPv6 for the LAN)" dns_says 192.168.77.1 target.test AAAA "rcode=0 answers=0"
check "unknown names get NXDOMAIN" dns_says 192.168.77.1 nothing.test A "rcode=3"
check "upstream DNS sees the VPN server as source" dns_says 192.168.77.1 source.test A "answers=1 $SERVER"
# The ordinary policy keeps local main-table routes. DNS must still use
# the tunnel even if the administrator has such a route to its upstream.
in_ns $NS_C ip route add $TARGET/32 via 203.0.113.1 dev c-wan
check "a main-table upstream route cannot leak gateway DNS" dns_says 192.168.77.1 source.test A "answers=1 $SERVER"
in_ns $NS_C ip route del $TARGET/32 via 203.0.113.1 dev c-wan
check "the gateway machine itself also uses the VPN" seen_as $SERVER
if stats=$(LAN_TIMEOUT=60 lan_curl -o /dev/null -w '%{size_download} %{speed_download}' "http://$TARGET:8080/bytes/100000000") &&
    [ "${stats%% *}" = 100000000 ]; then
    ok "LAN device download through the gateway: $(python3 -c "print(round(${stats##* } * 8 / 1e6))") Mbit/s"
else
    bad "LAN device download through the gateway ($stats)"
fi
if [ $HAVE_V6 = 1 ]; then
    in_ns $NS_C ip -6 addr add fd77::1/64 dev c-lan nodad
    in_ns $NS_L ip -6 addr add fd77::2/64 dev l-eth nodad
    in_ns $NS_L ip -6 route add default via fd77::1
    in_ns $NS_C sysctl -qw net.ipv6.conf.all.forwarding=1
fi
check6_not "IPv6 from the LAN is not forwarded, even with IPv6 forwarding on" in_ns $NS_L ping -6 -c1 -W2 $TARGET6
stop_client
check "the gateway rules stay after the client exits" in_ns $NS_C nft list table inet masque-gateway
check_not "so the LAN device stays offline" lan_curl "http://$TARGET:8080/"
check_not "the DNS listener is closed before routes are removed" dns_says 192.168.77.1 source.test A "answers=1"
check "while the gateway machine itself goes direct again" seen_as $CLIENT
start_client "$WORK/client.toml" "$WORK/client-nogw.log"
check "without [gateway], the client removes the rules" wait_log "$WORK/client-nogw.log" "removed the LAN gateway rules" 10
check_not "the table is gone" in_ns $NS_C nft list table inet masque-gateway
stop_client

echo "== LAN gateway with one network card (the uplink is the LAN)"
# As after a reboot: nothing forwards until the client sets it up.
in_ns $NS_C sysctl -qw net.ipv4.ip_forward=0
lan2_sees() { in_ns $NS_L2 curl --noproxy "*" -s --max-time 5 "$2" | grep -qx "$1"; }
check_not "without the client, the device has no Internet" in_ns $NS_L2 curl --noproxy "*" -s --max-time 3 "http://$TARGET:8080/"
# No interface given: the one of the default route (c-wan) is used.
client_config "$WORK/client-gw1.toml" laptop "$LAPTOP_PW" 'ipv6 = false' "dns = [\"$TARGET\"]" '[gateway]'
start_client "$WORK/client-gw1.toml" "$WORK/client-gw1.log"
check "without [gateway] interface, the default route's is used" \
    wait_log "$WORK/client-gw1.log" "using the interface of the default route.*c-wan" 10
check "the client comes up as a gateway on its uplink" wait_log "$WORK/client-gw1.log" "tunnel up" 15
check "the device reaches the Internet through the VPN" lan2_sees $SERVER "http://$TARGET:8080/"
check "by name, through the gateway's DNS forwarder" lan2_sees $SERVER "http://target.test:8080/"
check "the gateway machine itself also uses the VPN" seen_as $SERVER
stop_client
check_not "after the client exits, the device stays offline" in_ns $NS_L2 curl --noproxy "*" -s --max-time 3 "http://$TARGET:8080/"
start_client "$WORK/client-gw1.toml" "$WORK/client-gw1-crash.log"
check "the gateway comes back" wait_log "$WORK/client-gw1-crash.log" "tunnel up" 15
check "and the device is online again" lan2_sees $SERVER "http://$TARGET:8080/"
kill -KILL "$CLIENT_PID"
wait "$CLIENT_PID" 2>/dev/null
CLIENT_PID=""
check_not "after the client crashes, the device stays offline" in_ns $NS_L2 curl --noproxy "*" -s --max-time 3 "http://$TARGET:8080/"

echo "== server shutdown cleans up"
start_client "$WORK/client-h2.toml" "$WORK/client-h2-shutdown.log"
check "an HTTP/2 tunnel is up" wait_log "$WORK/client-h2-shutdown.log" "tunnel up" 15
t0=$(date +%s)
stop_server
check "Caddy exits promptly with a tunnel open" test $(($(date +%s) - t0)) -lt 10
check_not "nftables table removed" in_ns $NS_S nft list table inet caddy-masque
check_not "server tunnel interface removed" in_ns $NS_S ip link show masque0
stop_client

echo "== a returned address and its old connections"
# The server's connection tracking keeps a session's NAT state after the
# session ends, so packets for its connections still arrive. A returned
# address goes to another user only after every never-used one, so they
# must not reach the next user.
cat >"$WORK/pusher.py" <<'EOF'
import socket, sys, threading, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 9999))
def push(a):
    for _ in range(300):
        s.sendto(b"stale", a)
        time.sleep(0.2)
while True:
    _, a = s.recvfrom(64)
    threading.Thread(target=push, args=(a,), daemon=True).start()
EOF
ip netns exec $NS_I python3 "$WORK/pusher.py" $TARGET &
cat >"$WORK/listen.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 40000))
if len(sys.argv) > 2:
    s.sendto(b"hello", (sys.argv[2], 9999))
s.settimeout(float(sys.argv[1]))
try:
    print(s.recvfrom(64)[0].decode())
except socket.timeout:
    pass
EOF
# heard <seconds> [target]: what arrives for UDP port 40000, after first
# sending from that port to the target's pusher if one is given.
heard() { in_ns $NS_C python3 "$WORK/listen.py" "$@"; }
tunnel_address() { in_ns $NS_C ip -4 -o addr show dev masque0 | awk '{ sub("/.*", "", $4); print $4 }'; }
POOL4=10.89.0.1/29 write_server_config laptop tablet
client_config "$WORK/client-laptop4.toml" laptop "$LAPTOP_PW" 'ipv6 = false'
client_config "$WORK/client-tablet4.toml" tablet "$TABLET_PW" 'ipv6 = false'
check "server starts with a small address pool" start_server
start_client "$WORK/client-laptop4.toml" "$WORK/client-laptop4.log"
check "the first user's tunnel comes up" wait_log "$WORK/client-laptop4.log" "tunnel up" 15
FIRST=$(tunnel_address)
check "a connection of the first user gets packets" test "$(heard 3 $TARGET)" = stale
stop_client
start_client "$WORK/client-tablet4.toml" "$WORK/client-tablet4.log"
check "the next user's tunnel comes up" wait_log "$WORK/client-tablet4.log" "tunnel up" 15
SECOND=$(tunnel_address)
check "the next user gets another address ($FIRST, then $SECOND)" test -n "$SECOND" -a "$FIRST" != "$SECOND"
check "and none of the first user's packets" test -z "$(heard 3)"
stop_client
stop_server

echo "== a reused address (the pool has one address) and a server crash"
# When the address must be reused, the server deletes the earlier user's
# connection tracking entries first; after a crash, the next run deletes
# those the crashed run left.
POOL4=10.89.0.1/30 write_server_config laptop tablet
check "server starts with a one-address pool" start_server
start_client "$WORK/client-laptop4.toml" "$WORK/client-laptop5.log"
check "the first user's tunnel comes up" wait_log "$WORK/client-laptop5.log" "tunnel up" 15
ONLY=$(tunnel_address)
check "a connection of the first user gets packets" test "$(heard 3 $TARGET)" = stale
stop_client
start_client "$WORK/client-tablet4.toml" "$WORK/client-tablet5.log"
check "the next user's tunnel comes up" wait_log "$WORK/client-tablet5.log" "tunnel up" 15
check "with the same address, the only one ($ONLY)" test "$(tunnel_address)" = "$ONLY"
check "and none of the first user's packets" test -z "$(heard 3)"
check "a connection of the next user gets packets" test "$(heard 3 $TARGET)" = stale
stop_client
kill -KILL "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""
deleted=$(grep -c "deleted connection tracking entries of the tunnel addresses" "$WORK/server.log")
check "after a crash, the server starts again" start_server
check "and deletes the crashed run's connection tracking entries" \
    test "$(grep -c "deleted connection tracking entries of the tunnel addresses" "$WORK/server.log")" -gt "$deleted"
start_client "$WORK/client-laptop4.toml" "$WORK/client-laptop6.log"
check "the first user's tunnel comes up again" wait_log "$WORK/client-laptop6.log" "tunnel up" 15
check "with the same address" test "$(tunnel_address)" = "$ONLY"
check "and none of the other user's packets" test -z "$(heard 3)"
stop_client
stop_server

echo
echo "$PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]

#!/usr/bin/env bash
# Run only on a disposable systemd VM. Tests the real service and installer;
# external IP/DNS discovery is stubbed and a local CA replaces public ACME.
set -euo pipefail
[[ ${MASQUE_TEST_SYSTEMD:-} == 1 ]] || { echo 'requires MASQUE_TEST_SYSTEMD=1 on a disposable VM' >&2; exit 1; }
[[ $(id -u) == 0 ]] || { echo 'requires root' >&2; exit 1; }
SOURCE=$(cd "$(dirname "$0")/.." && pwd)
CANDIDATE=$(realpath -- "${1:?usage: systemd-smoke.sh COMBINED_CADDY}")
for path in /usr/local/bin/caddy /usr/local/bin/caddy-smoke-good /etc/caddy /etc/systemd/system/caddy-masque.service /root/masque-credentials.txt /var/www/site; do
    [[ ! -e $path ]] || { echo "refusing to overwrite $path" >&2; exit 1; }
done
if nft list table inet caddy-masque >/dev/null 2>&1; then
    echo 'refusing to overwrite existing MASQUE networking' >&2
    exit 1
fi
WORK=$(mktemp -d)
FORWARDING=$(cat /proc/sys/net/ipv4/ip_forward)
cleanup() {
    systemctl stop caddy-masque 2>/dev/null || true
    systemctl disable caddy-masque 2>/dev/null || true
    rm -f /etc/systemd/system/caddy-masque.service /usr/local/bin/caddy /usr/local/bin/caddy-smoke-good
    systemctl daemon-reload
    rm -rf -- /etc/caddy /var/www/site "$WORK"
}
trap cleanup EXIT
install -m 755 "$CANDIDATE" /usr/local/bin/caddy
install -m 755 "$CANDIDATE" /usr/local/bin/caddy-smoke-good
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<'EOF'
{
    masque {
        interface masque-smoke
        ipv4 10.254.248.1/29
        user smoke $argon2id$v=19$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8
    }
}
localhost, :443 {
    tls internal
    masque
    respond "<title>Production smoke</title>"
}
EOF
chmod 600 /etc/caddy/Caddyfile
install -m 644 "$SOURCE/deploy/caddy-masque.service" /etc/systemd/system/caddy-masque.service
systemd-analyze verify /etc/systemd/system/caddy-masque.service
systemctl daemon-reload
systemctl start caddy-masque
website() {
    for _ in $(seq 30); do
        if curl --noproxy '*' --cacert /var/lib/caddy/pki/authorities/local/root.crt \
            --connect-timeout 1 --max-time 2 -fsS https://localhost/ 2>/dev/null | grep -q 'Production smoke'; then
            return 0
        fi
        sleep 0.2
    done
    journalctl -u caddy-masque -n 30 --no-pager >&2
    return 1
}
website
[[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]]
nft list table inet caddy-masque >/dev/null
[[ $(stat -c %a /run/caddy-masque/admin.sock) == 600 ]]
[[ $(systemctl show -p RuntimeDirectoryPreserve --value caddy-masque) == yes ]]
runtime_identity=$(stat -c '%d:%i' /run/caddy-masque)
systemctl reload caddy-masque
website
systemctl restart caddy-masque
website
[[ $(stat -c '%d:%i' /run/caddy-masque) == "$runtime_identity" ]]

# Exercise the installer with its real filesystem paths and service calls.
# Stub only public-IP discovery and DNS, avoiding public ACME or DNS writes.
mkdir "$WORK/bin"
cat > "$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *https://api.ipify.org*|*https://ip.sb*) printf '127.0.0.1\n';;
    *) exec /usr/bin/curl --cacert /var/lib/caddy/pki/authorities/local/root.crt "$@";;
esac
EOF
cat > "$WORK/bin/dig" <<'EOF'
#!/usr/bin/env bash
printf '127.0.0.1\n'
EOF
cat > "$WORK/startup-failure" <<'EOF'
#!/usr/bin/env bash
if [[ $1 == run ]]; then exit 42; fi
exec /usr/local/bin/caddy-smoke-good "$@"
EOF
chmod 755 "$WORK/bin/curl" "$WORK/bin/dig" "$WORK/startup-failure"
export MASQUE_TEST_UFW_LOG="$WORK/ufw.log"
cat > "$WORK/bin/ufw" <<'EOF'
#!/usr/bin/env bash
if [[ $1 == status ]]; then
    printf 'Status: active\n'
else
    printf '%s\n' "$*" >> "$MASQUE_TEST_UFW_LOG"
fi
EOF
chmod 755 "$WORK/bin/ufw"
if ! PATH="$WORK/bin:$PATH" CADDY_BIN="$CANDIDATE" bash "$SOURCE/deploy/install-server.sh" localhost > "$WORK/install.log" 2>&1; then
    tail -40 "$WORK/install.log" >&2
    exit 1
fi
grep -qxF 'route allow in on masque-smoke' "$MASQUE_TEST_UFW_LOG"
website
before=$(sha256sum /usr/local/bin/caddy)
if PATH="$WORK/bin:$PATH" CADDY_BIN="$WORK/startup-failure" bash "$SOURCE/deploy/install-server.sh" localhost > "$WORK/rollback.log" 2>&1; then
    echo 'startup-failing candidate unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'restoring the previous Caddy binary' "$WORK/rollback.log"
[[ $(sha256sum /usr/local/bin/caddy) == "$before" ]]
systemctl is-active --quiet caddy-masque
website
systemctl stop caddy-masque
[[ -d /run/caddy-masque ]]
[[ $(stat -c '%d:%i' /run/caddy-masque) == "$runtime_identity" ]]
[[ $(cat /proc/sys/net/ipv4/ip_forward) == "$FORWARDING" ]]
if nft list table inet caddy-masque >/dev/null 2>&1; then
    echo 'firewall table survived service stop' >&2
    exit 1
fi
if ip link show masque-smoke >/dev/null 2>&1; then
    echo 'TUN device survived service stop' >&2
    exit 1
fi
echo 'Real systemd lifecycle, installer startup rollback, and custom-interface UFW command passed'

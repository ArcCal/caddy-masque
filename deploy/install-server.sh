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
GO_VERSION=$(sed -n 's/^go \([0-9.]*\)$/\1/p' "$SRC/go.mod")

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31m错误：%s\033[0m\n' "$*" >&2; exit 1; }

[ -n "$DOMAIN" ] || die "用法：bash deploy/install-server.sh 你的域名 [用户名]"
[ "$(id -u)" = 0 ] || die "请用 root 运行（先执行 sudo -i）"
if [ ! -f "$SRC/go.mod" ] || ! grep -q caddy-masque "$SRC/go.mod"; then die "请在 caddy-masque 源码目录里运行"; fi
. /etc/os-release
case "$ID" in
    debian | ubuntu) ;;
    *) die "只支持 Debian 和 Ubuntu，这台是 $PRETTY_NAME" ;;
esac

say "安装系统软件"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q curl ca-certificates nftables iproute2 dnsutils jq

say "检查域名 $DOMAIN 是否指向这台服务器"
PUBLIC_IP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || curl -4 -fsS --max-time 10 https://ip.sb || true)
RESOLVED=$(dig +short A "$DOMAIN" @1.1.1.1 | tail -1)
echo "本机公网 IPv4：${PUBLIC_IP:-未知}；$DOMAIN 解析到：${RESOLVED:-（没有 A 记录）}"
if [ -z "$RESOLVED" ]; then
    die "$DOMAIN 还没有 A 记录。先在域名服务商那里加一条 A 记录指向 ${PUBLIC_IP:-本机公网 IP}，几分钟后再运行"
fi
if [ -n "$PUBLIC_IP" ] && [ "$RESOLVED" != "$PUBLIC_IP" ]; then
    die "$DOMAIN 解析到 $RESOLVED，不是本机的 $PUBLIC_IP。改好 A 记录后再运行（用了 Cloudflare 的话，代理状态要设成仅 DNS，灰色云朵）"
fi

say "安装 Go $GO_VERSION（已安装就跳过）"
export PATH=/usr/local/go/bin:$PATH
if ! go version 2>/dev/null | grep -q "go$GO_VERSION"; then
    case "$(uname -m)" in
        x86_64) GOARCH=amd64 ;;
        aarch64) GOARCH=arm64 ;;
        *) die "不支持的 CPU：$(uname -m)" ;;
    esac
    GO_FILE="go$GO_VERSION.linux-$GOARCH.tar.gz"
    # A directory of our own: nobody else can put a file in its place.
    GO_TMP=$(mktemp -d)
    curl -fsSL "https://go.dev/dl/$GO_FILE" -o "$GO_TMP/$GO_FILE" || die "下载 Go 失败"
    # The SHA-256 from the official release list.
    GO_SHA256=$(curl -fsSL --max-time 60 'https://go.dev/dl/?mode=json&include=all' |
        jq -r --arg f "$GO_FILE" 'first(.[].files[] | select(.filename == $f) | .sha256) // empty') ||
        die "取不到 Go 的官方校验值"
    [ -n "$GO_SHA256" ] || die "Go 的官方发布列表里没有 $GO_FILE"
    echo "$GO_SHA256  $GO_TMP/$GO_FILE" | sha256sum -c --quiet - || die "Go 安装包的 SHA-256 不对，没有安装"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TMP/$GO_FILE"
    rm -rf "$GO_TMP"
fi
go version

say "编译（第一次要几分钟）"
# Building Caddy needs about 2 GB of memory; small servers get a temporary
# swap file of their own, removed afterwards.
SWAP=""
cleanup_swap() {
    [ -n "$SWAP" ] || return 0
    if swapon --show=NAME --noheadings | grep -qxF "$SWAP" && ! swapoff "$SWAP"; then
        printf '注意：临时交换文件 %s 停用失败，没有删除；重启后可以手动删掉它\n' "$SWAP"
        SWAP=""
        return 0
    fi
    rm -f "$SWAP"
    SWAP=""
}
trap cleanup_swap EXIT
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
if [ $((mem_kb + swap_kb)) -lt 2500000 ]; then
    echo "内存较小，编译期间临时加 2 GB 交换空间"
    SWAP=$(mktemp /caddy-build-XXXXXX.swap) # a new file, mode 600
    fallocate -l 2G "$SWAP" 2>/dev/null || dd if=/dev/zero of="$SWAP" bs=1M count=2048 status=none
    mkswap -q "$SWAP"
    swapon "$SWAP"
fi
(cd "$SRC" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /tmp/caddy-masque.bin ./cmd/caddy)
cleanup_swap
install -m 755 /tmp/caddy-masque.bin /usr/local/bin/caddy
rm -f /tmp/caddy-masque.bin
caddy version

say "端口"
# masque-vpn's own server, or another web server, would hold 443.
for unit in masque-server caddy nginx apache2; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        die "$unit 正在运行，会占用 80/443 端口。先停掉它：systemctl disable --now $unit"
    fi
done
for p in 80 443; do
    if ss -ltnH "sport = :$p" | grep -q . && ! systemctl is-active --quiet caddy-masque; then
        die "TCP $p 端口被占用（$(ss -ltnpH "sport = :$p" | head -1)），先停掉占用的程序"
    fi
done

say "伪装网站"
if [ -f "$SITE/index.html" ]; then
    echo "已有 $SITE/index.html，保留"
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
    echo "放了一个简单的首页；想换成自己的网页，把文件放进 $SITE（要有 index.html）"
fi

say "配置"
if [ -f "$CONFIG" ]; then
    echo "已有 $CONFIG，保留（其中的用户不变）"
else
    IPV6_LINE="# ipv6 fd89:6d61:7371::1/64"
    # Offer IPv6 in the tunnel only when this server reaches the IPv6 Internet.
    if [ -d /proc/sys/net/ipv6 ] && ip -6 route show default | grep -q .; then
        IPV6_LINE="ipv6 fd89:6d61:7371::1/64"
    fi
    read -r HASH PASSWORD < <(caddy masque-passwd --name "$USER_NAME" |
        awk '/^user / {h=$3} /^password =/ {gsub(/"/, "", $3); p=$3} END {print h, p}')
    if [ -z "$HASH" ] || [ -z "$PASSWORD" ]; then die "生成用户失败"; fi
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

$DOMAIN {
	masque
	root * $SITE
	file_server
}
EOF
    cat >"$CREDENTIALS" <<EOF
MASQUE VPN, $(date '+%Y-%m-%d')
服务器域名：$DOMAIN
服务器 IP：${PUBLIC_IP:-}
用户名：$USER_NAME
密码：$PASSWORD
EOF
    chmod 600 "$CONFIG" "$CREDENTIALS"
    umask 022
fi
caddy validate --config "$CONFIG" >/dev/null 2>&1 ||
    { caddy validate --config "$CONFIG" || true; die "$CONFIG 有错误，见上面的输出"; }

say "启动服务"
install -m 644 "$SRC/deploy/caddy-masque.service" /etc/systemd/system/caddy-masque.service
systemctl daemon-reload
systemctl enable --now caddy-masque
systemctl restart caddy-masque
sleep 3
if ! systemctl is-active --quiet caddy-masque; then
    journalctl -u caddy-masque -n 30 --no-pager -o cat
    die "caddy-masque 没有启动，原因见上面的日志"
fi

say "检查（第一次要等 Caddy 申请证书）"
ok=""
for _ in $(seq 30); do
    if curl -fsS --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" 2>/dev/null | grep -qi '<title>'; then
        ok=1
        break
    fi
    sleep 2
done
if [ -n "$ok" ]; then
    echo "网站正常：https://$DOMAIN/"
else
    echo "警告：本机访问 https://$DOMAIN/ 没有得到网页（多半是证书还没申请下来），看日志：journalctl -u caddy-masque -n 50 -o cat"
fi
ss -lunH 'sport = :443' | grep -q . && echo "UDP 443（HTTP/3）在监听"
ss -ltnH 'sport = :443' | grep -q . && echo "TCP 443（HTTP/2、HTTP/1.1）在监听"

say "完成"
cat <<EOF

客户端（Mac 上的 MasqueVPN，或 masque-client）这样填：
$(if [ -f "$CREDENTIALS" ]; then sed -n '2,$p' "$CREDENTIALS"; else echo "  （用户在已有的 $CONFIG 里）"; fi)
  （IP 可不填。）

这些信息也保存在 $CREDENTIALS（只有 root 能读）。

还要确认云服务商的防火墙（安全组）放行了：
  TCP 443、UDP 443（VPN 和网站）  TCP 80（证书申请和续期）
UDP 443 没开也能用，但只能走较慢的 TCP。

常用命令：
  systemctl status caddy-masque              状态
  journalctl -u caddy-masque -f -o cat       实时日志
  caddy masque-passwd --name 新用户名        再建一个用户（每台设备一个），
                                             把输出的 user 行加进 $CONFIG，
                                             然后 systemctl reload caddy-masque
EOF

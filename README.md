# caddy-masque

用 Go 重写的 [masque-vpn](https://github.com/ArcCal/masque-vpn) 服务端，做成 Caddy 模块：

- **标准**：IETF MASQUE 的 IP 代理 CONNECT-IP（RFC 9484），HTTP Datagram 与 Capsule（RFC 9297），
  HTTP/2、HTTP/3 的扩展 CONNECT（RFC 8441、RFC 9220）。HTTP/3、HTTP/2、HTTP/1.1 三种方式都支持。
- **客户端不变**：masque-vpn 的 `masque-client` 和 Mac 上的 MasqueVPN 直接连，配置一个字都不用改。
  `caddy masque-passwd` 生成的密码哈希和 masque-vpn 的 `masque-passwd` 通用。
- **Caddy 管证书和流量**：证书自动申请、续期；VPN 和网站共用 443 端口（TCP 和 UDP）；
  同一个 Caddy 还可以照常托管别的网站、反向代理。
- **看起来就是个网站**：只有带正确用户名密码的 CONNECT-IP 请求才会变成隧道；
  其他所有请求（包括密码错误的、探测的）都交给网站处理，回应和普通 Caddy 网站一模一样。

只支持 Linux（需要 root：创建 TUN 设备、设置转发和 NAT）。

## 一键安装

在 Debian 12/13 或 Ubuntu 22.04/24.04 上，域名先解析到服务器，然后：

```sh
git clone https://github.com/ArcCal/caddy-masque && cd caddy-masque
sudo bash deploy/install-server.sh vpn.example.com
```

脚本会装 Go、编译、写好 `/etc/caddy/Caddyfile`（带一个伪装首页和一个随机密码的用户）、
启动 `caddy-masque` 服务。最后打印客户端要填的域名、用户名、密码。
云服务商的防火墙要放行 TCP 80、TCP 443、UDP 443。

已经装了 masque-vpn 的服务端？先 `systemctl disable --now masque-server`，它们都要用 443 端口。
原来的用户可以照搬：`server.toml` 里每个 `[[user]]` 写成 Caddyfile 里的一行 `user 名字 哈希`。

## 手动编译

需要 Go 1.26：

```sh
go build -o caddy ./cmd/caddy
```

得到的 `caddy` 就是完整的 Caddy（带全部标准模块）加上本模块。也可以用 xcaddy：
`xcaddy build --with github.com/ArcCal/caddy-masque`。

## 配置

```caddyfile
{
	masque {
		ipv4 10.89.0.1/24
		ipv6 fd89:6d61:7371::1/64
		user macbook $argon2id$v=19$m=19456,t=2,p=1$...
		user iphone  $argon2id$v=19$m=19456,t=2,p=1$...
	}
}

vpn.example.com {
	masque
	root * /var/www/site
	file_server
}
```

站点里的 `masque` 指令负责接 VPN 请求，其余请求照常往下走（这里是 `file_server` 提供网页）。
它会自动排在 `file_server`、`reverse_proxy` 等指令前面。

### 全局选项 `masque { ... }`

| 选项 | 说明 | 默认 |
|---|---|---|
| `ipv4 地址/前缀` | 服务器自己的隧道地址，前缀里其余地址分给客户端。必填 | — |
| `ipv6 地址/前缀` | 隧道里提供 IPv6；服务器能上 IPv6 网时再开 | 不提供 |
| `user 名字 哈希` | 一个用户，哈希由 `caddy masque-passwd` 生成。每台设备一个 | — |
| `interface 名字` | TUN 设备名 | `masque0` |
| `mtu 字节` | 隧道 MTU（576–1500；开 IPv6 时至少 1280） | `1350` |
| `block 前缀...` | 不许客户端访问的目的地址，可写多行。写了就替换默认列表；`block none` 表示不屏蔽 | 私有地址、本机、组播等（含云服务商内网和 169.254.169.254） |
| `allow_client_to_client` | 允许客户端之间互相访问 | 不允许 |
| `manage_network off` | 不改转发和 NAT（sysctl、nftables），自己管 | 自动管理 |
| `http3 off` | 不接管 HTTP/3（见下文），VPN 只走 HTTP/2 和 HTTP/1.1 | 接管 |

链路本地地址（169.254.0.0/16、fe80::/10）无论怎么配置都不转发（RFC 9484 §7.2）。

### 指令 `masque [路径模板]`

路径模板默认是 `/.well-known/masque/ip/{target}/{ipproto}/`，和客户端默认值一致。
改了的话，客户端的 `uri_template` 要跟着改。客户端 `uri_template` 里的主机名要和站点地址一致。

## 用户管理

```sh
caddy masque-passwd --name iphone
```

把输出的 `user ...` 那一行加进 Caddyfile 的 `masque { }`，然后 `systemctl reload caddy-masque`。
输出里也有客户端配置要填的用户名和随机密码。想自己定密码：`echo 密码 | caddy masque-passwd --name iphone --stdin`。

## 重载配置

`systemctl reload caddy-masque`（即 `caddy reload`）：

- 已连接的隧道**不断**，HTTP/3、HTTP/2、HTTP/1.1 都一样；
- 删掉的用户、改了密码的用户**立即断开**；
- 改了 `block`、`allow_client_to_client`，**在线的会话立即生效**，客户端收到新的路由（RFC 9484 §4.7.3）；
- `interface`、`ipv4`、`ipv6`、`mtu`、`manage_network` 改了要重启：`systemctl restart caddy-masque`。

证书用的是自己的文件（`tls 证书 私钥`）时，文件换了而 Caddyfile 没变，要 `caddy reload --force`
才会重新读（服务文件里的 reload 已经带了 `--force`）。Caddy 自动申请的证书不用管。

## 和 Caddy 的关系（技术细节）

- **HTTP/3**：Caddy 自己的 HTTP/3 关闭了 HTTP Datagram，CONNECT-IP 用不了。
  所以本模块接管 HTTPS 站点的 UDP 端口，用同样的证书、同样的站点路由提供 HTTP/3（带 Datagram），
  并照 Caddy 的样子发 `Alt-Svc` 头。普通网页请求走 HTTP/3 也照常由 Caddy 的路由处理。
  `http3 off` 则把 HTTP/3 还给 Caddy。
- **HTTP/2**：Go 的 HTTP/2 默认不接受扩展 CONNECT，要 `GODEBUG=http2xconnect=1`。
  本模块在程序启动时自动设置（无论用本项目的 `cmd/caddy` 还是 xcaddy 编译）；
  如果环境变量里明确写了 `http2xconnect=0`，就尊重它，此时 HTTP/2 隧道不可用，日志里有警告。
- **退出**：Caddy 退出时主动结束所有隧道，不会因为隧道一直开着而卡住。

## 测试

```sh
go test -race ./...                 # 单元测试和进程内集成测试（不需要 root）
sudo tests/e2e-netns.sh             # 端到端测试：网络命名空间里跑 Caddy 和原版 masque-client
```

进程内测试在测试进程里启动真的 Caddy（TUN 设备换成假的），用 Go 写的小客户端
走 HTTP/3、HTTP/2、HTTP/1.1 做 CONNECT-IP：收发数据包、伪装成网站的拒绝、重载、删用户、新屏蔽等。

端到端测试需要 masque-vpn 的客户端（默认找 `../masque-vpn/target/debug/masque-client`，
或用 `CLIENT_BIN=` 指定），覆盖：三种传输方式、UDP 被封时回退到 TCP、限定范围的请求
（含服务器解析域名）、证书和用户的重载、服务器崩溃和重启、客户端互访、SOCKS 模式、
局域网网关模式、地址复用时清理连接跟踪等。

GitHub Actions 对每次推送到 main 和每个 PR 跑单元测试；仓库设置了 `MASQUE_VPN_TOKEN`（能读 masque-vpn 的令牌）时也跑端到端测试。

## 许可证

MIT 或 Apache-2.0，与 masque-vpn 相同。

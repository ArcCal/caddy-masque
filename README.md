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
| `mtu_probe off` | 不做 IPv6 MTU 探测（见下文）。只在确知客户端都直连、中间没有 HTTP 代理时关 | 探测 |

带 IPv6 的 HTTP/3 隧道（QUIC datagram）建立后，服务器向客户端的 IPv6 地址发 1280 字节的
ICMPv6 Echo 请求，确认隧道装得下 IPv6 的最小 MTU；10 秒内收不到回复就拆掉隧道（RFC 9484 §7.2
要求这样做，除非有带外手段保证 QUIC Initial 包的填充已经足够，即中间没有 HTTP 代理）。
客户端的 IPv6 协议栈会自动回复；**客户端防火墙丢弃 ICMPv6 Echo（如 macOS 的隐身模式）时，
HTTP/3 隧道会被拆掉**，这时放行 ICMPv6 Echo，或在确知没有中间代理时用 `mtu_probe off`。

链路本地地址（169.254.0.0/16、fe80::/10）无论怎么配置都不转发（RFC 9484 §7.2）。

### 指令 `masque [路径模板]`

路径模板默认是 `/.well-known/masque/ip/{target}/{ipproto}/`，和客户端默认值一致。
改了的话，客户端的 `uri_template` 要跟着改。客户端 `uri_template` 里的主机名要和站点地址一致。
模板可以用 RFC 9484 §3 允许的写法：路径和查询里的简单表达式（`{target}`、`{target,ipproto}`，
前后可以有固定文字）、`{?target,ipproto}`、`{&...}`，以及固定参数（如 `?v=1`）。
服务器没法无歧义地匹配的写法（两个表达式紧挨着、变量当参数名、`{?...}` 后面跟的文字不以 `&` 开头）
在加载配置时报错，不会等到请求时才匹配不上。

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
- 改了 `block`、`allow_client_to_client`：多出来的目的地址**立即**以新的路由通告发给在线会话；
  被收回的目的地址，相关隧道会被关闭（RFC 9484 要求隧道存续期间保持已分配的路由），
  客户端自动重连后拿到新的路由；
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
- **只走加密连接**：RFC 9484 §4 要求 CONNECT-IP 跑在 TLS 或 QUIC 上。没有 TLS 的连接
  （`http://` 站点、h2c）上的 CONNECT-IP 请求一律交给网站处理，不建隧道。
- **畸形请求**：通过认证、但 `target`、`ipproto` 缺失或不合规，或带了内容头的请求是畸形的
  （RFC 9484 §4.1、RFC 9297 §3.2）：回 400；HTTP/3 上还按 RFC 9114 §4.1.2 以 H3_MESSAGE_ERROR
  结束请求流（STOP_SENDING，400 照样送达）。目的地址不允许（403）、DNS 失败（502）等是拒绝，不算畸形。
- **超时**：Caddy 2.11 默认的读写空闲超时（1 分钟）和 `read_timeout`、`write_timeout` 不作用于隧道，
  隧道空闲多久都不断；对普通网页请求照常生效。
- **不支持 HTTP/3 Datagram 的客户端**：用 DATAGRAM capsule 在流上传数据包（RFC 9297 §3.5）。
- **退出**：Caddy 退出时主动结束所有隧道，不会因为隧道一直开着而卡住。
- **重载失败**：新配置启动失败时，用户、可达范围、HTTP/3 都回到旧配置。

已知的限制：

- `Alt-Svc` 头只加在带 `masque` 指令的站点上；同一端口上的其他站点照样能用 HTTP/3，只是不会被告知。
- VPN 接管的 HTTP/3 不接受 0-RTT（重放风险），也不套用 Caddy 的 `packet_conn_wrappers`（如 UDP 上的 proxy protocol）。
- HTTP/2 上，RFC 9113 §8.1.1 要求把畸形请求（以及畸形 capsule，RFC 9297 §3.3）当作 PROTOCOL_ERROR 流错误。
  Caddy 用的 Go HTTP/2 服务端（`x/net/http2`）不让处理器指定错误码，处理器能触发的流重置只有 INTERNAL_ERROR，
  所以畸形请求只回 400，畸形 capsule 中止隧道时错误码是 INTERNAL_ERROR。客户端照样把它当作失败
  （RFC 9484 §4.5：非成功响应即失败），互通不受影响；要做到完全符合，只能换掉 Caddy 的 HTTP/2 服务端。

## 测试

```sh
go test -race ./...                 # 单元测试和进程内集成测试（不需要 root）
sudo tests/e2e-netns.sh             # 端到端测试：网络命名空间里跑 Caddy 和原版 masque-client
```

进程内测试在测试进程里启动真的 Caddy（TUN 设备换成假的），用 Go 写的小客户端
走 HTTP/3、HTTP/2、HTTP/1.1 做 CONNECT-IP：收发数据包、伪装成网站的拒绝、重载（含失败的重载）、删用户、新屏蔽、空闲超时等。

端到端测试需要 masque-vpn 的客户端（默认找 `../masque-vpn/target/debug/masque-client`，
或用 `CLIENT_BIN=` 指定），覆盖：三种传输方式、UDP 被封时回退到 TCP、限定范围的请求
（含服务器解析域名）、证书和用户的重载、服务器崩溃和重启、客户端互访、SOCKS 模式、
局域网网关模式、地址复用时清理连接跟踪、带校验的大文件传输（HTTP/3 下载 300 MB、上传 100 MB，
HTTP/2 和 HTTP/1.1 各 100 MB / 50 MB）、差网络（见下）、MTU 1300 的窄路径等。

### 差网络下的表现

内核没有 netem 时，测试用 `tests/netsim` 在路由器里造一条慢链路（TUN 设备上的用户态 netem：
按包加延迟和抖动、随机丢包，保持包序），再用 tbf 限速：120 ms RTT、1% 和 5% 丢包、4 Mbit/s 带宽、
20 秒和 70 秒断网。结果：

- 隧道在这些条件下都能正常收发、校验通过；20 秒断网后 QUIC 连接自己恢复、不重连；
  70 秒断网超过空闲超时，客户端自动重连，服务端清理掉死会话。
- **随机丢包下 HTTP/3 隧道的吞吐量远低于 HTTP/2 隧道。** 120 ms RTT、1% 丢包时，HTTP/3 隧道下载 1.7 Mbit/s、
  隧道内 UDP 约 7 Mbit/s；HTTP/2 隧道下载 13 Mbit/s、隧道内 UDP 约 19 Mbit/s。对照实验（同一条链路，不经过隧道）：
  Linux TCP 约 70 Mbit/s，quic-go 的流和 datagram 都只有 2 Mbit/s 左右；无丢包时两者都是几百 Mbit/s。
  这是 quic-go 拥塞控制对随机丢包的反应方式决定的，不是本模块能改的；Rust 服务端（quinn）类似。
  **在丢包明显的网络上，客户端配置 `transport = "h2"` 会快得多。**
- 带宽受限时，服务端队列里等待超过 200 ms 的包会被丢掉，不会积压出几秒的延迟。
- 路径 MTU 只有 1300 时，HTTP/3 建不起来（两端都把 QUIC Initial 包填充到约 1400 字节，
  这是 RFC 9484 §7.2 保证 IPv6 1280 字节包能通过的办法），客户端回退到 HTTP/2，大文件传输正常。

GitHub Actions 对每次推送到 main 和每个 PR 跑单元测试；仓库设置了 `MASQUE_VPN_TOKEN`（能读 masque-vpn 的令牌）时也跑端到端测试。

## 许可证

MIT 或 Apache-2.0，与 masque-vpn 相同。

# masque-vpn 客户端兼容性要求

目标客户端：[ArcCal/masque-vpn](https://github.com/ArcCal/masque-vpn) 的真实 `masque-client`，以及使用其核心的 MasqueVPN macOS 应用。2026-10-04 起，服务端改动同时以 **IETF 规范、安全与可靠性、目标客户端兼容性** 为验收条件。

兼容性需要固定并记录版本、配置与测试结果；“完美兼容”是目标，不能作为未经验证的保证。默认覆盖当前 `main` 的明确提交、最新稳定发行版和用户实际部署版本；当前 main 的固定提交已记录如下；稳定发行版和用户实际部署版本尚待确认。历史版本逐项记录支持范围，不承诺所有历史构建都具备后来新增的协议能力。

## 兼容原则

- 合法客户端请求在支持的传输与部署范围内应继续工作。尽量保持现有配置可用，包括默认 URI Template、IP 地址连接搭配域名 SNI、用户名/密码、SOCKS 与 TUN 模式。
- 优先通过 RFC 已定义的协商、Capsule 承载和传输回退解决能力差异，不引入双方必须理解的私有格式，不将删除一种现有传输当成规范修复。
- IETF 要求和身份/网络隔离不能因某个客户端的旧行为而放宽。若客户端存在不符合规范的实现，先复现并定位，采用符合规范的服务端选择或客户端修复，记录版本边界和迁移方法。
- 兼容修复不能关闭证书校验、源地址校验、访问控制、conntrack 隔离或绕过 IPv6 最小 MTU 保证。凭据撤销、策略拒绝和资源繁忙的合理失败也属于需要验证的行为。
- 模拟客户端、独立 `connect-ip-go` 客户端和历史日志仅提供各自范围的证据。必须用目标 Rust 客户端及 macOS 应用验证后，才能对相应版本作兼容结论。

## 必测范围

以下表格定义验收范围，不表示这些组合已在本次环境运行。

| 范围 | 组合与预期行为 |
| --- | --- |
| 传输与协商 | HTTP/3、HTTP/2、HTTP/1.1；QUIC DATAGRAM 与标准 DATAGRAM Capsule；UDP 被阻断、QUIC 不可用时的实际回退 |
| 连接身份与 TLS | 域名连接；IP `uri_template` + 域名 `server_name`；SNI 与 authority 不同；有效/错误证书、证书重载；保持证书验证 |
| 地址与路由 | IPv4-only、双栈、客户端 `ipv6=false`；ADDRESS_REQUEST/ASSIGN、ROUTE_ADVERTISEMENT、Request ID 和目标/协议范围；地址续用及跨用户复用隔离 |
| 客户端模式 | TUN、SOCKS5 TCP/UDP/域名解析、LAN gateway；目标 macOS 应用的实际发布构建另测，不能以 Linux CLI 代替 |
| MTU 与 ICMP | IPv6 1,280 字节完整报文；SOCKS/`ipv6=false` 的 MTU 探测回应；IPv4 DF/分片、IPv6 PTB、低 MTU、ICMP 被过滤时的受控失败/回退 |
| 生命周期 | 正常/失败重载、证书更新、服务器重启/崩溃、网络切换、长时间空闲、失联清理和带退避的重连 |
| 认证与策略 | 正确/错误凭据、改密、用户撤销、每用户/全局容量限制、503 繁忙与退避；被禁止目的地持续受限 |
| 负面协议用例 | 正确生成 RFC 要求的错误码；合法客户端的其他并发流不受畸形流影响；客户端不发生无限重试或错误地视为成功 |
| 数据完整性与可靠性 | 双向 TCP/UDP、大文件校验和、丢包/延迟/限速/断网恢复；记录吞吐、内存、会话清理与错误 |
| 交付版本 | 真实运行带 `caddy-masque` 和 `caddy-dns/cloudflare` 的候选 Artifact；Linux arm64/amd64 服务端；不能仅验证无 DNS 插件的开发构建 |

## 已知的版本敏感点

服务端 README 记录，`masque-vpn#14` 起客户端在各模式回应 IPv6 MTU 探测；更早的 SOCKS 或 `ipv6=false` 构建可能不能回应。已读取的客户端提交 `ba82e36164a69c01a2a366153550aee2821c41b7` 在未使用 IPv6 地址时仍保留 peer 地址并回应 Echo；本轮真实 H3/SOCKS/`ipv6=false` 用例通过 10 秒探测窗口后仍可收发。此结论仅适用于所测提交，尚未确认 macOS 应用内嵌版本或所有旧构建。

仅知道“直连、没有 HTTP 代理”不足以凭空宣称 MTU 保证。若使用 `mtu_probe off`，必须另有经过验证的 RFC 9484 §7.2 保证；不要为旧客户端无条件关闭探测。选择标准可靠 Capsule 承载或受支持传输也须通过真实互操作测试，且不关闭其他报文保护。HTTP/2 当前的规范错误码缺口仍须按审计 S1 修复，不能因为旧客户端能容忍就视为合规。

## 现有测试的证据边界

- `tests/e2e-netns.sh` 已包含目标 Rust 客户端的三种传输、UDP 阻断回退、IP authority + 域名 SNI、范围请求、重连、SOCKS、gateway 和数据完整性场景。脚本存在这些检查，不等于它们当前已运行。
- `.github/workflows/ci.yml` 的 Rust e2e job 在缺少 `MASQUE_VPN_TOKEN` 时只显示 notice，整体可以显示成功。**该状态不能用于通过客户端兼容性门槛。**发布/晋级门槛必须要求真实 e2e 执行并通过；缺少凭据、零用例或跳过必测组合应视为未验收。
- 当前 Rust e2e 工作流构建 `./cmd/caddy`，不含 Cloudflare。验收组合发行版时，应使用已记录源码及校验和的组合二进制运行同一数据通路测试。
- macOS 应用的 TUN/SOCKS、系统防火墙、睡眠唤醒和网络切换需要 macOS 端验证，Linux 命名空间不能证明这些平台行为。
- e2e 脚本已改为唯一命名空间/临时 veth 名，拒绝冲突并只清理本次创建的命名空间；冲突拒绝路径经命令 spy 验证。完整脚本仍仅允许在一次性特权测试机器运行。

每次兼容性验收记录：服务端完整 SHA、Caddy/Cloudflare/Go 版本、客户端完整 SHA/发行版、macOS 应用版本与内嵌核心版本、架构、模式/传输/IPv6/MTU 配置、实际运行/通过/失败/跳过数量和日志。失败归属先由相同输入在两端复现确定，再分别修改服务端或客户端；不以新增宽松处理替代符合规范的修复。

## 当前状态（2026-10-04）

通过保持代理和 TLS 校验的普通 GitHub HTTPS API 请求，已读取私有仓库 main 并下载固定提交：**`ba82e36164a69c01a2a366153550aee2821c41b7`**。源码置于服务器仓库外，使用原 Cargo.lock 和其固定的 hyperium/h3 提交，Rust 1.99.0 `cargo build --locked --bin masque-client` 成功；`cargo test --locked --workspace` **200 个测试通过、0 个失败**。没有提取代理认证，也没有改动客户端源码。此前 Git/gh 的认证失败不应扩大为所有 HTTPS 读取路径不可用。

服务端 **`d414d2a07eb5e9d305fbf7d82fc46efe8302dd18`** 的 `TestInteropMasqueVPNClient` 启动这个真实二进制，通过独立进程的 SOCKS5 UDP ASSOCIATE 发送/接收 IP 报文。六种组合全部通过：

| HTTP 传输 | 客户端 IPv6 关闭 | 客户端 IPv6 开启 |
| --- | --- | --- |
| HTTP/3 | IPv4 UDP 双向通过；等待超过 10 秒探测期限后再次通过 | IPv4/IPv6 UDP 双向通过 |
| HTTP/2 | IPv4 UDP 双向通过 | IPv4/IPv6 UDP 双向通过 |
| HTTP/1.1 | IPv4 UDP 双向通过 | IPv4/IPv6 UDP 双向通过 |

测试使用 IP URI authority、域名 SNI、有效的私有 CA/独立终端证书，证书验证保持开启。最初失败是原 Go 测试夹具把 CA 用作服务器证书，Rust TLS 正确返回 `CaUsedAsEndEntity`；修正夹具证书链后重测通过，未放宽客户端 TLS 或服务器协议检查。

**证据边界：**服务端为真实 Caddy 的 in-process 实例，TUN/目标 UDP 回包由夹具模拟，客户端使用真实协议栈。没有运行真实 macOS 应用、客户端 TUN/gateway 模式、SOCKS TCP/DNS 的跨项目验收，也没有使用带 Cloudflare 的下载 Artifact 完成这套真实客户端测试。Rust 自身的 in-process 测试覆盖不能替代这些组合。

复现：

```sh
# 在 companion 客户端仓库，使用受支持的 Rust 工具链
cargo build --locked --bin masque-client
cargo test --locked --workspace

# 在服务端仓库，用客户端二进制的绝对路径
MASQUE_TEST_CLIENT=/absolute/path/to/masque-client \
  go test -race -count=1 -v . -run '^TestInteropMasqueVPNClient$'
```

真实互通测试已加入原 e2e Actions job；它仍需要仓库侧 `MASQUE_VPN_TOKEN` 才能获取私有客户端，缺少 secret 时未运行。只授予读取 companion 仓库的权限，在支持的设置中输入；不得在聊天发送或把环境代理凭据复制为 secret。当前本地读取与测试已完成，不再把云环境添加客户端仓库当作读取的必需前提。

规范与规模门槛见 [安全与 IETF 审计](security-ietf-audit-2026-10-04.md)。当前结果确认所测 CLI/模式/传输范围内兼容，不构成“所有版本/所有模式完美兼容”或生产验收。

## 网络加固后的再次验证

服务端网络实现 `e649126e66d07016e4eac0716367cb1006af489b`（交付候选 `2455ab70af40af6c8f364bc270265e97de27a3d6` 的 Go 源码相同）再次运行全量 race suite，225 个测试/子测试通过，真实 companion CLI 的上述六种组合全部通过。客户端版本保持固定 SHA、原始二进制和证书验证；没有重跑此前 200 项 Rust workspace 测试，因为本轮没有修改客户端。

原生 arm64/amd64 内核测试另验证了模拟协议客户端与独立 `connect-ip-go` 的双向 NAT、TTL/Hop Limit、ICMP 超时和本地回应；这不是目标 Rust TUN/macOS 验收。新的组合 Artifact 已通过实际 service/installer 检查和离线 DNS provider 配置，仍未完成 Rust/组合 Artifact 互通或真实 DNS 签发/续期。版本、下载、日志和证据边界见 [本轮记录](network-hardening-2026-10-04.md)。

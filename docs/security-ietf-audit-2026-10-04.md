# caddy-masque 安全、实现合理性与 IETF 审计（2026-10-04）

## 结论

**当前实现不能被认定为完全符合 IETF 规范，也尚不足以签字确认适合大规模生产部署。**

核心隧道、身份隔离、报文解析和默认访问控制已有较好的保护。本次没有发现可复现的未经认证接管隧道或跨用户读取报文的路径；这不是“没有漏洞”的证明。已确认 HTTP/2 错误处理与规范要求不符、URI 模板校验遗漏，以及认证内存预算和会话管理的规模风险。TTL/Hop Limit 的内核委托边界尚未完成规范验证。

修复必须保留 RFC 定义的消息、地址、路由和错误语义。不能把“客户端仍能连接”“返回 400”或“测试全绿”等同于符合规范；不能靠关闭报文检查、跳过 conntrack 清理、补偿性修改 TTL 或自定义 Capsule 来掩盖问题。

用户进一步明确，保持与 [ArcCal/masque-vpn](https://github.com/ArcCal/masque-vpn) 真实客户端兼容也是目标。后续改动须同时通过规范、安全可靠性和 [目标客户端兼容性验收](client-compatibility.md)；既不能为旧行为牺牲 RFC 要求，也不能只验证模拟客户端就宣称完成真实兼容。本次环境无法读取客户端源码，兼容性仍未重新验收。

## 范围与证据边界

实现基线：[`3d7537ee375953d3ec5d9f1d3be67e4b20b056e7`](https://github.com/ArcCal/caddy-masque/commit/3d7537ee375953d3ec5d9f1d3be67e4b20b056e7)，`production-readiness` 分支。包含此前生产改进和本次接口重载修复；文档与诊断脚本的后续提交不会改变该实现。

完整阅读了仓库全部 Go 实现、测试辅助程序和测试源码，以及部署脚本、systemd 配置和 GitHub 工作流。实现约 6,000 行，分布在 21 个文件中：

- 应用与 Caddy 集成：`app.go`、`caddyfile.go`、`command.go`、`cmd/caddy/main.go`、`handler.go`、`tunnel.go`。
- 会话与转发：`core.go`、`session.go`、`metrics.go`。
- 内部实现：`internal/auth/{auth,throttle}.go`、`internal/hostnet/{hostnet_linux,hostnet_other}.go`、`internal/ip/ip.go`、`internal/pool/pool.go`、`internal/proto/{capsule,scope,template}.go`、`internal/routes/routes.go`、`internal/xconnect/xconnect.go`。
- 测试辅助：`tests/netsim/main.go`。同时阅读了所有 `_test.go`、`tests/*.sh`、`deploy/*` 和工作流。

对照了 RFC 9484、9297、9113、9114，并按需检查 HTTP/1.1、URI Template、QUIC DATAGRAM、IPv4/IPv6 与隧道 MTU 的相关 RFC。检查了关键依赖中实际使用的 HTTP/2、conntrack 和 Cloudflare token 校验代码；**没有完整审计所有第三方依赖或私有 Rust 客户端**。

证据分三种：专项运行复现、源码及依赖调用链确认、需要真实网络进一步验证。下面逐项注明，不将静态推断写成已发生的线上事故，也不将可能风险写成已证明的攻击。历史报告中原 Rust 客户端的测试数量不作为本次重新验证的证据。

## 已修复：修改 TUN 名称时的重载顺序

**优先级 P1，网络生命周期；已修复并回归。**

原先 `App.Provision` 按接口名称选择共享 core。重载把 `masque0` 改为另一个名称时会创建第二个 core，绕过原本应拒绝底层网络参数变化的检查。两者却共用固定 nftables 表名。新网络启动和旧网络析构可能相互覆盖、删除规则或恢复 sysctl，造成断流并可能暂时削弱宿主访问保护。

现在同一 Caddy 进程的 masque app 始终使用同一 core 键。在打开第二个 TUN 或改变宿主网络前，先比较配置；不兼容的变更返回“需要重启”，旧隧道继续工作。没有改变 CONNECT-IP 的线上格式。

`TestCaddyRejectsInterfaceChangeBeforeOpeningNetwork` 在修改前失败：尝试启动了第二个网络；修改后验证“没有打开替代网络、重载被拒绝、原会话仍可收发”。接口变更、正常重载和失败重载的三个测试合计通过 10 次 race 重复运行。阻塞写入测试改为每种传输使用独立 Caddy 实例，避免上一测试的监听器交接影响下一测试；两个测试通过 20 次 race 重复运行。QUIC DATAGRAM 不受流的写入窗口限制，不能用它证明 TCP 流写阻塞；HTTP/3 的重载、撤销和控制 Capsule 阻塞测试仍保留。

## 尚未关闭的问题

### S1 — HTTP/2 畸形消息的错误码不符合规范

**P1：严格 IETF 验收阻断项；帧级复现。**

位置：`handler.go` 的 `reject`、HTTP/2 `reset`，以及 Caddy 使用的 `golang.org/x/net/http2`。

[RFC 9484 §4.1](https://www.rfc-editor.org/rfc/rfc9484.html#section-4.1) 要求不合法的 `target`/`ipproto` 按畸形请求处理；[RFC 9297 §3.3](https://www.rfc-editor.org/rfc/rfc9297.html#section-3.3) 对畸形 Capsule 采用同样的要求。[RFC 9113 §8.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1) 明确要求 `PROTOCOL_ERROR` 流错误，允许在关闭或复位前发送 HTTP 响应。

实际 TLS/HTTP/2 帧诊断结果：

| 输入 | 实际结果 | 要求 |
| --- | --- | --- |
| `ipproto=256` | `400`、`END_STREAM`，随后 `RST_STREAM(NO_ERROR)` | `PROTOCOL_ERROR` |
| 成功建立隧道后发送空 `ADDRESS_REQUEST`（字节 `02 00`） | 初始 `200`，随后 `RST_STREAM(INTERNAL_ERROR)` | `PROTOCOL_ERROR` |

请求会被拒绝，未证明认证绕过；但错误语义确实不合规。README 之前已记录该限制，本次直接验证了其存在。

**责任与改动方向：**模块应承担最终的规范符合性责任，底层障碍在 Caddy 使用的 HTTP/2 handler API。应推动显式流复位接口，或采用经过维护、验证并在普通 Caddy、xcaddy 和组合构建中一致使用的适配层/依赖补丁。仅修补本仓库的 `cmd/caddy` 会产生构建方式间的行为差异。不要使用反射修改 HTTP/2 内部状态，也不要把 `INTERNAL_ERROR` 描述成合规替代。修复后的验收必须在真实帧层断言两个案例均为 `PROTOCOL_ERROR`，并验证同一连接的其他合法流仍能继续工作。

### S2 — URI Template 校验接受变量位于 fragment 中的模板

**P2：规范校验遗漏；诊断复现；管理员配置触发。**

位置：`internal/proto/template.go` 的 `ParseTemplate`、`parseParts`。

`https://server/path#fragment/{target}/{ipproto}/` 被接受，变量实际上处于 URI fragment。[RFC 9484 §3](https://www.rfc-editor.org/rfc/rfc9484.html#section-3) 要求所有模板变量必须在 path 或 query 中。`1https://server/path/{target}/{ipproto}/` 同样被接受，但 scheme 的首字符不满足 [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1)。默认模板不受影响，当前证据是错误配置通过校验，并非远程入侵。

应先可靠区分 URI 组件，再检查变量位置与 scheme 语法；保留 RFC 6570 允许的编码规则。现有操作符限制、禁止 level 4、匹配工作量上限应保留。验收要覆盖 literal `#` 与 `%23`、query/fragment 边界、合法 scheme 和 RFC 6570 的变量编码，避免为修复校验而误拒绝合法模板。

### S3 — Argon2 有并发上限，但没有总内存预算

**P1：可用性与容量阻断项；参数及并发诊断复现，未进行 OOM 攻击试验。**

位置：`internal/auth/auth.go` 的 `New`、`parsePHC`、`Verify`。

并发数为 `2 × runtime.NumCPU()`，没有结合 hash 的内存成本或容器内存预算。单个配置 hash 允许 `m=1048576` KiB、`t=64`，即约 1 GiB 工作内存和 64 次迭代。**参数来自管理员配置，不是远程请求可任意指定的参数**；但未认证请求可以用已配置用户名和错误密码触发该成本。

本环境诊断：`NumCPU=5`、`GOMAXPROCS=4`，允许 10 个并发验证。默认每个约 19 MiB，仅 Argon2 就可约 190 MiB；允许的最高参数对应约 10 GiB。诊断只做配置解析，没有分配 10 GiB。容器 CPU 配额、宿主可见 CPU 数和内存配额不一致时，默认值也可能过大。

已有每来源 4 个验证、IPv6 /64 聚合、有限等待队列、失败限流和正确凭据 HMAC 缓存；这些有效减少单来源攻击和热重连成本，不能替代总内存预算，也不能保证分布式攻击下首次登录的可用性。

应增加按 Argon2 内存成本加权的全局预算，限制 CPU 并发和等待时间，在配置加载时拒绝超出预算的参数组合。保留密码算法和凭据撤销语义。验收至少包括多来源错误凭据、合法首次登录、缓存重连、取消请求、容器 CPU/内存限制以及 RSS/p95/p99；`GOMEMLIMIT` 或 systemd `MemoryMax` 单独使用不能证明不会 OOM。

### S4 — 缺少全局会话/队列字节预算，登录检查为 O(N)

**P1：大规模部署阻断项；结构与孤立测量确认，未做真实容量压测。**

位置：`core.go` 的 `acquire`、`atSessionLimit`、`readNetwork`，`tunnel.go` 的 `newCapsuleReader`。

默认每用户最多 8 个会话，地址池也限制总量；但没有独立的全局会话预算、排队字节预算或用户间带宽公平机制。每个会话直接分配 1,024 个队列槽和 32 KiB Capsule 读取缓冲。本环境 `queued` 为 48 字节，仅这两部分就约 **80 KiB/空闲会话**：10,000 个约 781 MiB，还没计入 QUIC、socket、goroutine、解析器和其他状态。若队列塞满 1,350 字节报文，单个会话的排队 payload 约 1.32 MiB；这是容量估算，不是已测 RSS。

`atSessionLimit` 在会话锁内遍历所有活动地址，分配时执行不止一次。诊断用 100、10,000、100,000 个地址各做 100 次检查，分别约 0.8 µs、0.10 ms、1.56 ms/次；这是本机孤立测量，不能解释为生产吞吐或延迟上限。双栈会话还占用两个地址条目。其他会话统计和重连记录清理也需要检查峰值成本。

应改为锁内一致维护的每用户计数，加入全局 admission 上限和队列字节预算，按需分配队列，明确拥塞时的公平丢弃策略。地址池的有限性仍须保留。默认 `10.89.0.1/24` 只有约 253 个可用客户端 IPv4 地址，不能支撑上千个同时活动的会话；每个并发会话占一个地址。扩大网段前要检查宿主/VPC/LAN/Docker/Kubernetes 路由冲突。

### S5 — 地址复用的 conntrack 清理会读取整张表

**P1：大连接表、高重连频率下的容量阻断项；依赖调用链确认。**

位置：`internal/hostnet/hostnet_linux.go` 的 `Forget`；`github.com/vishvananda/netlink v1.3.1` 的 `ConntrackDeleteFilters`。

依赖先通过 `NLM_F_DUMP` 读取整个地址族的 conntrack 表，保存原始条目，再在用户态匹配并逐个确认删除。清理一个复用地址也有 O(整张表) 的读取和内存成本；不是只向内核提交一个地址过滤条件。大地址池的新地址和同凭据短期重连能减少调用，但小池高周转和百万连接表仍需要专门测量。

清理旧 NAT 状态是用户隔离的必要保护，当前失败后拒绝分配是正确的。**不能删除检查，也不能在失败时继续把地址交给别人。**应研究内核侧过滤、隔离 conntrack zone/网络命名空间、受限且合并的清理任务；用真实大表验证延迟、峰值内存和失败恢复后再选择方案。当前没有“百万连接已通过”的证据。

### S6 — 带点接口名的 sysctl 路径构造错误

**P2：配置兼容性、PMTU 与 IPv6 可用性；源码确认，实际 VLAN/TUN 场景待验证。**

位置：`internal/hostnet/hostnet_linux.go` 的 `SetSysctl`、`changeSysctl`、`keepRouterAdvertisements`。

把所有 `.` 替换为 `/`，使合法 Linux 接口 `vpn.0` 的 `net.ipv4.conf.vpn.0.accept_local` 变成 `.../conf/vpn/0/accept_local`；实际目录应是 `.../conf/vpn.0/accept_local`。物理 VLAN 接口 `eth0.100` 的 `accept_ra` 也有同样问题。前者可能破坏 PMTU 错误回送，后者可能使启用 IPv6 forwarding 后无法保留依赖 RA 的默认路由。

应显式构造 `/proc/sys` 路径组件，保留接口名中的点，并让保存/恢复使用同一路径函数。补充带点 TUN 和 VLAN 的真实命名空间测试；同时校验 Linux 接口名约束。目前仅检查长度不足以尽早拒绝所有无效名称。

### S7 — TTL/Hop Limit 的内核委托边界未完成验证

**P1：规范验收的待验证项；不是已经证明的 MUST 违规。**

[RFC 9484 §7.2](https://www.rfc-editor.org/rfc/rfc9484.html#section-7.2) 说明跨链路转发在 encapsulation 时递减 TTL/Hop Limit，在 decapsulation 时不递减；该节也明确指出，依赖外部软件路由的实现可能不直接承担这些路由要求。

本实现把客户端报文原样写入 TUN，由 Linux 转发和递减 TTL；反向报文在内核路由到 TUN 后封装。现有 fake-TUN 测试要求原样报文，真实内核测试验证了 NAT 和双向 UDP，但没有断言 TTL/Hop Limit、TTL=1、255、traceroute 或 ICMP Time Exceeded 的行为。

需要先明确“HTTP 隧道链路、共享 TUN 和内核路由器”分别承担什么角色，在 TUN/WAN 两侧抓取 IPv4、IPv6 报文，验证两个方向和本地产生/本地终止报文是否只发生应有的路由跳数。**不能直接给收到的 TTL 加 1**：这会在 255、校验和、本地目的地和超时报文处引入新的错误。尚未完成这项验证前，不签署完整 §7.2 符合性结论。

### S8 — 宿主网络所有权和部署边界需要收紧

**P2：运维隔离与故障恢复；源码确认。**

同一进程接口变更已修复，但两个独立 Caddy 进程若使用不同 TUN，仍会共享固定 `inet caddy-masque` nftables 表和宿主 sysctl；不应视为可安全独立运行。建议每网络命名空间只运行一个网络管理实例，或重新设计表名、sysctl 所有权和生命周期管理。

`manage_network off` 会把防火墙、NAT、forwarding 的责任交给管理员，模块不会安装默认宿主保护 input 链；`allow_host_access` 的默认值不能代替外部防火墙。`Repair` 每 30 秒检查表是否存在，不检查表内规则是否被部分清空；外部命令没有执行超时，清理时部分错误被忽略。应补规则完整性检查、外部命令期限和故障指标，并验证与 UFW、Docker、firewalld 的真实组合。当前已经验证的修复/清理顺序不能证明这些组合均可靠。

`tunnel.go` 还按 `Source`/`Conn` 字段名用反射解开 Caddy 的 body/连接包装。当前版本有测试，但字段名不是稳定的公开解包契约；升级后可能重新受到 idle timeout 影响或无法应用 TCP 设置。应优先采用公开解包接口，保持依赖版本与升级回归测试一致。现有 systemd 沙箱、0600 admin socket、工作流只读权限和关闭 checkout credential 持久化值得保留；第三方 Actions 的版本 tag 仍可进一步锁定为审核过的提交 SHA。

配置校验还接受广播地址 `10.89.0.255/24`、没有可分配客户端地址的 `10.89.0.1/31`、链路本地池 `169.254.89.1/24`。这可能造成不可用或违背默认网络隔离意图，来源是管理员配置。应在加载阶段验证可用池、地址类别和冲突，明确支持范围；对链路本地流量坚持 RFC 9484 §7.2 的限制。

### S9 — Cloudflare provider 的错误路径可能输出 API token

**P2：凭据日志泄露；第三方源码确认，未使用真实 token。**

组合构建锁定的 Cloudflare provider `0.2.4`、提交 `a8737d095ad5a48ca031cea6ab704057dbc2d250`，在 [`Provision`](https://github.com/caddy-dns/cloudflare/blob/a8737d095ad5a48ca031cea6ab704057dbc2d250/cloudflare.go) 的无效 token 错误中插入了 token 原文。换行或不符合检查的值可能进入验证/启动日志。

这是 Cloudflare provider 的校验错误问题，与 MASQUE 的报文格式无关。应向上游改为脱敏错误并锁定修复版本；操作侧使用最小权限、限制 zone 的 token，保护环境文件和日志访问。移除 systemd 的 `--environ` 已消除另一条启动泄露路径，但不能消除 provider 自身这条错误路径。DNS 插件可与 MASQUE 共存；这不等于真实 DNS 签发和续期已经验证。

### S10 — 丢包观测与测试脚本隔离不足

**P2：运维与测试安全；源码确认。**

`core.readNetwork` 中 `toClient` 队列满时直接丢弃，没有增加现有 dropped counter，指标会漏报拥塞丢包。应增加原因明确、低基数的丢包和 admission/认证繁忙指标；大量用户名标签也需要评估指标基数。metrics/admin 端点须限制访问。

原有 `tests/e2e-netns.sh` 使用固定 `mq-*` 名称，开始时会删除同名已有网络命名空间；不能在生产宿主上直接运行。应拒绝已有命名空间或采用唯一名称，并在破坏性操作前检查运行环境。本次原生验证在一次性 GitHub runner 的隔离命名空间中进行，没有执行该脚本修改生产机器。

## 已检查的规范与保护措施

以下是本次检查结果，不是覆盖全部 RFC 条款的认证表。

| 要求/区域 | 检查结果与边界 |
| --- | --- |
| RFC 9484 §3 URI Template | 默认模板及 level/operator 限制有测试；S2 的 fragment 和 scheme 校验仍有遗漏 |
| RFC 9484 §4 加密与请求编码 | TLS 前提、H1 Upgrade、H2/H3 extended CONNECT、成功状态和 Capsule-Protocol 均有实现及集成测试 |
| RFC 9484 §4.1 畸形请求 | H3 使用 `H3_MESSAGE_ERROR`；H2 存在 S1 的已复现错误码缺口 |
| RFC 9484 §4.6 目标范围 | `target`/`ipproto` 解析、DNS 解析失败与 Proxy-Status、按目标/协议收窄访问有测试 |
| RFC 9484 §4.7 地址/路由 Capsule | 字段长度、版本、前缀、顺序、协议 0 的重叠检查有测试；全量地址回应和 Request ID 回显有测试 |
| RFC 9297 Capsule 解析 | 分块读取、截断、未知类型跳过和长度上限有测试；资源限制未引入私有线上格式；H2 错误仍受 S1 影响 |
| HTTP/3 DATAGRAM 协商 | 检查双方设置，无法使用 QUIC DATAGRAM 时采用标准 Capsule 承载；不关闭 QUIC 拥塞控制 |
| RFC 9484 §6 Context ID | 使用 Context ID 0；未知 context 的处理有测试 |
| RFC 9484 §7.2 报文处理 | 源地址必须属于本会话；转发校验失败丢包，不将普通 IP 转发错误都误判为隧道协议错误；TTL 仍须完成 S7 |
| IPv6 最小 MTU / RFC 9484 §7.2 | 默认发送 1,280 字节完整 Echo 探测，校验来源、序号、内容和校验和；不足以承载 IPv6 时结束隧道；关闭探测须另有 MTU 保证 |
| IPv4 分片、IPv6 Packet Too Big | DF/分片/ICMP 大小、校验和及返回方向有测试；真实低 MTU、中间代理路径还需验证 |
| RFC 9484 §10 ICMP/拥塞 | ICMP 限速；保留 QUIC 拥塞机制；没有把可靠 Capsule 通道错误当作数据报拥塞控制的替代 |
| 身份与访问隔离 | Argon2id、随机密码、有限等待、每来源限制、凭据缓存；默认阻止私有/链路本地/metadata/NAT64 相关目的地；改密撤销与 conntrack 隔离有测试 |
| 热重载/结束 | 撤销用户、密码变化、配置收窄和服务停止结束会话；网络参数变更要求重启；真实服务生命周期有原生测试 |

两个容易混淆的边界：

- 这是远程访问 VPN 服务端。客户端发送合法地址/路由公告会被解析，但不会自动安装为站点互联路由。RFC 9484 允许此类用途，并不意味着每个部署都必须支持所有拓扑；应明确产品范围。
- 路由收窄时关闭原隧道是实现选择的保守策略。不要把“关闭所有受影响会话”说成 RFC 唯一允许的做法；任何未来动态更新也必须保持请求流与地址/路由状态一致。

## 本次验证与复现方法

本地使用 Go 1.26.8，运行：

```sh
go vet ./...
go test -race -count=1 -json ./...
bash tests/audit-ietf.sh
```

全量 race 结果：**172 个测试/子测试通过，6 个跳过，0 个失败**；跳过项包括需要特权的内核检查、缺少 nft 的规则检查及内核测试子进程辅助入口。三个包没有测试文件，不能计为有测试覆盖。接口重载专项和阻塞写专项的重复测试另见上文。

`tests/audit-ietf.sh` 使用 Go overlay 在临时目录注入诊断，不改写工作树、不修改宿主网络、只使用测试配置和临时 Caddy 状态目录。它测量 HTTP/2 帧、配置校验、认证预算和会话扫描成本；[本次输出](audit-output-2026-10-04.txt) 随报告保存。**诊断显示 PASS 只意味着测量完成；S1/S2 的输出恰恰展示不符合项。**不把这些诊断纳入自动“合规通过”判据。脚本中的最高 Argon2 参数仅被解析，不运行高成本 hash。

此前已完成的 packet/capsule fuzz、安装回滚、离线 Cloudflare provisioning 和真实内核数据通路验证详见 [生产验证记录](production-readiness-2026-10-03.md)。同一实现提交 `3d7537e` 的 [CI](https://github.com/ArcCal/caddy-masque/actions/runs/37168812585)、[源码漏洞扫描](https://github.com/ArcCal/caddy-masque/actions/runs/37168812583)、原生组合构建 [arm64](https://github.com/ArcCal/caddy-masque/actions/runs/37169055101) 和 [amd64](https://github.com/ArcCal/caddy-masque/actions/runs/37169056521) 均已通过。两种架构各验证真实 IPv4/IPv6 TUN/NAT、三种 HTTP 传输和独立 `connect-ip-go` 客户端、systemd 生命周期与安装回滚；两份下载包的 SHA-256、静态 ELF 架构和源码提交号已核对。上述连通性通过仍不关闭 S1/S7。

本地重新扫描源仓库及按 Artifact 的 `go.mod`/`go.sum` 重建的组合程序源码，调用分析均报告 **0 个可达已知漏洞**，但 required module 中有 [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)（未维护的 `x/crypto/openpgp`）。对删除符号表的 arm64 Artifact 做 binary-mode 扫描时，该告警被报告为命中；`govulncheck v1.8.0` 的 `ExtractPackagesAndSymbols` 在 stripped binary 上退回模块元数据，不能提供调用可达性证据。使用相同实现、依赖和 Go 版本重建保留符号表的 amd64 程序，binary-mode 扫描报告 0 命中，`go tool nm` 也没有 OpenPGP 符号。[各次扫描输出](audit-vulncheck-2026-10-04.txt) 均保留，不能把 stripped 模式的模块命中直接写成已证明的可利用路径，也不能把源码的 0 可达写成所有依赖都安全。依赖告警仍需持续跟踪。

以下仍未验证：真实 Cloudflare DNS challenge 签发/续期、原私有 Rust 客户端当前版本的端到端互操作、生产网络拓扑、多租户故障、真实大规模/长期压力、S7 的 TTL 边界。GitHub job 的绿色状态不能把因缺少 `MASQUE_VPN_TOKEN` 而跳过的步骤变成已测试。

## 改进顺序与验收门槛

1. **严格标准门槛：**完成 S1 的跨构建一致流错误修复、S2 URI 组件校验，并实测和明确 S7 内核委托边界。协议负面用例必须断言规范规定的错误，不能只断言“连接断开”。
2. **规模和资源门槛：**实现 S3 的认证内存预算、S4 的全局 admission/队列预算与常数时间计数，验证 S5 在大 conntrack 表下的清理成本和失败隔离。给出 CPU、内存、吞吐、会话数和登录峰值的可测容量范围。
3. **宿主可靠性门槛：**修复 S6，完善 S8 的配置与所有权检查，验证网络冲突、规则漂移、低 MTU、IPv6 RA、服务重启和回滚；补 S10 的完整丢包指标和安全测试入口。
4. **部署与凭据门槛：**处理 S9，完成真实 DNS 签发/续期与目标客户端的 staging 测试，限定 token 权限、admin socket 权限和日志访问。先在隔离环境验证，再部署生产。

保留标准 HTTP/3、HTTP/2、HTTP/1.1 与 DNS 插件集成。当前证据不支持删除协议校验、访问控制、MTU 检查或 conntrack 隔离来换取性能；也不支持新增私有协议扩展。完成上述门槛前，PR 保持 draft，不能宣称“完全符合 IETF”或“已验证大规模生产就绪”。

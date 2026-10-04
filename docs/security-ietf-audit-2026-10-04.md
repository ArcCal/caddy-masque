# caddy-masque 安全、实现合理性与 IETF 审计（2026-10-04）

## 结论

**当前实现不能被认定为完全符合 IETF 规范，也尚不足以签字确认适合大规模生产部署。**

核心隧道、身份隔离、报文解析和默认访问控制已有较好的保护。本次没有发现可复现的未经认证接管隧道或跨用户读取报文的路径；这不是“没有漏洞”的证明。HTTP/2 错误处理仍与规范要求不符。后续修复已补 URI 组件校验、认证内存预算、全局会话和队列预算；Linux TTL/Hop Limit 的基本委托边界已通过真实内核检查。conntrack 大表成本、真实容量及实际部署拓扑仍待验收。

修复必须保留 RFC 定义的消息、地址、路由和错误语义。不能把“客户端仍能连接”“返回 400”或“测试全绿”等同于符合规范；不能靠关闭报文检查、跳过 conntrack 清理、补偿性修改 TTL 或自定义 Capsule 来掩盖问题。

用户进一步明确，保持与 [ArcCal/masque-vpn](https://github.com/ArcCal/masque-vpn) 真实客户端兼容也是目标。后续改动须同时通过规范、安全可靠性和 [目标客户端兼容性验收](client-compatibility.md)；既不能为旧行为牺牲 RFC 要求，也不能只验证模拟客户端就宣称完成真实兼容。后续已通过托管 HTTPS API 读取固定提交的客户端源码并完成六种传输/IPv6 组合的真实 CLI 测试；macOS 应用、TUN 模式与实际组合 Artifact 的完整验收仍未完成。

## 范围与证据边界

初次审计基线：[`3d7537ee375953d3ec5d9f1d3be67e4b20b056e7`](https://github.com/ArcCal/caddy-masque/commit/3d7537ee375953d3ec5d9f1d3be67e4b20b056e7)，`production-readiness` 分支。包含此前生产改进和本次接口重载修复。后续实现提交为 [`d414d2a07eb5e9d305fbf7d82fc46efe8302dd18`](https://github.com/ArcCal/caddy-masque/commit/d414d2a07eb5e9d305fbf7d82fc46efe8302dd18)，以下状态已按该提交更新。

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

## 发现与修复状态

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

### S2 — URI Template 组件校验已修复

**P2：已修复本次复现的 fragment/scheme 遗漏；先失败后通过的专项测试。**

`ParseTemplate` 现在检查 scheme 首字符，先区分 authority、path/query 和 fragment，再解析变量。变量位于 literal `#` 后时拒绝模板；无变量的固定 fragment 允许保留在原始 URI，但不发送到 HTTP request target；`%23` 仍是编码的路径字面量。authority 前的 query/fragment 分隔符也不能被误认为 path。

`TestTemplateURIComponents` 的七个畸形组件用例在修复前失败，修复后通过；另外验证合法自定义 scheme、固定 fragment、编码 `#` 和扩展后的匹配。未引入私有 URI 格式，原有操作符/level 4 和匹配成本限制保留。这关闭所列复现，不代表已经穷尽 RFC 6570 的全部文法组合。

### S3 — 认证已增加加权内存和等待预算，真实容量仍待验收

**P1：基础资源缺陷已修复；分布式负载、容器 RSS/p95/p99 验收未关闭。**

原先 `2 × NumCPU()` 个并发 hash、每 hash 允许 1 GiB 的组合没有总内存预算。参数由管理员配置，但未认证错误凭据可以触发其成本。初次诊断的 10 GiB 是容量估算，没有实际分配这些内存。

现在 CPU admission 使用 `2 × GOMAXPROCS(0)`，另按 PHC `m` 参数加权保留 Argon2 工作内存。默认 `auth_memory 128` MiB，可配置 19–1024 MiB；配置加载拒绝单 hash 超过预算。CPU 与内存等待共用最多 5 秒 admission 期限，返回 503；已开始的 hash 在调用者取消后仍持有 CPU、来源和内存额度，直到真正完成。预算变更需要重启，避免跨配置遗失在途额度。

新增测试验证超预算配置、只缺内存时的取消/恢复、开始 hash 后取消仍保留额度，以及等待超时的资源释放。原有每来源限制、正确凭据缓存、撤销语义和 PHC 兼容性保留。当前机器 `NumCPU=5`、`GOMAXPROCS=4`、CPU slots=8、聚合工作内存预算=128 MiB。

预算不是 RSS 上限：Argon2 临时内存等待 GC 回收、Caddy 和 HTTP/QUIC 仍需额外空间。19 MiB 默认 hash 同时最多六个；不能据此保证首次登录在分布式攻击下总能成功。仍需在真实 CPU/内存限制和业务负载下测量；`GOMEMLIMIT`/systemd `MemoryMax` 单独使用不构成 OOM 安全证明。

### S4 — 会话和队列已增加全局预算，大规模性能仍待验收

**P1：基础 admission/排队缺陷已修复；真实容量、带宽公平及其他 O(N) 路径仍开放。**

新增 `max_total_sessions`（默认 1024，允许重载）和 `queue_memory`（默认 64 MiB，1–1024 MiB，变更需重启）。按用户计数在锁内维护，限额检查不再扫描活动地址。待分配、正在 conntrack 清理、已撤销但尚未完成清理的会话均占 admission；失败/取消回滚，lease 清理幂等。每用户限额仍是 429，全局资源不足采用标准 503，不改变 Capsule/Datagram 线上格式。

队列共享原子 payload 预算，先检查容量/预算再复制报文；取出、过期丢弃和 lease 结束都归还额度。enqueue 与 queue cleanup 同步，避免关闭后重新入队和额度泄漏。满队列/预算不足增加现有 dropped counter。并发 admission、阻塞清理时的取消、双栈只计一次、撤销保持额度、重复清理、跨队列预算与关闭/入队竞争均有 race 回归。

每会话仍预分配 1024 个槽；现在 `queued` 为 56 字节，另有 32 KiB Capsule 缓冲，约 88 KiB/空闲会话。默认 1024 个 admission 约 88 MiB，仅是这些固定结构的估算，未包含协议状态、payload 和 GC。预算不包含在途写、slice 分配取整或其他堆对象。没有承诺内存/带宽的用户间公平；`recent` 清理、指标统计和 conntrack 仍有扫描路径。

默认 `/24` IPv4 池约 253 个可用客户端地址；扩大限额不能扩大地址池。新诊断显示限额检查的成本不再随 100/10000/100000 个地址明显增长，但纳秒级孤立测量不是生产容量。仍需真实长期压力、重连峰值、RSS 和延迟测量，并检查 VPC/LAN/容器路由冲突。

### S5 — 地址复用的 conntrack 清理会读取整张表

**P1：大连接表、高重连频率下的容量阻断项；依赖调用链确认。**

位置：`internal/hostnet/hostnet_linux.go` 的 `Forget`；`github.com/vishvananda/netlink v1.3.1` 的 `ConntrackDeleteFilters`。

依赖先通过 `NLM_F_DUMP` 读取整个地址族的 conntrack 表，保存原始条目，再在用户态匹配并逐个确认删除。清理一个复用地址也有 O(整张表) 的读取和内存成本；不是只向内核提交一个地址过滤条件。大地址池的新地址和同凭据短期重连能减少调用，但小池高周转和百万连接表仍需要专门测量。

清理旧 NAT 状态是用户隔离的必要保护，当前失败后拒绝分配是正确的。**不能删除检查，也不能在失败时继续把地址交给别人。**应研究内核侧过滤、隔离 conntrack zone/网络命名空间、受限且合并的清理任务；用真实大表验证延迟、峰值内存和失败恢复后再选择方案。当前没有“百万连接已通过”的证据。

### S6 — 带点接口名的 sysctl 路径已修复

**P2：已修复；arm64/amd64 原生组合构建和 CI 内核回归均通过。**

每接口 sysctl 现在使用显式 slash 路径，例如 `net/ipv4/conf/mq.test/accept_local`，保留接口名中的点。全局 dotted sysctl 仍兼容原有调用；读、保存、恢复与写使用同一路径函数。

真实命名空间生命周期测试使用 `mq.test` TUN 和 `wan.100` veth，断言 TUN `accept_local=1`、启用 IPv6 forwarding 时 WAN `accept_ra=2`，关闭后恢复原值。普通本地 suite 因无特权跳过该用例；原生 arm64 组合构建和 amd64 CI 已真正运行并通过该用例。配置阶段另拒绝 `/`、`:`、空白、NUL、`.`/`..` 等无效 Linux 名称，合法 `vpn.0` 保持可用。

### S7 — Linux TTL/Hop Limit 的基本委托边界已验证

**原 P1 待验证项：标准 Linux 路由路径已验证；复杂路径与真实目标客户端仍需验收。不是已证明的 MUST 违规。**

[RFC 9484 §7.2](https://www.rfc-editor.org/rfc/rfc9484.html#section-7.2) 说明跨链路转发在 encapsulation 时递减 TTL/Hop Limit，在 decapsulation 时不递减；该节也明确指出，依赖外部软件路由的实现可能不直接承担这些路由要求。

本实现把客户端报文原样写入 TUN，由 Linux 转发和递减 TTL；反向报文在内核路由到 TUN 后封装。HTTP 隧道/TUN 适配层不额外修改跳数，Linux 是外部 IP 路由器。fake-TUN 原样报文断言保留，没有加入补偿性 TTL 修改。

实现 `e649126e66d07016e4eac0716367cb1006af489b` 的 [原生 CI](https://github.com/ArcCal/caddy-masque/actions/runs/37176808547) 已通过新增内核测试。三种 HTTP 传输、IPv4/IPv6 中，origin 用 socket ancillary data 实测客户端 64 → 63、255 → 254；origin 明确设置回包 64，客户端收到 63。跳数 1 发往远端返回 ICMP Time Exceeded，引用的源/目的地正确；跳数 1 发往本地网关得到 Echo Reply，回包保持 64。独立 `connect-ip-go` 客户端自身先递减一次，故 origin 实测 62/253；测试明确区分这个额外客户端路由跳数。

这些结果确认所测 Linux/TUN/WAN 路径没有重复递减、255 回绕或本地目的地误递减。`manage_network off` 或其他外部路由软件必须独立保证同样的行为；低 MTU、中间代理、多跳拓扑、真实 Rust TUN/macOS 仍需要部署验证。**不能直接给收到的 TTL 加 1**，也不能据上述边界测试签署完整 §7.2 或所有 RFC 符合性结论。

### S8 — 已加固宿主网络所有权与规则恢复，部署组合仍待验收

**P2：基础所有权、规则漂移和命令/清理问题已修复；外部网络管理器组合仍开放。**

自动网络管理在创建 TUN、改变 sysctl/nftables 前取得按 network namespace inode 命名的非阻塞 `flock`，持续持有到清理完成。竞争者提前失败，崩溃后内核释放锁；拒绝符号链接、硬链接、非正规文件及不安全所有权/写权限。锁文件不删除。systemd 设置 `RuntimeDirectoryPreserve=yes`，防止停止时删除 inode 导致接管者与新进程锁住不同文件。共享网络命名空间的容器必须共享 `/run/caddy-masque`；私有运行目录不能互相协调。独立网络命名空间允许独立管理。

`Repair` 现在比较安装后读取的 nftables JSON，忽略 handle/metainfo，保留链策略、hook、priority、规则顺序和表达式；部分清空和额外规则也会修复。检查失败不再直接推断表消失，只有成功枚举确认缺失才重新安装。每条命令最多 5 秒、输出最多 64 KiB；进程退出后的 pipe 等待也有限。关闭幂等，清理失败向 Caddy 上报；恢复 sysctl 前检查当前值仍等于本进程安装值，不覆盖可辨识的后续管理员修改。这是非原子的 best-effort 比较，不是与所有管理软件的事务协调。systemd 留 45 秒给正在运行的修复及清理。

跨进程争用/崩溃释放、不安全锁路径、命令超时/输出限额、并发关闭、sysctl 恢复和检查失败的只读行为均有本地 race 回归。原生内核测试进一步验证竞争者不创建 TUN、独立 namespace 不受父锁阻挡，以及 input/forward/postrouting 清空和插入额外规则后的恢复。后续服务测试检查运行目录在 restart/stop 后的身份；结果随最新交付记录保存。

`manage_network off` 不安装默认宿主保护 input 链，访问控制责任交给管理员。30 秒 watcher 不能提供外部 flush 后的即时保护，也不与任意 UFW、Docker、firewalld 策略自动协调；仍需故障指标、报警及真实组合验证。Linux forwarding sysctl 的系统性副作用和生产路由冲突也须按实际宿主验收。

崩溃会释放锁/TUN，但不会执行 `Close`，原始 sysctl 值仅保存在内存；下一次启动能替换保留表，却不能恢复已经丢失的崩溃前 forwarding 原值。这是源码可确认的恢复边界，尚未新增真实进程崩溃/持久状态恢复验收，不能把锁自动释放写成完整网络回滚。

`tunnel.go` 还按 `Source`/`Conn` 字段名用反射解开 Caddy 的 body/连接包装。当前版本有测试，但字段名不是稳定的公开解包契约；升级后可能重新受到 idle timeout 影响或无法应用 TCP 设置。应优先采用公开解包接口，保持依赖版本与升级回归测试一致。现有 systemd 沙箱、0600 admin socket、工作流只读权限和关闭 checkout credential 持久化值得保留；第三方 Actions 的版本 tag 仍可进一步锁定为审核过的提交 SHA。

配置校验已拒绝广播地址 `10.89.0.255/24`、无可用地址的 `10.89.0.1/31`、链路本地、loopback、multicast 网关和过小 IPv6 池；已补合法小池/带点接口和错误配置测试。这是本实现的可分配池限制，不是宣称 IETF 禁止 /31 或 /127 的点到点用途。真实宿主路由冲突检测仍未完成；链路本地转发限制始终保留。

### S9 — Cloudflare provider 的错误路径可能输出 API token

**P2：凭据日志泄露；第三方源码确认，未使用真实 token。**

组合构建锁定的 Cloudflare provider `0.2.4`、提交 `a8737d095ad5a48ca031cea6ab704057dbc2d250`，在 [`Provision`](https://github.com/caddy-dns/cloudflare/blob/a8737d095ad5a48ca031cea6ab704057dbc2d250/cloudflare.go) 的无效 token 错误中插入了 token 原文。换行或不符合检查的值可能进入验证/启动日志。

这是 Cloudflare provider 的校验错误问题，与 MASQUE 的报文格式无关。应向上游改为脱敏错误并锁定修复版本；操作侧使用最小权限、限制 zone 的 token，保护环境文件和日志访问。移除 systemd 的 `--environ` 已消除另一条启动泄露路径，但不能消除 provider 自身这条错误路径。DNS 插件可与 MASQUE 共存；这不等于真实 DNS 签发和续期已经验证。

### S10 — 满队列丢包已计数，测试入口已改善隔离

**P2：丢包遗漏已修复；测试脚本完整特权验收仍未运行。**

队列满或共享 payload 预算不足时增加现有 dropped counter，结束队列也会释放剩余 packet 额度。仍应增加 admission/认证繁忙的低基数观测，并评估用户名标签的指标基数；metrics/admin 端点需要限制访问。

`tests/e2e-netns.sh` 现在使用随机后缀的命名空间和宿主临时 veth 名，拒绝已有命名空间/解析器目录；只清理本次成功创建的命名空间，创建 veth 失败后不会继续移动同名宿主接口。命令 spy 已验证冲突时在任何网络修改前退出；shell 语法检查通过。这不代替整个脚本的真实特权运行，GitHub Rust e2e 因缺少 secret 仍跳过。仍只允许在一次性测试宿主运行该脚本。

## 已检查的规范与保护措施

以下是本次检查结果，不是覆盖全部 RFC 条款的认证表。

| 要求/区域 | 检查结果与边界 |
| --- | --- |
| RFC 9484 §3 URI Template | 默认模板及 level/operator 限制有测试；S2 所列 fragment/scheme 用例已修复 |
| RFC 9484 §4 加密与请求编码 | TLS 前提、H1 Upgrade、H2/H3 extended CONNECT、成功状态和 Capsule-Protocol 均有实现及集成测试 |
| RFC 9484 §4.1 畸形请求 | H3 使用 `H3_MESSAGE_ERROR`；H2 存在 S1 的已复现错误码缺口 |
| RFC 9484 §4.6 目标范围 | `target`/`ipproto` 解析、DNS 解析失败与 Proxy-Status、按目标/协议收窄访问有测试 |
| RFC 9484 §4.7 地址/路由 Capsule | 字段长度、版本、前缀、顺序、协议 0 的重叠检查有测试；全量地址回应和 Request ID 回显有测试 |
| RFC 9297 Capsule 解析 | 分块读取、截断、未知类型跳过和长度上限有测试；资源限制未引入私有线上格式；H2 错误仍受 S1 影响 |
| HTTP/3 DATAGRAM 协商 | 检查双方设置，无法使用 QUIC DATAGRAM 时采用标准 Capsule 承载；不关闭 QUIC 拥塞控制 |
| RFC 9484 §6 Context ID | 使用 Context ID 0；未知 context 的处理有测试 |
| RFC 9484 §7.2 报文处理 | 源地址必须属于本会话；转发校验失败丢包，不将普通 IP 转发错误都误判为隧道协议错误；S7 已验证基本 Linux TTL/ICMP 边界，复杂部署仍待验收 |
| IPv6 最小 MTU / RFC 9484 §7.2 | 默认发送 1,280 字节完整 Echo 探测，校验来源、序号、内容和校验和；不足以承载 IPv6 时结束隧道；关闭探测须另有 MTU 保证 |
| IPv4 分片、IPv6 Packet Too Big | DF/分片/ICMP 大小、校验和及返回方向有测试；真实低 MTU、中间代理路径还需验证 |
| RFC 9484 §10 ICMP/拥塞 | ICMP 限速；保留 QUIC 拥塞机制；没有把可靠 Capsule 通道错误当作数据报拥塞控制的替代 |
| 身份与访问隔离 | Argon2id、随机密码、有限等待、每来源限制、凭据缓存；默认阻止私有/链路本地/metadata/NAT64 相关目的地；改密撤销与 conntrack 隔离有测试 |
| 热重载/结束 | 撤销用户、密码变化、配置收窄和服务停止结束会话；网络参数变更要求重启；真实服务生命周期有原生测试 |

两个容易混淆的边界：

- 这是远程访问 VPN 服务端。客户端发送合法地址/路由公告会被解析，但不会自动安装为站点互联路由。RFC 9484 允许此类用途，并不意味着每个部署都必须支持所有拓扑；应明确产品范围。
- 路由收窄时关闭原隧道是实现选择的保守策略。不要把“关闭所有受影响会话”说成 RFC 唯一允许的做法；任何未来动态更新也必须保持请求流与地址/路由状态一致。

## 本次验证与复现方法

初次基线 `3d7537e` 的本地验证使用 Go 1.26.8，运行：

```sh
go vet ./...
go test -race -count=1 -json ./...
bash tests/audit-ietf.sh
```

该初次基线的全量 race 结果：**172 个测试/子测试通过，6 个跳过，0 个失败**；跳过项包括需要特权的内核检查、缺少 nft 的规则检查及内核测试子进程辅助入口。三个包没有测试文件，不能计为有测试覆盖。接口重载专项和阻塞写专项的重复测试另见上文。

`tests/audit-ietf.sh` 使用 Go overlay 在临时目录注入诊断，不改写工作树、不修改宿主网络、只使用测试配置和临时 Caddy 状态目录。它测量 HTTP/2 帧、配置校验、认证预算和会话扫描成本；[初次基线输出](audit-output-2026-10-04.txt) 随报告保存。**诊断显示 PASS 只意味着测量完成；初次基线 S1/S2 输出展示不符合项。** S2 等修复后的重新测量与真实 CLI 结果见 [后续输出](audit-followup-output-2026-10-04.txt)。不把这些诊断纳入自动“合规通过”判据。脚本中的最高 Argon2 参数仅被解析，不运行高成本 hash。

此前已完成的 packet/capsule fuzz、安装回滚、离线 Cloudflare provisioning 和真实内核数据通路验证详见 [生产验证记录](production-readiness-2026-10-03.md)。同一实现提交 `3d7537e` 的 [CI](https://github.com/ArcCal/caddy-masque/actions/runs/37168812585)、[源码漏洞扫描](https://github.com/ArcCal/caddy-masque/actions/runs/37168812583)、原生组合构建 [arm64](https://github.com/ArcCal/caddy-masque/actions/runs/37169055101) 和 [amd64](https://github.com/ArcCal/caddy-masque/actions/runs/37169056521) 均已通过。两种架构各验证真实 IPv4/IPv6 TUN/NAT、三种 HTTP 传输和独立 `connect-ip-go` 客户端、systemd 生命周期与安装回滚；两份下载包的 SHA-256、静态 ELF 架构和源码提交号已核对。上述连通性通过仍不关闭 S1/S7。

本地重新扫描源仓库及按 Artifact 的 `go.mod`/`go.sum` 重建的组合程序源码，调用分析均报告 **0 个可达已知漏洞**，但 required module 中有 [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)（未维护的 `x/crypto/openpgp`）。对删除符号表的 arm64 Artifact 做 binary-mode 扫描时，该告警被报告为命中；`govulncheck v1.8.0` 的 `ExtractPackagesAndSymbols` 在 stripped binary 上退回模块元数据，不能提供调用可达性证据。使用相同实现、依赖和 Go 版本重建保留符号表的 amd64 程序，binary-mode 扫描报告 0 命中，`go tool nm` 也没有 OpenPGP 符号。[各次扫描输出](audit-vulncheck-2026-10-04.txt) 均保留，不能把 stripped 模式的模块命中直接写成已证明的可利用路径，也不能把源码的 0 可达写成所有依赖都安全。依赖告警仍需持续跟踪。

以下仍未验证：真实 Cloudflare DNS challenge 签发/续期、目标 Rust 客户端的完整 TUN/gateway/实际组合 Artifact 与 macOS 验收、生产网络拓扑、多租户故障、真实大规模/长期压力。S7 的基本 Linux TTL 边界后来已验证，上文单独记录范围；真实 CLI 的六种组合已通过，见客户端兼容性记录。GitHub job 的绿色状态不能把因缺少 `MASQUE_VPN_TOKEN` 而跳过的步骤变成已测试。

## 后续实现与真实客户端验证（`d414d2a`）

本轮修复 S2 的已复现 URI 组件问题，补 S3/S4 的基础资源预算，修复 S6 的路径构造，并收紧 S8 的不可用地址池/接口配置，补 S10 的满队列指标和测试隔离。

- 同一实现的本地 full race suite，设置 `MASQUE_TEST_CLIENT` 使用真实 companion 二进制：**204 个测试/子测试通过，6 个跳过，0 个失败**。跳过项仍是特权/宿主工具及子进程辅助入口；三个无测试文件的包不计覆盖。
- session admission/queue 并发专项和认证预算/取消专项分别通过 **10 次 race 重复运行**。预算改变需重启、session 总量可重载、429/503 恢复和原隧道保持可用均通过回归。
- 客户端 commit **`ba82e36164a69c01a2a366153550aee2821c41b7`**，未改源码，Rust **1.99.0** locked build 成功，workspace **200 tests passed**。六个跨项目 CLI 用例通过，覆盖三种 HTTP 传输、IPv6 开/关与 H3/IPv6 关闭后探测存活；服务端 TUN 为模拟设备，完整模式/平台边界见 [兼容性记录](client-compatibility.md)。
- `go mod verify`、`go vet ./...`、格式/差异检查和 e2e shell 语法检查通过；命令 spy 验证已存在命名空间时不触发任何网络修改。
- [CI](https://github.com/ArcCal/caddy-masque/actions/runs/37173506367) 已通过 race/vet、真实内核和三个 20 秒 parser fuzz；Rust-client job 仍因 secret 缺失跳过。本地真实客户端测试的证据独立记录。
- [源码漏洞扫描](https://github.com/ArcCal/caddy-masque/actions/runs/37173506345) 报告 0 个可达漏洞、1 个 required-module advisory；stripped-binary 扫描的边界仍需保留，不能宣称所有依赖都无漏洞。
- 原生 [arm64 组合构建](https://github.com/ArcCal/caddy-masque/actions/runs/37173519441) 通过源代码测试、带点 TUN/WAN sysctl/RA 生命周期、真实 IPv4/IPv6 NAT 回包、三种传输与独立客户端、离线 Cloudflare 配置、实际候选二进制的 systemd/安装回滚。下载 [Artifact](https://github.com/ArcCal/caddy-masque/actions/runs/37173519441/artifacts/11292746630) 的 SHA-256、静态 aarch64 架构和完整源码 SHA 已核对。它没有完成真实 Rust 客户端/该组合 Artifact 的互通验收。
- 同实现原生 [amd64 组合构建](https://github.com/ArcCal/caddy-masque/actions/runs/37173520546) 也已全部通过；[Artifact](https://github.com/ArcCal/caddy-masque/actions/runs/37173520546/artifacts/11292397751) 的校验和、静态 x86-64 架构、源码提交和三个 custom modules 已核对。两种架构均为 Caddy 2.11.6、Cloudflare 0.2.4、Go 1.26.8。
- 最新只读诊断重新确认 S1 的两个 HTTP/2 错误码仍不合规；[后续测量/真实 CLI 输出](audit-followup-output-2026-10-04.txt) 明确保留该结果。诊断 PASS 不改变这一结论。

## 改进顺序与验收门槛

最新网络实现为 `e649126e66d07016e4eac0716367cb1006af489b`，加上 systemd 锁目录保留后的交付候选为 `2455ab70af40af6c8f364bc270265e97de27a3d6`。本地全量 race **225 个测试/子测试通过、8 个跳过、0 个失败**，包含真实客户端六种组合；hostnet 故障专项另通过 3 次 race 重复。

候选的 [CI](https://github.com/ArcCal/caddy-masque/actions/runs/37176965685)、[源码扫描](https://github.com/ArcCal/caddy-masque/actions/runs/37176965624)、原生组合构建 [arm64](https://github.com/ArcCal/caddy-masque/actions/runs/37176981769)/[amd64](https://github.com/ArcCal/caddy-masque/actions/runs/37176982669) 均已通过。两种原生构建真正执行了 S7 TTL/ICMP、S8 所有权/规则漂移，以及实际 Artifact 的服务目录保留、启停重载、安装回滚。下载包 SHA-256、静态架构和源码 SHA 已核对；详情、下载和证据见 [本轮记录](network-hardening-2026-10-04.md)。内核数据通路使用 source test binary，服务/安装检查使用组合 Artifact；不将它们写成已经完成真实 Rust/组合 Artifact 互通。

最新帧诊断仍复现 S1；源码扫描仍是 0 个可达已知漏洞、1 个 required-module advisory。GitHub private-client job 仍跳过；S3/S4 的真实容量、S5、S9、真实 macOS/模式和 DNS 续期门槛仍开放。

1. **严格标准门槛：**完成 S1 的跨构建一致流错误修复，保留 S2/S7 回归并验证实际外部路由部署边界。协议负面用例必须断言规范规定的错误，不能只断言“连接断开”。
2. **规模和资源门槛：**在真实资源限制和负载下验收 S3/S4 的新预算，验证 S5 在大 conntrack 表下的清理成本和失败隔离。给出 CPU、内存、吞吐、会话数和登录峰值的可测容量范围。
3. **宿主可靠性门槛：**保留 S6/S8 的原生回归，验证实际网络冲突、外部防火墙组合、低 MTU、IPv6 RA、服务重启和回滚；补 S10 的完整丢包指标和安全测试入口。
4. **部署与凭据门槛：**处理 S9，完成真实 DNS 签发/续期与目标客户端的 staging 测试，限定 token 权限、admin socket 权限和日志访问。先在隔离环境验证，再部署生产。

保留标准 HTTP/3、HTTP/2、HTTP/1.1 与 DNS 插件集成。当前证据不支持删除协议校验、访问控制、MTU 检查或 conntrack 隔离来换取性能；也不支持新增私有协议扩展。完成上述门槛前，PR 保持 draft，不能宣称“完全符合 IETF”或“已验证大规模生产就绪”。

# macOS 安全与极客防线

## 目录

1. 定位与威胁建模：macOS 与 iOS 防线的根本差异
2. Apple Silicon 硬件信任根
3. 安全启动链、启动策略与恢复防线
4. 系统完整性：SIP、签名系统卷与 AMFI
5. Gatekeeper、公证、隔离属性与路径随机化
6. TCC 隐私授权体系：macOS 特有的高价值权限面
7. 沙盒、系统扩展与内核攻击面收敛
8. FileVault、APFS 与静态数据保护
9. 钥匙串、Passkeys 与凭证窃取防线
10. Apple 内建防恶意软件栈：XProtect 与安全响应
11. 网络、外联控制与设备互联攻击面
12. 恶意软件与真实攻击案例
13. 国家级植入、MDM 滥用与供应链攻击
14. 持久化机制全景与检测方法
15. 取证、物理与现场防线
16. 分层加固清单、检测工具与持续防御

---

## 1. 定位与威胁建模：macOS 与 iOS 防线的根本差异

### 1.1 为什么 macOS 需要单独一套防线

许多用户把 macOS 当作"大屏版 iOS"，认为两者共享同一套安全模型。这个判断只对了一半。

macOS 与 iOS 共享硬件信任根（Secure Enclave、Apple Silicon 的 Boot ROM 与 PAC）、共享内核血统（XNU）、共享部分强制机制（代码签名、AMFI、沙盒、TCC）。但它们在设计目标上是两种截然不同的系统：

- **iOS 是封闭执行环境**：应用只能来自 App Store（欧盟外的地区），不能启动任意本地二进制，没有 shell，没有包管理器，不能加载内核扩展
- **macOS 是通用计算平台**：用户可以打开终端、执行任意脚本、安装 Homebrew、pip、npm、下载 DMG、双击 pkg、运行自己编译的 ELF/Mach-O

这意味着 macOS 的攻击面天然比 iOS 大一个数量级。iOS 上"攻击者必须先拿到零点击链或诱导点击链接"的约束，在 macOS 上被大大削弱——攻击者可以通过一个"看起来正常"的安装器、一个 npm 包、一个被篡改的开源二进制，就获得用户态代码执行。

但反过来，macOS 也有 iOS 不具备的优势：**它运行在企业安全栈之上**。EDR、MDM、SIEM、二进制白名单（Santa）、网络过滤（LuLu）在 macOS 上的成熟度远高于 iOS。因此 macOS 极客防线的重点不是"依赖系统默认"，而是"**如何把 Apple 的机制与主动检测栈组合成纵深**"。

### 1.2 macOS 的攻击面地图

```
┌───────────────────────────────────────────────────────────┐
│                    macOS 攻击面                             │
├──────────────────┬──────────────────┬─────────────────────┤
│  远程无交互       │  远程需一次点击   │  本地/用户态          │
├──────────────────┼──────────────────┼─────────────────────┤
│ iMessage 附件解析 │ Safari/WebKit    │ Shell / 脚本         │
│ FaceTime         │ Chrome/Firefox   │ 包管理器 (npm/pip)   │
│ APNs 载荷        │ 邮件富文本/链接   │ Homebrew / taps      │
│ 邮件通知解析      │ DMG / pkg 安装    │ Xcode 工具链         │
│ Spotlight 索引   │ 浏览器扩展         │ CI/CD Runner         │
│                  │ 共享文件 (SMB/AFP)│ SSH / 远程登录        │
├──────────────────┴──────────────────┴─────────────────────┤
│  近距与物理                                                │
│  Wi-Fi (AWDL) / 蓝牙 / Thunderbolt DMA / USB HID          │
│  恢复模式 / 单用户模式 / 固件密码 / 冷启动                  │
└───────────────────────────────────────────────────────────┘
```

### 1.3 对手分级与 macOS 现实

| 等级 | 对手 | 对 macOS 的典型手段 | 现实频率 |
|------|------|-------------------|---------|
| T0 | 批量广告软件 / PUA | 假 Flash 更新、捆绑安装、搜索引擎劫持 | 极高 |
| T1 | 信息窃取团伙 | 签名 + 公证的 stealer、npm/PyPI 投毒、假"清理工具" | 高 |
| T2 | 商业间谍软件 | iMessage/浏览器链、持久化 implant | 中（定向） |
| T3 | 国家级 APT | 定制 implant、MDM/更新服务器介入、0-day | 低但对特定人群高 |
| T4 | 执法取证 | FileVault 爆破、镜像、逻辑提取 | 中 |
| T5 | 内部/物理威胁 | 未锁屏、短暂接触、肩窥 | 高 |

**关键差异**：在 iOS 上，T0/T1 几乎无法获得持久代码执行；在 macOS 上，T0/T1 是主流且成功案例众多。Shlayer 这类广告软件在数年间感染量达数百万台，Atomic Stealer/AMOS 在 2023 年造成了可观的直接经济损失。**macOS 极客防线的第一优先级不是零点击链，而是"软件来源治理"**。

### 1.4 macOS 特有的结构性风险

1. **首次运行即完全信任**：Gatekeeper 只在应用**首次执行**时校验。一旦通过，后续运行不再重新评估。被放行的恶意二进制可以无限期运行
2. **TCC 由用户授予，而非开发者声明**：Full Disk Access、屏幕录制、辅助功能三大权限是 macOS 的"提权捷径"。大量真实攻击的核心不是漏洞利用，而是**骗用户点一个 TCC 授权弹窗**
3. **管理员账户是日常账户**：绝大多数 Mac 用户每天用 admin 账户。sudo 一次输入就获得 root。iOS 不存在这个概念
4. **公证 ≠ 安全**：多起真实案例（Silver Sparrow 等）显示攻击者使用**合法注册的 Developer ID 并完成 Apple 公证**。公证只证明"来源可追溯 + 无已知恶意软件扫描命中"，不证明无害
5. **内核与系统服务攻击面更宽**：IOKit 驱动栈、Mach 端口服务、系统守护进程数量远超 iOS，历史漏洞密度更高
6. **企业基础设施成为跳板**：MDM 服务商、构建服务器、代码签名证书被攻击，可以在下游形成"合法签名的恶意软件"

### 1.5 防线分层模型

本报告按七层组织 macOS 防线：

```
第 7 层  运营与响应：检测、取证、演练、事件处置
第 6 层  监控与加固：EDR/白名单/外联控制/MDM
第 5 层  软件治理：来源、公证、包管理、供应链
第 4 层  隐私授权：TCC、Full Disk Access、屏幕录制、辅助功能
第 3 层  执行控制：Gatekeeper、Hardened Runtime、沙盒、系统扩展
第 2 层  系统完整性：SIP、签名系统卷、AMFI、内核防护
第 1 层  硬件与加密：SEP、PAC、启动链、FileVault
```

每一层的假设是**上一层已被绕过**。攻击者拿到用户态代码执行是"何时"而非"是否"，因此第 6/7 层的可观测性在 macOS 上比 iOS 更关键。

### 1.6 威胁建模的三个问题

在决定投入多少精力之前，先回答三个问题：

1. **谁可能攻击我？**（广告软件 / 财务型团伙 / 定向间谍 / 取证机构）
2. **他们想要什么？**（凭据、钱包密钥、邮件会话、源码、通信内容、位置）
3. **哪一层是我当前的最弱点？**（通常是软件来源治理与 TCC 授权习惯）

对多数技术用户，答案是"财务型 stealer + 我自己的下载习惯"，防线重点在第 5 与第 4 层。对研究人员、记者、加密资产持有者，第 3、6、7 层的投入需要显著提高。

---

## 2. Apple Silicon 硬件信任根

### 2.1 Secure Enclave 在 Mac 上的角色

Mac 上的 Secure Enclave Processor（SEP）与 iOS 同源，但在 Apple Silicon 上被更深地整合进 SoC：

- **独立实时处理器**，运行 Apple 的 L5 微内核，拥有自己的内存与加密引擎
- **UID/HID 密钥**：一次性可编程、永不离开 SEP、Apple 也没有副本
- **单调计数器**：反回滚，绑定固件与密钥世代
- **安全存储（Secure Storage）**：每把密钥可绑定到"需要用户存在（生物识别/密码）才能释放"的条件
- **角色**：
  - FileVault 卷密钥的保护与释放
  - 系统密钥袋（System Keybag）
  - Touch ID 模板存储与匹配
  - Apple Pay / Passkeys 的签名操作
  - 安全启动策略的度量与验证

**与 iOS 的差异**：Mac 的 SEP 需要服务一个更复杂的用户态环境（多用户、远程登录、恢复模式、固件密码），因此历史上 Mac 的 SEP/iBoot 固件栈出现过独立的攻击研究。最著名的例子是 2020 年的 **CosmicStrand**——针对 T2 芯片 SEP 固件的**持久化漏洞**，可在系统盘擦除后存活。Apple 在公开披露的同时发布了修复，并罕见地以"Security Response"形式说明这是一起**针对特定目标的攻击**（而非大规模传播）。

**极客结论**：SEP 层面没有已知的大规模可利用缺陷，但它不是理论盲区。对 T3 级目标，"擦除重装不足以清除固件级持久化"这一事实决定了应急响应的处置深度。

### 2.2 PAC 与分支指令保护

Apple Silicon（以及 A12 之后的 iOS 设备）全面启用 **Pointer Authentication Codes (PAC)**：

- 64 位指针的高 16 位空闲比特被用作基于密钥的签名
- 关键指针（返回地址、函数指针、虚表）在写入时 `PACIA/PACIB`，使用前 `AUTIA/AUTDA`
- 校验失败触发异常，进程终止

**攻击现实**：PAC 不阻止内存破坏本身，而是阻止**被破坏的指针被用于跳转**。现代 macOS/iOS 利用链通常需要：

1. 先获得一次信息泄露，泄漏有效指针与它的 PAC 签名
2. 或找到"签名 oracle"（一个会用受控数据自动 PAC 的指令序列）

在 macOS 上，内核与用户态都受 PAC 保护，但由于可执行二进制数量巨大、系统服务繁多，可用 gadget 远比 iOS 丰富。**这是 macOS 利用链比 iOS 更常公开的原因之一**。

较新的 Apple Silicon 世代进一步引入分支目标识别等控制流完整性机制，逐步收敛可用 gadget。

### 2.3 SPTM、TXM 与页表强制

Apple 把 iOS 17 引入的 **Secure Page Table Monitor (SPTM)** 与 **Trusted Execution Monitor (TXM)** 陆续移植到 Apple Silicon Mac 的平台安全栈中：

- **SPTM** 运行在最高异常级别，是**页表的唯一权威**：内核不能修改自己的映射，W^X（不可同时可写可执行）被硬件强制
- **TXM** 作为可信执行监控，验证加载的内核与系统扩展，并在内核行为违反完整性约束时产生独立的 panic

**对防线的意义**：

- 传统 macOS rootkit 手法（修改内核代码段、注入可执行内存）被结构性切断
- 攻击者转向"合法的、可写的、可改变内核控制流的数据结构"
- 崩溃日志中会出现 TXM/SPTM 相关 panic 记录——**这类 panic 是极强的失陷信号**

**注意**：移植进度随机型与系统版本不同而不完全一致。判断自身设备是否具备相应保护，应以"保持最新系统"为主要手段，而不是逐项推断。

### 2.4 Exclaves：第三方隔离执行域

Apple 公开的 **Exclaves** 框架把 SPTM 的隔离能力开放给第三方，形成"客户对客户的机密计算"：

- 敏感代码与密钥放入独立内存域，宿主进程（即使 root）无法直接读取
- 面向密码管理、密钥库、健康、身份验证类场景
- 与 SEP 是互补关系：SEP 负责密钥的根与释放条件，Exclaves 负责在通用算力侧提供隔离执行

**极客关注**：当关键密钥的持有者从"应用主进程"变为"隔离域"时，"攻破 App 就拿到全部密钥"这类攻击的价值会下降。评估密码管理器与钱包类产品时，是否使用该框架将成为一个可问的技术指标。

### 2.5 神经引擎与侧信道（真实学术风险）

Apple 的机器学习加速器在密码学场景中引入过可验证的侧信道风险：

**GoFetch（2024）**：研究者证明 Apple Silicon 的**神经引擎（ANE）会被内核用于后量子密钥封装的运算**，而通过精心调度的并发任务可观测其访存模式，从而在**本地、无需 root** 的条件下逐位恢复 **ML-DSA（Dilithium）** 签名私钥。相关漏洞被分配多个 CVE，Apple 在后续更新中移除了受影响的后量子密钥交换默认使用。

其他公开的 Apple Silicon 微架构侧信道：

- **Augury（2022）**：基于缓存 prefetch 探测，可推断 ASLR 基址与部分秘密
- **FALKA'SPY（2023）**：跨线程推测执行导致内核地址泄漏
- 传统的 Spectre/Downfall 类问题在 Apple Silicon 上的等价研究

**极客结论**：

1. 侧信道攻击需要本地执行代码，因此**"谁能在我的机器上跑代码"**成为核心问题（回到第 5 层软件治理）
2. 对极高价值秘密（长期签名密钥），优先使用**专用硬件 HSM / 硬件安全密钥**，而不是仅依赖普通笔记本的本地实现
3. 保持更新是唯一的实际缓解手段

### 2.6 硬件层配置与验证清单

```bash
# 确认 SEP 与固件信息
system_profiler SPiBridgeDataType 2>/dev/null   # Intel T2
system_profiler SPHardwareDataType | grep -E "Chip|Model"

# 确认启动策略（Apple Silicon）
# 需在恢复模式下的"启动安全实用工具"查看：完整安全性 / 降低安全性

# 检查平台类型
sysctl -n hw.optional.arm64 2>/dev/null && echo "Apple Silicon"
uname -m
```

**要点**：

- Apple Silicon 优先（Boot ROM 无公开可复用漏洞，不存在 checkm8 类比缺陷）
- 启动策略保持"完整安全性"
- 长期签名密钥迁移到硬件密钥 / HSM

---

## 3. 安全启动链、启动策略与恢复防线

### 3.1 Apple Silicon 启动链

```
Boot ROM（出厂固化，不可修改）
    ↓ 验证
iBoot / LLB（Apple 签名固件）
    ↓ 检查启动策略（存于 SEP 保护区域）
安全启动策略：完整 / 降低 / 无
    ↓ 验证
KernelCollection（KC，签名内核 + 系统扩展集合）
    ↓
XNU 内核（受 SPTM/页表强制约束）
    ↓
launchd（PID 1）
```

**关键概念：KernelCollection**

Intel Mac 使用"kernelcache / prelinked kernel"，Big Sur 起 Apple Silicon 与后续 Intel 均改用 **KernelCollection（.kc）**——把内核与其依赖的系统扩展打包并整体签名。意义在于：

- 无法单独替换内核或某个系统扩展
- 加载前整体校验，任何篡改导致启动失败

### 3.2 启动策略（Startup Security Utility）

Apple Silicon 上通过恢复模式的"启动安全实用工具"配置：

| 策略 | 允许启动 | 外部介质 | 内核调试 | 典型场景 |
|------|---------|---------|---------|---------|
| 完整安全性 | 仅当前签名 OS | 否 | 否 | 默认，推荐 |
| 允许媒体使用 | 仅签名 OS | 是（签名） | 否 | 装机/维修 |
| 降低安全性 | 旧版签名 OS | 是 | 可配置 | 开发者/研究 |
| 无安全性 | 未签名系统 | 是 | 是 | 仅研究设备 |

**攻击含义**：

- "降低安全性"允许启动**旧版签名系统**——若旧版本存在已知漏洞，等同于打开后门
- 任何进入恢复模式的操作在默认配置下**需要本机管理员凭据**，Apple Silicon 上还受激活锁约束
- 攻击者若能物理接触且有数分钟，通常第一步是检查/降低启动策略

**防线**：

- 保持"完整安全性"
- 组织环境中通过 MDM **禁用用户对启动策略的修改权限**
- 定期核对启动策略是否被改动

### 3.3 恢复模式、认证恢复与激活锁

**macOS 恢复（Recovery）**：

- Apple Silicon 上恢复系统位于独立的 APFS 容器，与主系统分离，由签名保护
- 进入方式：开机长按电源键进入启动选项（Apple Silicon）；Intel 为 Command-R

**认证恢复（Authenticated Restore）**：

- 引入自 macOS 13，恢复时要求 Apple ID 凭据或管理员授权，防止攻击者通过"擦除重装"把设备重新占为己有
- 与 Activation Lock 共同构成"设备所有权"防线

**激活锁（Activation Lock）与"查找"**：

- 与 Apple ID 绑定，擦除后重新激活需要原始账户
- 防盗窃有效，**防数据提取无效**（它不保护数据，只保护"设备可用性"）

**恢复锁定（Recovery Lock）**：

- macOS 较新版本引入：进入恢复模式前需要设备密码或 Apple ID
- 显著抬高"短暂物理接触 → 恢复 → 绕过锁屏"的攻击成本
- **建议：所有含敏感数据的 Mac 开启**

### 3.4 固件密码与单用户模式（Intel 遗留面）

Intel Mac 的历史攻击面值得记录，因为它解释了为什么 Apple Silicon 更安全：

- **单用户模式（Command-S）**：旧系统可直接进入 root shell，**无需任何密码**，是几十年来最经典的 Mac 物理绕过
- **FileVault 关闭时**：单用户模式 / 恢复模式终端可挂载卷并修改 `/etc/passwd`、安装 launch daemon
- **固件密码（Firmware Password）**：T2/Intel 上阻止从外部介质启动，凭据可绑定 Apple ID
- **`nvram` 修改 boot-args**：`csrutil disable` 通过恢复模式即可执行

Apple Silicon 移除了传统的单用户模式与任意 NVRAM 修改路径，启动策略由 SEP 保护，**这些经典绕过在物理接触场景下大幅失效**。这是从 iOS 视角看 Mac 时最容易被忽略的巨大进步。

### 3.5 启动链检测信号

```bash
# 系统完整性与认证根状态
csrutil status
csrutil authenticated-root status     # 应为 "Enabled"（macOS 15 默认强制）

# 当前挂载的系统卷是否为密封快照
mount | grep -E " / " 
diskutil apfs list | grep -A3 "Snapshot for"

# 启动相关日志
log show --last 1d --predicate 'eventMessage CONTAINS[c] "authenticated root"'
```

**异常信号**：

- `csrutil status` 显示 disabled
- `authenticated-root status` 显示 disabled（macOS 15 起该项不应可关）
- 系统卷可写（正常应为 `read-only, sealed`）
- 频繁出现 TXM/SPTM panic（`/Library/Logs/DiagnosticReports/`）

---

## 4. 系统完整性：SIP、签名系统卷与 AMFI

### 4.1 SIP（System Integrity Protection）

自 OS X El Capitan 引入，SIP 限制 root 权限能做什么：

**受保护范围**：

- `/System`、`/usr`（`/usr/local` 与 `/usr/libexec` 部分例外）、`/bin`、`/sbin`
- 已签名系统应用的进程（不可 ptrace、不可注入、不可读取其内存）
- 内核扩展加载策略
- 调试器附加到受保护进程
- 引导参数写入（`nvram boot-args`）

**部分关闭选项（Big Sur+）**：

```bash
# 仅关闭 kext 保护，其余保留
csrutil enable --without kext

# 查看各配置位
csrutil status
```

**关键认知**：`csrutil disable` **必须在恢复模式**下执行，而恢复模式受管理员密码、启动策略、Recovery Lock 与激活锁约束。因此**SIP 被禁用几乎总意味着攻击者已获得物理访问或用户主动配合**。

在**正常启动的系统内**，即使 root 也无法直接关闭 SIP。这是 macOS 与 Windows/Linux 的根本差异之一。

### 4.2 签名系统卷（Signed System Volume, SSV）

Big Sur 引入，是当前 macOS 完整性最强的机制：

- 整个系统卷以 **APFS 快照**形式**密封（sealed）**：每个文件、每个 inode 的哈希构成 **Merkle 树**，根哈希由 Apple 签名
- 系统卷以**只读**挂载，运行时按需校验路径上每一层哈希
- 任何一个字节被修改 → 校验失败 → **无法启动**
- 可写内容全部迁出到 Data 卷（用户数据、配置、日志、临时文件）

**架构演进：系统卷组（System Volume Group）**

macOS 较新版本采用"卷组"管理多套系统（当前系统 + 更新中的系统 + Recovery），实现原子性更新与快速回滚。安全含义：

- 更新在独立的"update volume"上完成，切换失败自动回退
- 攻击者不能用"半更新状态"持久化篡改系统文件
- 快照的存在意味着**旧数据物理残留时间被延长**（取证价值与隐私风险并存）

**认证根（Authenticated Root）**：

- macOS 15 起在 Apple Silicon 上默认强制，且**不再允许关闭**
- 校验根哈希由启动链度量，与 SSV 形成闭环

### 4.3 AMFI 与代码签名策略

**AMFI（Apple Mobile File Integrity）** 在 macOS 上同样存在，负责执行代码签名与 entitlement 策略：

- 拒绝运行未签名（或签名损坏）的可执行文件——注意：这不是 Gatekeeper，AMFI 在**每次 exec** 时校验签名完整性
- 强制 Hardened Runtime 约束（见第 5 章）
- 校验 entitlement 是否由 Apple 授权签名（"restricted entitlements"）
- 控制 JIT、可写可执行内存、调试附加

**关键区别**：

| 机制 | 校验时机 | 可关闭 |
|------|---------|--------|
| **AMFI** | 每次执行 | 恢复模式下 `amfi_get_out_of_my_way=1`（需先关 SIP） |
| **Gatekeeper** | 首次执行 + 定期后台复核 | 系统设置中由用户关闭（新版移除"任意来源"） |
| **SIP** | 持续强制 | 仅恢复模式 |
| **SSV** | 启动与读取时 | 不可关闭（认证根强制后） |

**真实攻击路径**：macOS 恶意软件的常见第一步不是绕过 AMFI，而是**让 AMFI 满意**——使用有效（甚至被盗的）Developer ID 证书签名并完成公证。这使第 13 章的供应链问题成为 macOS 防线的核心。

### 4.4 内核攻击面：IOKit 与 DPH 类缺陷

macOS 上大量内核驱动通过 **IOKit** 暴露用户态可访问的接口。历史上，驱动中"直接分页（Direct Parameter Block / DPH）"式 IOMemoryDescriptor 处理存在**跨越几乎整个驱动栈的 use-after-free 模式**：

**DPH Attack（2024，CVE-2024-23222）**：研究者发现 IOKit 中一类**广泛存在于各类驱动**的内存描述符释放-使用缺陷，只需**普通用户态权限**即可获得内核内存的读/写原语，从而提权。Apple 将其定性为**已在真实攻击中被利用**，通过紧急更新修补，并以 Security Response 形式公布。

**防线含义**：

- 内核提权在 macOS 上是"本地、低门槛、高普遍性"的风险——**任何能在你的 Mac 上运行代码的进程都是潜在提权起点**
- 这再次把重点推回"谁能执行代码"
- 保持更新 + 限制外来源代码执行是唯二可靠手段

**其他 macOS 本地提权长期来源**：

- `Setuid` root 二进制（Apple 已大幅削减，Homebrew 会引入新的）
- 以 root 运行的守护进程中的 Mach/XPC 接口
- `/etc/paths.d`、`/etc/zshrc` 等全局可写配置（若权限错误）
- 安装脚本中的 `chmod/chown` 错误
- **第三方辅助工具（privileged helper）**：DMG 里的 App 常附带 root helper，用不安全的 XPC 协议向任意本地进程派发消息——这是 macOS 上数量最多的可实际利用提权缺陷类别之一

### 4.5 系统完整性验证操作

```bash
# SIP / 认证根
csrutil status
csrutil authenticated-root status

# 系统卷密封状态
diskutil info / | grep -iE "Read-Only|Sealed|Snapshot"
mount | awk '$2=="/"'

# 检查是否有异常 kext / 系统扩展
kextstat 2>/dev/null | head -30            # Intel
kmutil showloaded --no-kernel-components 2>/dev/null | head -30
systemextensionsctl list

# 检查第三方 root 辅助工具的 XPC 是否可被任意访问
ls -la /Library/PrivilegedHelperTools/
launchctl print system 2>/dev/null | grep -i helper | head

# 全局配置文件权限审计（常见提权来源）
ls -l /etc/paths /etc/paths.d/ /etc/zshrc /etc/zprofile /etc/pf.conf 2>/dev/null
find /etc -maxdepth 1 -perm -o+w -type f 2>/dev/null
```

### 4.6 系统完整性配置清单

- SIP：**保持开启**，绝不因某个工具"需要"而关闭
- 认证根：macOS 15 默认强制，确认 `Enabled`
- SSV：确认系统卷 `sealed / read-only`
- 不安装 kext；要求第三方驱动走 DriverKit / 系统扩展
- 对每个 privileged helper 视为潜在提权面；不需要的产品卸载
- 定期审计 `systemextensionsctl list`、`/Library/PrivilegedHelperTools/`

---

## 5. Gatekeeper、公证、隔离属性与路径随机化

### 5.1 Gatekeeper 的真实语义

Gatekeeper 常被误解为"实时杀毒"。它实际是**首次执行时的来源与签名策略**：

- 应用**第一次**在设备上执行时评估：Developer ID 证书有效？已公证？未被吊销？
- 通过则放行；此后**不再阻止**（历史行为），即使日后发现恶意
- 由 `syspolicyd` 执行，评估结果持久化在 `/var/db/SystemPolicy`

**较新 macOS 的重要收紧（macOS 15 世代）**：

- 移除"任何来源"选项（自 Ventura 起需 `spctl --master-disable` 才能启用，新版更严格）
- 未签名/未公证应用**默认无法通过右键打开绕过**——旧版"右键 → 打开 → 仍要打开"的路径被削弱
- 引入更明确的"不允许"路径与后台周期性复核（对已被标记恶意的 Developer ID 应用可事后拦截）

**极客必须知道的边界**：

1. Gatekeeper 只看**下载来的**、带隔离属性的文件；本地生成的脚本、`curl | sh`、包管理器安装**完全不经过 Gatekeeper**
2. 一个通过公证的恶意 App 会一路绿灯（Silver Sparrow 等真实案例使用了合法开发者证书）
3. `spctl --master-disable` 被组织内滥用会瞬间摧毁这层防线

### 5.2 隔离属性（Quarantine）

macOS 用扩展属性 `com.apple.quarantine` 标记"来自网络的内容"：

```bash
# 查看
xattr -l ~/Downloads/someapp.dmg
xattr -p com.apple.quarantine ~/Downloads/someapp.dmg
# 输出形如：0081;66f1a2b3;Safari;https://example.com/app.dmg
#          ↑flags  ↑时间戳    ↑来源App ↑来源URL

# 清除（危险：绕过 Gatekeeper 评估）
xattr -d com.apple.quarantine /path/to/app
xattr -rd com.apple.quarantine /Applications/Foo.app
```

**为什么这个属性如此关键**：它是 Gatekeeper、路径随机化、部分 TCC 评估的触发条件。教程里常见的 `xattr -d com.apple.quarantine ...` ——大量用户为了"打开被拦截的 App"执行它，实际上是在**主动关闭防线**。攻击者甚至会直接把这句话写进社工话术。

**极客准则**：只有在你**已独立验证过软件完整性**（校验和、签名、可信渠道一致）时才清除隔离属性；否则宁可换可信来源。

### 5.3 公证（Notarization）

自 Catalina 强制：Developer ID 分发的软件需提交 Apple 做自动化扫描与凭据签发。

**流程**：

```
开发者签名（Developer ID + Hardened Runtime + 安全时间戳）
    ↓
上传给 Apple notary service（Apple 扫描已知恶意软件、检查签名）
    ↓
通过 → 获得 ticket → 可 stapler 到 DMG/pkg（离线可验证）
    ↓
用户首次执行时 Gatekeeper 在线/离线确认 ticket
```

**公证检查什么**：

- 已知恶意软件签名（XProtect 类）
- 签名链完整、证书有效
- 未启用被禁止的 entitlement 组合
- **不检查**：逻辑漏洞、新恶意行为、数据窃取、隐私滥用

**命令**：

```bash
# 校验（Gatekeeper 视角）
spctl --assess --type execute -vv /Applications/Foo.app
spctl --assess -vv ~/Downloads/Foo.dmg

# 查看 stapled ticket
xcrun stapler validate /Applications/Foo.app
spctl check /Applications/Foo.app

# 看签名与 entitlement
codesign -dvvv /Applications/Foo.app 2>&1 | head -20
codesign -dvv --entitlements - /Applications/Foo.app 2>/dev/null | head -40
```

**要点**：公证是**准入凭证，不是安全评级**。

### 5.4 Hardened Runtime

公证要求启用 **Hardened Runtime**，它给应用加上运行时约束：

| Entitlement | 作用 | 削弱安全的方向 |
|-------------|------|---------------|
| `com.apple.security.cs.allow-jit` | 允许 JIT | 扩大代码注入面 |
| `com.apple.security.cs.allow-unsigned-executable-memory` | 允许 RWX 内存 | 严重：破坏 W^X |
| `com.apple.security.cs.disable-library-validation` | 允许加载任意库 | 严重：dylib 注入 |
| `com.apple.security.cs.debugger` | 允许调试 | 允许 ptrace/内存读取 |
| `com.apple.security.get-task-allow` | 允许被调试 | 通常开发构建才有 |

**审计价值**：一个"官方签名 + 公证"的 App 如果同时打开了 `disable-library-validation` 与 `allow-unsigned-executable-memory`，它就是一条**现成的注入通路**——任何能往其可搜索路径写文件的本地进程都能被它加载执行。

```bash
# 快速找出台面上开了危险 entitlement 的应用
for app in /Applications/*.app; do
  ent=$(codesign -d --entitlements - "$app" 2>/dev/null)
  if echo "$ent" | grep -q "disable-library-validation"; then
    echo "LIBVAL OFF: $app"
  fi
  if echo "$ent" | grep -q "allow-unsigned-executable-memory"; then
    echo "RWX: $app"
  fi
done
```

### 5.5 路径随机化（Path Randomization / Translocation）

针对"从未被移动过的 DMG 中直接运行"的应用，Gatekeeper 会**把应用复制到随机路径再执行**：

```
/private/var/folders/xx/xxxx/C/AppTranslocation/D/<uuid>/d/Foo.app
```

**目的**：让从只读 DMG 直接运行的应用**无法自我持久化**（改动随挂载消失而丢失）。

**失效条件**：只要用户把 App **拖到 /Applications**（这正是几乎所有安装流程在做的事），路径随机化就永久失效。因此它的实际保护窗口很短。

**检测方法**：

```bash
# 判断某进程是否运行在 translocation 路径
ps aux | grep AppTranslocation
```

### 5.6 证书吊销与 OCSP

Gatekeeper 会检查 Developer ID 证书是否被吊销。历史上 Apple 多次吊销被滥用的证书（盗版 App 分发、恶意软件被曝光后）。

**运维含义**：

- 一个证书被吊销后，**已安装**软件通常不会被自动清除（依赖后续 Gatekeeper 后台复核与 XProtect 更新）
- 企业若依赖某个 Developer ID 做白名单，需要订阅 Apple 的**凭据撤销列表**（CRL/OCSP）变化，或使用 MDM 的显式允许清单
- 攻击者**盗用合法证书**签恶意软件是 macOS 上最有效的绕过手段之一（见第 13 章）

### 5.7 软件治理防线清单

**执行层**：

- 保持 Gatekeeper 开启，绝不 `spctl --master-disable`
- 只用 App Store 或已公证的 Developer ID 应用
- **不为了绕过拦截而 `xattr -d com.apple.quarantine`**
- 拒绝一切"复制这行命令到终端执行"的教程（尤其涉及关闭 SIP / 清除隔离属性）

**下载层**：

- 只从官方域名下载，核对 TLS 证书与域名
- 大文件核对官方 SHA-256
- 拒绝第三方下载站、网盘镜像、"加速下载器"

**安装层**：

- `brew` 只使用官方 tap 与主流 cask；自建 tap 需理解内容
- `npm`/`pip` 项目固定版本与哈希（`package-lock.json`、`pip --require-hashes`）
- 不在 admin shell 里执行未审阅的安装脚本（先 `curl -O`，读完再跑）

**验证层**：

- 定期审计本机应用的危险 entitlement（上文脚本）
- `spctl --status` 确认策略未被关闭

---

## 6. TCC 隐私授权体系：macOS 特有的高价值权限面

### 6.1 TCC 是什么

**Transparency, Consent, and Control (TCC)** 是 macOS 的隐私授权层，由 `tccd` 守护进程管理，决定进程能否访问受保护资源。

**数据库位置**：

```
/Library/Application Support/com.apple.TCC/TCC.db      ← 系统级（root）
~/Library/Application Support/com.apple.TCC/TCC.db     ← 用户级
```

均为 SQLite，受 SIP 保护（root 也无法直接写，除非关闭 SIP 或 TCC.db 通过迁移工具访问）。

**查看授权**：

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT service, client, auth_value, last_modified FROM access ORDER BY service;" 2>/dev/null

# 系统级需要 root
sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT service, client, auth_value FROM access;"
```

`auth_value`：0=拒绝，1=未知/需询问，2=允许，3=允许但受限（部分版本含义有差异）。

### 6.2 macOS 独有的"三大杀器"权限

这三个权限在 iOS 上要么不存在，要么弱得多。**它们是 macOS 真实攻击中最常出现的授权目标**。

**1) 辅助功能（Accessibility / `kTCCServiceAccessibility`）**

- 允许进程**读取其他应用的界面文本**、**模拟键盘与鼠标事件**、操作控件
- 攻击用途：键盘记录、读取屏幕内容、自动点击"允许"弹窗、以用户身份操作银行/邮件页面
- 历史滥用：大量 stealer 与广告软件会引导用户"为完成安装，请在系统设置中允许辅助功能"
- **授予辅助功能 ≈ 授予键盘输入与界面控制**

**2) 屏幕录制（Screen Recording / `kTCCServiceScreenCapture`）**

- 允许抓取任意窗口与整个屏幕内容
- 攻击用途：持续截屏获取敏感数据；截屏 + OCR 等同于键盘记录（且更隐蔽）
- 较新系统开始显示**录制指示器**，但早期版本没有
- 该权限还会影响读取共享 GPU 资源的能力

**3) 全盘访问（Full Disk Access / `kTCCServiceSystemPolicyAllFiles`）**

- 绕过沙盒与数据保护，读取**其他应用的全部数据**
- 具体暴露：Safari/Chrome 的历史与 **cookie/session 数据库**、邮件库、消息库、Keychain 之外的凭据文件、`.ssh` 私钥、`.aws` 凭证、浏览器主密钥
- **授予 ADA = 把整台机器的身份与数据交给该进程**
- 攻击剧本：假"清理工具/激活工具/破解补丁"要求用户在设置中给一个陌生二进制勾选"全盘访问" → 一次性导出所有浏览器会话 cookie → 劫持邮箱、加密交易所、社交账号

**真实案例印证**：2023 年前后大量针对 Mac 的信息窃取恶意软件（Atomic Stealer/AMOS、StealV2 类）的核心动作不是漏洞利用，而是**用伪装的安装流程诱导用户授予 Full Disk Access / 辅助功能**，然后批量导出钥匙串、浏览器数据与 iCloud 会话。

### 6.3 其他关键权限

| TCC 服务 | 暴露内容 | 风险 |
|---------|---------|------|
| `kTCCServiceAppleEvents` | 用 AppleScript 控制邮件/终端/Finder | 可在终端执行任意命令 |
| `kTCCServiceSystemPolicyDocumentsFolder` | 文稿目录 | 中高 |
| `kTCCServiceSystemPolicyDownloadsFolder` | 下载目录 | 中 |
| `kTCCServiceCamera` / `Microphone` | 采集 | 高（有指示器） |
| `kTCCServiceListenEvent`（输入监控） | 全局按键 | 高（等同键盘记录） |
| `kTCCServicePostEvent` | 注入事件 | 高 |
| `kTCCServicePhotos` | 照片库 | 中 |
| `kTCCServiceLocation` | 位置 | 中 |
| `kTCCServiceEndpointSecurityClient` | EDR/审计数据 | **极高**（可监视全系统事件） |

**特别注意 `EndpointSecurityClient`**：授予后该进程可订阅全系统的 exec/open/link 事件，既能做防御也能做监控。恶意软件若取得它，等同于取得完美键盘/行为记录的元数据（但**注意**：ESF 授权通常要求系统扩展 + 批准，不是简单弹窗）。

### 6.4 Apple 对 TCC 提示的加固演进

- 提示措辞改为**"App 名称请求访问 XX"**，并在较新系统中加入更明确的来源标识与默认"不允许"倾向
- 屏幕/录制指示器与来源显示
- 限制通过 `tccutil` 之外的静默授权
- **仍存在的弱点**：提示中大量用户不会注意"哪个 App 在请求什么"；批量弹窗（一次请求多个权限）会诱导"连点允许"

**防御性习惯**（比任何配置都有效）：

1. 任何 TCC 弹窗**先读标题里的请求方**（不是"允许"按钮）
2. 陌生/临时二进制请求 Accessibility / ScreenCapture / AllFiles **一律拒绝**
3. 安装新工具时，把"需要授予的权限"作为审查项，去读它为什么需要

### 6.5 授权审计与最小化

```bash
# 列出所有已授予的高危权限（用户级）
for svc in kTCCServiceAccessibility kTCCServiceScreenCapture \
           kTCCServiceSystemPolicyAllFiles kTCCServiceListenEvent \
           kTCCServicePostEvent kTCCServiceAppleEvents; do
  echo "=== $svc ==="
  sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT client, auth_value FROM access WHERE service='$svc' AND auth_value>=2;" 2>/dev/null
done

# 撤销某个客户端
tccutil reset All com.example.app
tccutil reset ScreenCapture
tccutil reset SystemPolicyAllFiles

# 查看哪些进程当前持有屏幕录制
log show --last 2h --predicate 'subsystem == "com.apple.controlcenter" && eventMessage CONTAINS[c] "ScreenCapture"' 2>/dev/null | head
```

**周期任务（每月）**：

- 系统设置 → 隐私与安全性 → 辅助功能 / 屏幕录制 / 全盘访问：**逐个问"为什么需要"**
- 删除不再使用的授权
- 记录基线，比对新增

### 6.6 TCC 防线清单

- 三个"杀器"权限（辅助功能、屏幕录制、全盘访问）视为**root 级授权**管理
- 绝不为"绕过拦截"给陌生二进制 Full Disk Access
- 每月审计，形成基线
- 高价值凭据（硬件钱包密钥、离线签名材料）不出现在会同步到 Mac 的目录中，降低 ADA 被滥用后的损失
- 浏览器关键会话使用**硬件 2FA**，使 cookie 窃取不足以登录

---

## 7. 沙盒、系统扩展与内核攻击面收敛

### 7.1 Mac App Store 沙盒

Mac 上沙盒**只对 App Store 应用强制**。Developer ID 分发的应用可以完全不使用沙盒——这是与 iOS 的最大结构性差异。

```
~/Library/Containers/<bundle-id>/Data/     ← 沙盒容器的"主页"视图
```

- 通过 entitlement `com.apple.security.app-sandbox` 开启
- 网络、文件、其他应用数据访问都需显式 entitlement（`network.client`、`user-downloads`、`temporary-exceptions`）
- `temporary-exception` 可以让沙盒应用穿透到指定路径，长期看等于弱化沙盒

**现实**：大量主流 Mac 应用（浏览器以外的开发工具、Docker 类、终端、密码管理器）不是沙盒化的。因此**macOS 的默认隔离度远低于 iOS**，第 5/6 层（来源治理 + TCC）承担了 iOS 上由沙盒承担的职责。

### 7.2 从内核扩展到系统扩展：驱动防线演进

**内核扩展（kext）**：

- 运行在内核态，等同 root + 内核任意读写
- Intel 时代需签名、公证、且首次加载需用户批准
- 遗留问题极多：历史 kext 漏洞数量大，且一旦加载就是内核代码执行

**Apple 的收敛路径**：

- Apple Silicon 上**传统 kext 基本不可用**（需降低启动策略才能加载未签名）
- 迁移到 **DriverKit**（用户态驱动）+ **System Extensions**
- 系统扩展由第三方进程承担，权限细分到明确类别

**系统扩展类别**：

| 类型 | 用途 | 安全含义 |
|------|------|---------|
| `endpointsecurity` | 系统事件审计/拦截 | **需要 Apple 特别批准的 entitlement**，可监视全局 exec |
| `networkFilter` / `appProxy` / `neprovider` | 网络过滤/VPN | 可看到/控制全部流量（LuLu、VPN 用此） |
| `driver` (DriverKit) | 外设驱动 | 用户态，崩溃不导致内核 panic |
| `cryptoToken` | 智能卡/安全密钥 | 访问令牌 |
| `finderSync` / `fileProvider` | 云盘集成 | 文件系统可见 |
| `accessibility` | 输入辅助 | 少见 |
| `replacementExtension` | 替换 Apple 服务 | **需要 Apple 授权**，攻击者最想拿到 |

**关键认知**：系统扩展仍是**用户批准 + 管理员授权**才启用，但一旦启用，它能做的事情与 kext 相当接近（尤其 EndpointSecurity 与 NetworkFilter）。EDR/防火墙类产品的扩展被攻破，等于整机被监控。

```bash
# 列出所有系统扩展
systemextensionsctl list

# 激活/待删除状态一目了然
systemextensionsctl list | grep -E "activated|waiting|present"
```

### 7.3 XPC 与 Mach：本地提权的主战场

macOS 上系统服务通过 Mach 端口与 XPC 暴露接口。历史教训：

- **CoreAudio XPC（2021）**：`com.apple.audio.SandboxHelper` 接口缺乏调用方校验，导致沙盒内进程可越权改音频系统。分配了 CVE，并被用于定向攻击
- **MoveOneFile（CVE-2023-24800，2023）**：通过文件移动竞态实现沙盒逃逸，Apple 公开说明**疑似被国家级间谍软件利用**
- **DPH Attack（2024）**：IOKit 通用 UAF 缺陷
- 大量第三方 privileged helper 暴露无鉴权 XPC

**极客检查点**：

```bash
# 发现 root 运行的 launchd 服务（潜在提权面）
sudo launchctl print system 2>/dev/null | grep -E "^[[:space:]]*[0-9]+ = " | head -40

# 列出所有 Mach 服务注册
launchctl print system 2>/dev/null | grep -A200 "services =" | head -60

# 找 root 拥有的可写文件（经典提权）
sudo find /Applications /Library -perm -o+w -type f 2>/dev/null | head -30

# 找带特权且未加固的 helper
for h in /Library/PrivilegedHelperTools/*; do
  echo "--- $h"; codesign -dvv --entitlements - "$h" 2>&1 | grep -E "Identifier|team-id|helper"
done
```

### 7.4 Hardened Runtime 之外的运行时约束

- **Library Validation**：只允许加载同 Team ID / 同签名类型的动态库（关掉 = dylib 注入通路）
- **`com.apple.security.cs.disable-library-validation`**：常见于插件类应用，攻击者只要往插件目录写一个 dylib 即可注入
- **Dyld 环境变量注入**：受保护进程拒绝 `DYLD_INSERT_LIBRARIES`；未加固 + 未沙盒的进程则可能被注入
- **JIT/可写可执行内存**：Apple Silicon 上强约束

```bash
# 检查某进程是否被注入了可疑库
vmmap <pid> 2>/dev/null | grep -vE "/System|/usr/lib" | grep "\.dylib" | head
# 或
otool -L /path/to/binary
```

### 7.5 运行时防线清单

- 优先选择**沙盒化**（App Store）版本的应用
- 对 Developer ID 应用：审计 entitlement（尤其 library-validation、RWX、debugger）
- 定期 `systemextensionsctl list`，不保留不再需要的网络过滤/EndpointSecurity 扩展
- 每月扫描"root 可写文件"与"world-writable 应用文件"
- 卸载产品时清理其 privileged helper 与 LaunchDaemons（见第 14 章）

---

## 8. FileVault、APFS 与静态数据保护

### 8.1 FileVault 的密钥层级

FileVault 是 macOS 的卷加密（APFS 加密 / Apple Silicon 的硬件辅助）：

```
用户登录密码 / 生物识别
    ↓ (PBKDF2 派生，在 SEP 中执行)
Volume Unlock Key (VUK)
    ↓
Volume Encryption Key (VEK, XTS-AES 128/256)
    ↓
整个数据卷
```

**保护者类型**：

1. **用户账户**（每个能解锁卷的用户是一个保护者）
2. **个人恢复密钥 PRK**（26 位，格式 XXXX-XXXX-...）
3. **iCloud 恢复密钥**（较新系统：可把 PRK 存入 iCloud Keychain，端到端加密）
4. **机构托管密钥**（MDM escrow，企业场景）

**关键认知**：

- **FileVault 加密"关机/锁屏时的数据"，不加密正在使用中的数据**。已登录的会话中，恶意进程可读取明文（因此第 6 章的 Full Disk Access 审计才是重点）
- **每个有登录权限的用户都能解锁卷** → 减少可用账户数量 = 减少密钥持有者
- **MDM 托管密钥意味着组织可在你不知情时解密设备**（合法企业场景，个人设备需警惕）

### 8.2 取证与在线攻击

**FileVault 并不能阻止**：

- **运行时镜像获取**：设备处于登录状态时，任何取得 root 或特定权限的进程可以读取内存镜像、正在使用的文件、钥匙串会话
- **在线密码爆破**：解锁界面/`fdesetup` 有速率限制，但 T2/Apple Silicon 上凭据校验由 SEP 执行，**限制了离线高速爆破**
- 取证产品通常采用"获取用户凭据 / 利用未修补漏洞 / 用户胁迫"三种路径，而不是暴力

**冷启动攻击在现代 Mac 上基本不可行**：
Apple Silicon/T2 的内存加密与密钥生命周期管理使得关机后内存不含有效明文密钥。但仍存在一个**实际配置陷阱**——休眠镜像。

### 8.3 休眠镜像（sleepimage）与 `hibernatemode`

macOS 把内存内容写入 `/var/vm/sleepimage` 以支持安全休眠。历史攻击可从中提取磁盘密钥。

```bash
pmset -g | grep hibernatemode
ls -lh /var/vm/sleepimage
```

| 值 | 含义 | 安全性 |
|----|------|--------|
| 0 | 纯休眠到磁盘（禁用） | 内存不落盘，较安全，耗电 |
| 1 | 传统休眠 | 落盘 |
| 3 | 默认混合（笔记本） | 落盘，但**受 FileVault 保护**（写入受加密路径约束） |
| 25 | 仅安全休眠 | 内存**不**落盘，只有密钥丢失后唤醒（较新机型支持） |

现代系统默认路径与 FileVault 结合后风险显著下降。对**极高威胁模型**，可考虑：

```bash
sudo pmset -a hibernatemode 0
sudo rm -f /var/vm/sleepimage
sudo mkdir -p /var/vm/sleepimage && sudo chmod 000 /var/vm/sleepimage
```

**代价**：断电即丢工作内容。这是典型的"安全 vs 可用性"权衡，应显式决策而非默认执行。

### 8.4 APFS 特性带来的残留问题

- **快照（snapshots）**：系统更新、Time Machine 会创建快照。删除的文件可能仍在快照中
- **克隆（clones，copy-on-write）**：修改文件不覆盖旧块
- **卷共享空闲空间**：同一容器内多个卷共享，未分配块理论上残留

**处理**：

```bash
# 查看快照
diskutil apfs listSnapshots /
diskutil apfs listSnapshots disk3s1

# 删除非必要快照（谨慎；会破坏更新回滚）
diskutil apfs deleteSnapshot disk3s1 -uuid <snapshot-uuid>

# 查看容器与加密状态
diskutil apfs list
diskutil info / | grep -iE "Encrypted|FileVault"
```

**判断"抹掉"是否足够**：FileVault 开启下删除密钥（erase）让所有历史数据不可读——**只要密钥被销毁，块上的密文没有意义**。这也是 Apple Silicon 上"抹掉所有内容与设置"接近即时完成的原因。

### 8.5 FileVault 操作与验证

```bash
# 状态
fdesetup status

# 开启（会要求选择允许解锁的用户；建议仅保留必要账户）
sudo fdesetup enable -user "$(whoami)"

# 列出解锁者
fdesetup list

# 检查个人恢复密钥
fdesetup haspersonalexit -user "$(whoami)"

# 托管场景：确认是否存在机构退出凭据
sudo fdesetup hasrecoveryexit

# 延迟启用（部署脚本常用）
fdesetup defer -delay 300

# 关闭（不推荐；先确认威胁模型）
sudo fdesetup disable
```

**部署要点**：

- 开启前**先备份恢复密钥到离线媒介**（金属卡/纸质异地），丢失 PRK 等于数据永久不可恢复
- 个人设备：**拒绝机构托管密钥**；发现 `fdesetup hasrecoveryexit` 返回 yes 且你不属于任何组织，立即调查
- 组织设备：确保 PRK escrow 到受控 MDM，并限制访问该记录的人员范围
- 检查是否存在**多用户解锁者**：`fdesetup list` 每一行都是一个可用的解密入口

### 8.6 数据保护类（macOS Data Protection）

macOS 也提供 App 级的数据保护类（与 iOS 同源），自 Big Sur 起对 Mac App Store / 沙盒应用强制：

- `NSFileProtectionComplete`：锁屏后不可读，需要设备解锁
- `...UntilFirstUserAuthentication`：首次解锁后一直可读

Mac 上的语义比 iOS 弱（无"锁屏即切断"的强模型，因为登录会话长期存在）。因此**不能指望 App 级数据保护替代 FileVault + TCC 审计**。

### 8.7 加密层清单

- FileVault 开启，仅保留必要解锁用户
- 恢复密钥离线保管（金属 + 异地），每半年核对一次可读
- 确认无未知机构托管退出凭据
- 评估 `hibernatemode`（默认 3 通常足够；极端场景改 0/25 并理解代价）
- 定期 `diskutil apfs listSnapshots`，删除来源不明的快照
- 高价值长期密钥（冷钱包）不在联网 Mac 上生成/存储

---

## 9. 钥匙串、Passkeys 与凭证窃取防线

### 9.1 macOS 钥匙串结构

```
~/Library/Keychains/login.keychain-db    ← 用户登录钥匙串（登录时自动解锁）
/System/Library/Keychains/System.keychain ← 系统钥匙串（root，服务/机器凭据）
iCloud Keychain                          ← 跨设备同步（端到端加密）
/local item                              ← 设备本地专用条目（不迁移、不同步）
```

**保护机制**：

- 登录钥匙串主密钥由**用户登录密码**派生
- 每个条目有自己的 ACL（哪些应用可读取，是否需要用户确认）
- Apple Silicon/T2 上，派生过程与 SEP 协同；Touch ID 可作为条目访问条件
- 钥匙串**受 FileVault 保护**，但在已登录会话中内存里是**解密状态**

### 9.2 凭证窃取的现实路径

在已入侵且用户已登录的 Mac 上，攻击者获取凭据的实际手段（均为公开技术，MITRE ATT&CK for Mac 有对应条目）：

1. **`security` 命令行导出**
   ```bash
   security dump-keychain            # 会触发 GUI 授权提示
   security find-generic-password -s "service" -w
   security unlock-keychain -p <pw>  # 若知道登录密码即可无提示批量导出
   ```
   关键点：**只要拿到用户登录密码，ACL 保护形同虚设**。macOS 默认"登录钥匙串密码 = 用户登录密码"，所以密码即万能钥匙
2. **读取浏览器会话数据库**（需 Full Disk Access）：Cookie/会话令牌被直接复制即可劫持账户，无需破解密码
3. **主密钥提取**：Chrome/Edge/Firefox 在 Mac 上把加密主密钥存在钥匙串；取得钥匙串即取得全部保存的站点密码
4. **iCloud 会话令牌**：`akd`/`cloudd` 相关容器内的令牌可被重放，历史上出现过多起"窃取 Apple ID 会话"的恶意软件行为
5. **SSH 私钥与 API token**：`~/.ssh`、`~/.aws`、`~/.config/gcloud`、`.npmrc`、`.pypirc`、`.git-credentials`——这些**不受钥匙串保护**，只需文件读取权限

### 9.3 关键设计决策：让钥匙串密码与登录密码不同

这是 macOS 上少数**真正有效且被低估**的加固措施：

```bash
# 单独设置登录钥匙串密码（这样即使攻击者拿到登录密码，也无法静默解锁钥匙串）
security default-keychain -s ~/Library/Keychains/login.keychain-db
security changepw -h     # 交互式：旧登录密码 → 新独立钥匙串密码
```

**代价**：登录时不再自动解锁钥匙串，会频繁弹密码框；Touch ID 可缓解部分摩擦。

**收益**：切断"知道登录密码 → 静默 `security unlock-keychain` → 批量导出"的路径。对 T2+ 威胁模型值得权衡。

**更简洁的替代**：使用**独立密码管理器**（Bitwarden / KeePassXC / 1Password），其主密钥不派生自登录密码，且使用硬件密钥解锁。

### 9.4 Passkeys 与生物绑定

- Passkey 私钥存在 SEP 保护的安全存储，签名操作不出设备
- 通过 iCloud Keychain 端到端加密同步；启用高级数据保护后恢复路径完全由用户掌控
- Mac 上可用 Touch ID 完成断言；也可用第三方密钥管理器 + 硬件密钥

**优势（相对密码与 TOTP）**：

- 抗钓鱼：私钥绑定域名，伪造站点无法取到有效断言
- 会话若被盗（cookie 重放）仍是短板 → **Passkey 不等于会话安全**

**极客要点**：把关键账户从"密码 + SMS/TOTP"迁到 Passkey，可以消除"SIM 交换 + 短信二次验证"这条经典账户劫持路径。

### 9.5 iCloud 高级数据保护在 Mac 上

macOS 与 iOS 共享同一份 iCloud 密钥模型：

- 默认（未启用 ADP）：多数 iCloud 数据服务端可解密，Apple 可响应合法请求，也意味着**Apple ID 会话被窃取时损失更大**
- 启用 ADP（iCloud+ 订阅，无需额外付费；需 2FA）：照片、文件、备忘录、钥匙串、健康、通讯录、日历、提醒、Safari 书签、快捷指令、备份等转为端到端
- **不覆盖**：iCloud 邮件、群聊（部分服务端功能）、需要协议互通的日历/邮件标准服务

**在 Mac 上的额外含义**：ADP 降低的是**云端**风险；本地运行时风险仍由 FileVault + TCC + 来源治理决定。两者不能互相替代。

### 9.6 凭据层清单

- 关键账户全部使用 Passkey 或硬件密钥二次验证，**禁用 SMS**
- 密码库使用独立主密钥（不与登录密码同源）
- 评估"钥匙串密码独立于登录密码"或使用第三方密码管理器
- `~/.ssh` 私钥全部加 passphrase，并用硬件密钥（`ssh -Y`/`security-key`）替代裸私钥文件
- 云 CLI 凭证使用短期 STS/token，避免长期 AK/SK 落盘
- `.git-credentials` 换成 keychain helper 或 SSH
- 每月核对：系统设置 → 隐私与安全性 → 钥匙串访问中的应用授权；钥匙串访问 App 内查看"可访问此项目的应用"列表

---

## 10. Apple 内建防恶意软件栈：XProtect 与安全响应

### 10.1 三层内建防线

macOS 自带三种常被混淆的机制：

| 机制 | 作用 | 时机 | 能力边界 |
|------|------|------|---------|
| **Gatekeeper** | 来源/签名/公证策略 | 首次执行 | 不看行为，已知恶意靠后台复核 |
| **XProtect** | 恶意软件特征与域名/证书拦截 | 启动与更新时、执行路径中 | 特征匹配，**对 0-day 与无文件攻击无效** |
| **XProtect Remediator** | 检测并清除特定已知家族 | 周期性 | 只针对已建模的家族 |

历史上还有 **MRT（Malware Removal Tool）** 承担清除工作；Apple 在近期版本中把清除能力统一到 XProtect / Remediator 框架。判断口径是："Apple 的内建清除能力在持续演进，但**始终是特征驱动**"。

### 10.2 XProtect 的内容形式

XProtect 更新包含多类规则：

- **签名特征**（YARA-like 规则）与文件哈希黑名单
- **Bundle ID /  Team ID 黑名单**：整族应用被拦截
- **证书吊销与恶意 Developer ID**：直接封掉被盗证书
- **域名/IP 阻断列表**：拦截已知恶意下载与 C2 通信
- **恶意配置描述文件、Root CA**：阻断"装个 profile 就 MITM"这类攻击

查看（只读）：

```bash
# XProtect 主程序（较新版本）
ls /System/Library/CoreServices/XProtect.app/Contents/MacOS/ 2>/dev/null | head -40

# Remediator 家族列表：每个名字对应一个被建模的威胁
ls /System/Library/CoreServices/XProtect.app/Contents/PlugIns/ 2>/dev/null | head -40
ls /System/Library/CoreServices/XProtect.app/Contents/XPCServices/ 2>/dev/null | head -40

# 是否触发过查杀
log show --last 30d --predicate 'subsystem CONTAINS "xprotect" OR eventMessage CONTAINS[c] "XProtect"' 2>/dev/null | head -30
```

**重要边界**：

- XProtect 的更新随系统软件更新/静默内容更新下发
- 它**不阻止合法证书签名的全新恶意软件**——Silver Sparrow、多起 stealer 都在有效签名与公证下活动了很长时间
- 它**看不到**用系统自带解释器（python/osascript/bash）实现的无文件行为

### 10.3 安全更新与快速响应

**常规**：`软件更新`（含安全内容、可选功能与 Rosetta 更新）

```bash
softwareupdate --history | head -20
softwareupdate --list
sudo softwareupdate --install --all
```

**快速安全响应（Rapid Security Response, RSR）**：

- 以**系统 cryptex**形式叠加在主系统之上，不需完整重装，可独立回滚
- 用于在几小时到几天内封堵被积极利用的漏洞
- 查看：
  ```bash
  ls /Library/System/Cryptexes 2>/dev/null
  ls /var/db/system-cryptexes 2>/dev/null
  softwareupdate --history | grep -i "Rapid"
  ```

**组件级独立安全更新方向**：Apple 在近期发布周期中持续推进"把内核、SIP、WebKit 等组件的安全更新与整版系统更新解耦"的能力（内部/测试版社区常以 **Squabs** 称之）。**极客含义**：未来"停留在旧主版本但仍能拿到安全补丁"将变得可行，这会削弱"为了兼容旧工具链而不更新"的理由——也意味着"未更新 = 明确的选择"。

### 10.4 内建栈的战略定位

**要相信它**：

- 对 T0/T1 的批量广告软件与已知 stealer，XProtect + Gatekeeper + 公证的组合有效且成本为零
- 特征库更新及时，且覆盖域名/证书维度，不只是文件哈希

**不要迷信它**：

- 定向攻击（T2/T3）通常在相当长窗口内不被任何本地特征覆盖
- 一旦攻击者获得 Full Disk Access / 辅助功能，恶意行为可以是"完全合法的系统工具调用序列"，没有任何特征可写
- 因此 macOS 防线必须依赖**第 6、7、14 章的授权与持久化审计**，以及第 15/16 章的检测栈

### 10.5 防线清单

- 自动更新：系统 + 安全响应全部开启，不要"稍后提醒"常态化
- 记录当前系统版本与 RSR 版本，形成基线
- 每半年检查一次 `softwareupdate --history`，确认修补节奏符合预期
- 把 XProtect 视为"底线"，而非"保险"

---

## 11. 网络、外联控制与设备互联攻击面

### 11.1 内建防火墙的真实边界

macOS 的"防火墙"（`socketfilterfw`）**只管入站连接**：

```bash
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```

**它不控制出站**。恶意软件主动外联 C2、上传窃取数据，内建防火墙完全无感。这就是为什么 macOS 极客栈里 **Little Snitch / LuLu** 几乎是必装项。

### 11.2 出站控制

| 工具 | 机制 | 定位 |
|------|------|------|
| **LuLu**（开源，Objective-See） | Network Extension `NEFilterDataProvider` | 免费白名单式出站控制，社区规则可用 |
| **Little Snitch** | 同上 + 成熟的规则/图形界面 | 商业，规则精细度最高 |
| **Radio Silence** | 轻量拦截 | 简单场景 |

**部署要点**：

- 默认"未知进程外联即询问"，运行 2-4 周建立基线后再收紧
- 重点观察：首次出现的陌生二进制、`/usr/bin/curl`、`python`、`osascript` 发起连接
- **注意信任成本**：这类工具本身是 EndpointSecurity/NetworkFilter 系统扩展，一旦被攻破或被恶意替换，等于交出全流量可见性。定期 `systemextensionsctl list` 校验

### 11.3 加密 DNS、VPN 与 Private Relay

- **加密 DNS**：通过配置文件（`.mobileconfig`）或 App 启用 DoH/DoT；验证方式
  ```bash
  sudo dscacheutil -flushcache
  scutil --dns | head -30
  # 或查看是否启用了加密 DNS 配置
  profile_status=$(sudo profiles show -type configuration 2>/dev/null | grep -i dns)
  ```
- **iCloud Private Relay**：双中继分离"你是谁"与"你要访问哪"，覆盖面以 Safari/部分 App 为主
- **VPN**：优先自选审计过的无日志提供商或自建 WireGuard；注意企业 VPN profile 会引入根 CA 与全流量可见性

**红旗**：任何"免费 Wi-Fi 要求安装描述文件/证书"的场景。装了 root CA = HTTPS 可被中间人。

```bash
# 审计已安装描述文件
sudo profiles show -type configuration 2>/dev/null | grep -iE "displayName|payloadType" | head -40
ls -la /Library/Managed\ Profiles/ 2>/dev/null

# 审计自建根证书
security find-certificate -a -c "Authority" /Library/Keychains/System.keychain 2>/dev/null | grep labl | head
sudo security authorizationdb read system.trust 2>/dev/null | head -5
```

### 11.4 Thunderbolt / USB 与外设攻击面

**DMA 攻击**：Thunderbolt/USB4 允许外设直接访问内存。macOS 的缓解：

- macOS 11.3+ 引入 **Thunderbolt 安全级别**（默认"用户确认后允许新配件"）
  ```bash
  # 查看当前安全级别与已授权配件
  sudo thunderboltutil --list 2>/dev/null
  sudo defaults read /Library/Preferences/io.github.MRAlessi... 2>/dev/null
  # 更可靠的查看方式
  ioreg -p IOUSB -l -w0 | grep -iE "Thunderbolt|USB" | head -20
  ```
- Apple Silicon 上 PCIe 隧道权限受启动策略与内核约束更强控制

**HID 注入（BadUSB / O.MG 线缆）**：

- 设备被识别为"键盘"，可在几秒内以用户身份打开终端并粘贴命令
- **缓解**：锁定屏幕时不自动登录；关闭"需要密码"间隔为"立即"；不在离手的 Mac 上启用免密自动登录；敏感会议中不在无人看管时保持已登录
  ```bash
  # 检查是否自动登录（严重风险）
  sudo defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null
  # 立即锁屏
  sysadminctl -screenLock immediate -password "…"
  defaults read com.apple.screensaver idleTime
  ```

### 11.5 共享与远程服务

```bash
# 审计开启的共享服务
sudo launchctl print system 2>/dev/null | grep -iE "smbd|afpd|ssh|screensharing|ARD" | head
systemsetup -getremotelogin 2>/dev/null
sudo systemsetup -getremoteappleevents 2>/dev/null
# 打开的端口
sudo lsof -i -n -P | grep LISTEN
```

**默认姿态**：

- **远程登录（SSH）**：不需要就关闭 —— `sudo systemsetup -setremotelogin off`
- **屏幕共享 / 远程管理（ARD）**：非服务器用途全部关闭
- **文件共享（SMB/AFP）**：不对外，检查共享点与权限
- **Bonjour/设备发现**：在不受信网络中限制

### 11.6 跨设备互联面（Handoff / iPhone 镜像 / 通用控制）

macOS 与 iOS 的连续互通功能在提供便利的同时**扩大了信任半径**：

- **Handoff / 通用剪贴板**：一个设备的失陷可以让内容出现在另一个设备
- **iPhone 镜像（macOS 15+）**：Mac 上直接操作手机——意味着**Mac 失陷可延伸为手机内容的可视化访问**
- **通用控制（Universal Control）**：跨设备输入控制
- **AirDrop / 隔空投送**：历史上是恶意文件投递入口之一
- **随航 / 侧边栏 / 连续相机**：把 Mac 变成相机/显示链的一环

**建议**：

- 不需要就关闭：系统设置 → 通用 → 隔空投送与续接 / 显示器（通用控制）
- 高威胁目标：**不把 iPhone 镜像开放给任何 Mac**；把手机视为独立信任域
- iCloud 高级数据保护降低同步类风险的云端暴露，但不解决"设备互信"本身

### 11.7 无线与近距协议

- **蓝牙**：历史漏洞家族（BlueBorne、Knock Knock、BradtMite、BtleJack 等）表明，无交互/低交互攻击面长期存在；Apple 逐个修补。敏感场合直接关闭蓝牙
- **Wi-Fi AWDL（AirDrop/续接底层）**：`awdl0` 接口长期活跃；可关闭以减小面
  ```bash
  ifconfig awdl0            # 查看是否 up
  # 临时关闭（会破坏 Handoff/AirDrop）
  sudo ifconfig awdl0 down
  ```
- **私有 Wi-Fi 地址**：确认对每个 SSID 开启，减少被动追踪

### 11.8 网络层清单

- 入站防火墙开启 + **额外部署出站控制**（内建防火墙不管出站）
- 每月审计描述文件与自建根证书
- Thunderbolt/USB 配件保持"需确认"，绝不无人看管时自动登录
- 关闭不用的远程服务与共享
- 敏感场合：关闭蓝牙、`awdl0 down`、使用有线受控网络
- 限制跨设备互信范围（iPhone 镜像、通用控制、Handoff）

---

## 12. 恶意软件与真实攻击案例

以下案例全部来自公开安全厂商研究，用于说明 macOS 防线的**实际薄弱环节在哪一层**。

### 12.1 批量广告软件：Shlayer 型（T0）

**模式**：

- 通过恶意广告/SEO 投毒诱导下载"Flash Player 更新""浏览器组件"
- 落地为一个挂载的 DMG，内含 `.app`（常伪装成 Flash 图标）
- 运行时安装浏览器扩展/配置描述文件，劫持搜索与首页、注入广告
- 常见辅助手法：诱导用户执行 `xattr -d com.apple.quarantine`，或在提示框里让用户"输入密码以完成安装"

**防线教训**：

- **Flash 自 2020/2021 年后已不存在合法更新通道**——任何"Flash 更新"都是红旗
- 图标伪装（`.app` 显示成 `.pdf` 图标）是 macOS 上长期有效的社会工程
- 显示扩展名（Finder → 设置 → 高级 → 始终显示扩展名）能显著降低误点率

### 12.2 信息窃取类：Atomic Stealer / AMOS（T1）

**公开要点**（2023 年广泛报道）：

- 分发：约 255 个 npm 包投毒（typosquat + 依赖链），以及假"破解工具""激活器"
- 售价约数百美元的"即服务"模式
- 行为：一次性窃取钥匙串、浏览器数据与 Cookie、Apple ID/iCloud 会话、加密钱包、Telegram 会话、`.ssh` 与开发者凭据
- **关键**：安装过程中诱导用户授予 **Full Disk Access / 辅助功能**，或用钓鱼弹窗骗取登录密码

**防线教训**：

- 损失主要来自**凭据与会话**，而不是文件本身
- **硬件 2FA / Passkey** 让"偷到密码 + cookie"仍不足以登录关键账户
- npm/PyPI 依赖审查是 Mac 开发者的一等安全问题（不是 Web 开发者的问题）

### 12.3 高级潜伏：Silver Sparrow（T2 级工程）

**公开要点**（2021-2022 年多家厂商披露，感染约 3 万台以上）：

- 通过合法（后被识别异常）的 Developer ID 签名并**完成 Apple 公证**分发
- 第一阶段只部署"心跳 + 探测"逻辑，**长期未投递破坏性载荷**
- 显式探测 **Apple Silicon（M1）** 环境，说明为下一代载荷做准备
- 使用系统自带 `python`/JavaScript（JXA）实现"无文件"行为，避开基于文件特征的检测
- 作者可随时终止（含自毁/日落机制），最终未观察到大规模破坏

**防线教训**：

- **"公证 + 有效签名"不是安全背书**，只是准入门槛
- 文件特征检测对"用系统解释器执行的行为"无效 → **需要执行链与出站行为监控**（Santa/LuLu/EDR）
- 潜伏期长的 implant 只能靠**基线比对 + 持久化审计**发现（第 14 章）

### 12.4 开发工具链定向：XCSSET（T1/T2）

**公开要点**（2020）：

- 恶意软件注入 **Xcode 工程**（修改项目文件、添加构建脚本/引用），使开发者构建出的应用被感染
- 感染源包括开源仓库、被投放的"合作示例工程"
- 窃取敏感目录内容与聊天/凭据，并利用 **AppleScript/自动化 TCC** 触发授权

**防线教训**：

- 对 Mac 开发者，"克隆的示例工程""客户直接发来的 .xcodeproj"是真实攻击入口
- 构建前应检查工程中的**运行脚本阶段、外部引用与预构建 hook**
- 关键签名与发布构建应使用**隔离的构建环境**（干净 VM / CI）

### 12.5 MITM 类描述文件攻击：Dok 型（T1）

**公开要点**：

- 假 Flash 安装器投递 `.pkg`，安装配置描述文件
- 描述文件安装**自建根 CA + 全局代理** → 对全部 HTTPS 中间人
- 目标：网银、支付、邮件凭据

**防线教训**：

- 描述文件与根证书审计是**必须定期执行的独立动作**（第 11 章命令）
- "免费 Wi-Fi 要求装 profile/证书" 一律视为攻击
- 关键账户启用硬件 2FA，使 MITM 无法完成高保障登录

### 12.6 勒索与破坏：ThiefQuest / EvilQuest（T1）

**公开要点**（2020）：

- 伪装成流行软件（如 Small Helper / 破解工具）的"勒索软件"
- 同时具备键盘记录、钥匙串窃取、尝试移除/禁用安全扩展的能力
- 勒索实现质量低（被研究者指出加密逻辑缺陷），但**窃取能力真实**

**防线教训**：

- "反安全软件"行为（尝试卸载 EDR、清除扩展、改 pf 规则）是极强的高置信度恶意信号
- **值得监控的具体 IOC 类行为**：`systemextensionsctl uninstall`、修改 `/etc/pf.conf`、删除 `/Library/LaunchDaemons/*` 中他人条目、`spctl --master-disable`

### 12.7 案例归纳：薄弱环节排序

| 薄弱环节 | 出现频率 | 防线章节 |
|---------|---------|---------|
| 用户授予 TCC 高危权限 | 极高 | 6 |
| 诱导执行 shell / 清除隔离属性 | 极高 | 5 |
| 包管理器与 npm/PyPI 投毒 | 高 | 5、13 |
| 合法签名 + 公证的恶意 App | 中（但严重） | 5、10、13 |
| 描述文件 / 自建根 CA | 中 | 6、11 |
| 内核/XPC 本地提权 | 中（定向） | 4、7 |
| 零点击链（iMessage/FaceTime） | 低（定向） | 13、16（锁定模式） |

**结论**：macOS 上"最高回报的防线"是**软件来源治理 + TCC 授权纪律**，不是追逐最新的 0-day 情报。

---

## 13. 国家级植入、MDM 滥用与供应链攻击

### 13.1 定向植入的公开图景

多家厂商与威胁情报团队长期披露针对 macOS 的**定向 implant**（多数归属国家级或高能力团伙），共同模式：

- 投递依赖**社工 + 合法外观的下载**，而非大规模漏洞利用
- 载荷常为**轻量、无文件或以脚本/系统解释器承载**，用于长期潜伏与采集
- 目标集中于：智库/政策研究者、人权与 diaspora 组织、记者、外交、特定行业研发
- 公开命名的一系列 implant 家族（由 Microsoft、Google Threat Intelligence、SentinelOne、Elastic、奇安信/安恒等披露）在行为上高度相似：**建立持久化 → 采集凭据与文档 → 通过合法云/CDN 中转 C2**

**关键判断**：这类攻击**几乎不需要 macOS 漏洞**。一旦取得初始执行 + 用户授权（或一个被盗的 root 密码），macOS 的内建防线不会主动阻止长期驻留。这与 iOS 上"必须付出百万美元级 exploit 链"的图景完全不同。

### 13.2 零点击与消息入口（macOS 相关面）

Mac 上同样存在高价值远程入口：

- **Messages 附件解析**（图片/媒体/富文本预览路径）、FaceTime、邮件通知与预览
- **Safari/WebKit**：水坑与恶意广告
- **较新版本 Safari 的强化模式**（锁定模式下的更严格 JS/媒体处理）

**已公开的跨平台案例**：

- **FORCEDENTRY（2021）**：iMessage 零点击，经 PDF/字体解析路径，影响 iOS/iPadOS/**macOS** 等多平台；Apple 罕见以 Security Response 形式公开说明被定向利用
- **CoreAudio XPC 缺陷（2021）**：沙盒内进程通过音频服务越权，被用于定向攻击链
- **QuickTime/WebRTC 零点击（2023）**：媒体解析链，Apple 紧急修补
- **Coruna（2024）**：泄露的工具化 exploit 集，以合规 App + 网页联动投递，主要影响 iOS；其意义在于"廉价化"，未来同类手法会外溢到 Mac 目标

**防线**：

- 高风险人群应把 Mac 也纳入**锁定模式**（macOS 上同样可用，自 Ventura 起支持）
- 敏感场景**不使用 Messages 接收未知来源附件**；关闭 FaceTime 陌生人来电
- 保持更新是唯一起作用的措施

### 13.3 锁定模式在 macOS 上的具体收益

系统设置 → 隐私与安全性 → **锁定模式**（需重启）。公开列出的限制包括：

- 浏览器：禁用部分 JIT/复杂技术，仅少数例外站点正常工作
- 消息：附件预览与富文本链接受限，陌生 FaceTime 呼叫被阻止
- 设备关联：关闭部分跨设备/配件功能、限制共享
- Apple 服务：部分服务与后台预览受限
- 网络：在不受信网络上更严格；公共 Wi-Fi 相关行为收紧

**极客判断**：锁定模式是 macOS 上**成本最低的针对国家级攻击的强缓解**。它不能阻止本地代码执行，但显著削弱远程投递路径。

### 13.4 MDM 作为攻击载体

**为什么 MDM 有吸引力**：

- MDM 可以**静默安装描述文件、根 CA、配置 TCC 授权（部分）、推送脚本、部署软件、擦除设备**
- 一旦 MDM 服务端或租户被攻破，攻击者获得对**整个设备池**的高权限投递能力
- 对目标密集的机构（大学、研究机构、NGO、媒体），通过其 MDM 一次性投递 = 高效批量立足

**公开事件模式**（2024-2025 年由厂商与客户公开披露的 macOS MDM 相关入侵）：

- 某 MDM 供应商的客户环境被入侵，攻击者利用其向特定机构的 Mac 下发配置
- Apple 据此向受影响用户发送**国家级攻击警告**，安全研究与媒体广泛报道
- 常见技术：SSH 密钥滥用、持久化远程执行、通过管理脚本建立后续访问

**防线（机构与个人）**：

1. **最小化管理员面**：MDM 管理员账户强制硬件 2FA、独立身份、IP 限制、审计日志外送到不可由 MDM 管理员修改的地方
2. **管理脚本视为高危供应链**：只允许受版本控制、双人审核的脚本
3. **不要给 MDM 静默授予 TCC 的权限范围超出必要**
4. **个人层面**：入职/入学时理解"设备被管理意味着什么"；发现设备上有未知 `Managed Profiles` 且你不属于任何组织 → 立即处理
   ```bash
   sudo profiles show -type configuration 2>/dev/null
   ls -la /Library/Managed\ Preferences/ 2>/dev/null | head
   sudo profiles status -type enrollment 2>/dev/null
   ```
5. **离职/毕业后**：确认设备已从 MDM 解绑，`profiles status` 应显示未登记

### 13.5 代码签名与构建链攻击

**攻击路径**：

1. **窃取 Developer ID 证书 + 私钥** → 恶意软件带合法签名与公证（历史上多次发生，Apple 事后吊销）
2. **入侵更新服务器 / 构建流水线** → 合法产品分发被替换的二进制
3. **污染开发工具链** → XcodeGhost 型：被篡改的 Xcode 产出合法签名的恶意 App
4. **包管理器**：npm/PyPI/Homebrew tap/RubyGems/Crates.io 的 maintainer 账号接管或 typosquatting
5. **开源 CI runner**：公开可触发的工作流执行任意脚本，窃取云凭据与签名密钥

**防线（个人开发者/小团队）**：

```bash
# 校验下载物的来源与完整性
shasum -a 256 <file>
pkgutil --check-signature /path/to/installer.pkg
spctl --assess --type install -vv /path/to/installer.pkg
codesign -dvvv --requirements - /Applications/Foo.app 2>&1 | head -20

# 检查 pkg 里到底做了什么（先看脚本，再安装）
pkgutil --payload-files /path/to/Foo.pkg | head -40
pkgutil --expand /path/to/Foo.pkg /tmp/foo_expand
ls -R /tmp/foo_expand | head -40
# 阅读 Preinstall/Postinstall
find /tmp/foo_expand -name "*install*" -maxdepth 3
```

**构建侧要点**：

- 只从 Apple 官方/公司软件门户安装 Xcode；核对签名与来源
- 构建机与日常使用机**分离**；发布构建用干净、一次性环境
- 签名私钥置于**硬件密钥/HSM**，不允许出现在开发者笔记本
- CI secret 最小化，使用短期 OIDC token 而非长期密钥
- 依赖锁定 + 哈希校验；对高风险依赖做隔离审阅

### 13.6 供应链事件的经验教训

| 事件类 | 教训 |
|--------|------|
| 被污染的开发工具（Xcode 镜像） | 工具链完整性优先于代码审查 |
| 证书被盗/滥用 | 签名 ≠ 无害；关注 Apple 吊销公告 |
| 更新通道被入侵 | 自动更新是双刃剑，需要构建侧完整性保障 |
| 包投毒（npm/PyPI） | 依赖即攻击面；锁定 + 哈希 + 最小依赖 |
| MDM/服务商被入侵 | 集中管理通道是最高效投递面，需独立审计 |

---

## 14. 持久化机制全景与检测方法

### 14.1 macOS 持久化位置地图

```
系统级
  /Library/LaunchDaemons/*.plist
  /Library/LaunchAgents/*.plist
  /System/Library/LaunchDaemons/（受 SSV 保护，不可持久修改）
  /etc/pam.d/*（authorization 插件）
  /Library/Security/SecurityAgentPlugins/
  /Library/PrivilegedHelperTools/ + 对应 LaunchDaemon
  /Library/Extensions/*.kext（Intel）
  系统扩展（DriverKit / NetworkExtension / EndpointSecurity）
  /Library/StartupItems/（遗留）
  配置描述文件（MDM 下发）
  内核参数/启动参数（需先关 SIP）
  crontab / /etc/crontab / /usr/lib/cron/tabs

用户级
  ~/Library/LaunchAgents/*.plist
  登录项（SMAppService，macOS 13+ 由 BTM 统一管理）
  ~/Library/Application Support/<可疑目录>/
  ~/Library/Containers/<伪装 bundle-id>/
  ~/Library/Services/*.workflow / *.app
  ~/Library/Safari/Extensions（浏览器扩展）
  ~/Library/Application Support/*/NativeMessagingHosts/
  ~/Library/Screen Savers/（遗留 saver）
  ~/Library/QuickLook/ / ~/Library/Spotlight/
  Shell 初始化：~/.zshrc ~/.zprofile ~/.zshenv /etc/zshrc /etc/zprofile
  Git hooks（pre-commit / post-checkout）
  Xcode 工程注入（构建阶段脚本、外部引用）
  ~/.local/bin、/usr/local/bin 中被替换的二进制
  Finder Sync / 文件提供程序
```

### 14.2 现代管理入口：后台任务管理（BTM）

macOS 13 起，登录项与后台项目由 **Background Task Management** 统一登记，可用 `sfltool` 导出：

```bash
sfltool dumpbtm             # 需要管理员；显示所有登记的 agent/daemon 与来源
sfltool dumpbtm | grep -iE "disabled|visible|type" | head -40
```

**价值**：它揭示了"登录项面板里看不见的"条目，是发现伪装/隐蔽持久化的最好原生工具之一。

**图形入口**：系统设置 → 通用 → 登录项（同时显示"允许在后台"列表）。

### 14.3 逐类检测命令

```bash
# 1) Launch Agents / Daemons：全部来源
ls -la /Library/LaunchDaemons/ /Library/LaunchAgents/ ~/Library/LaunchAgents/ 2>/dev/null

# 2) 解析每个 plist 的实际可执行路径，标出指向异常位置的项
for p in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist \
         "$HOME/Library/LaunchAgents/"*.plist; do
  [ -f "$p" ] || continue
  prog=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$p" 2>/dev/null)
  [ -z "$prog" ] && prog=$(/usr/libexec/PlistBuddy -c "Print :Program" "$p" 2>/dev/null)
  echo "$(basename "$p") -> $prog"
done | grep -vE "^\S+ -> (/usr/sbin|/usr/bin|/sbin|/System/Library|/usr/libexec)"

# 3) 当前用户会话中已加载的 agent
launchctl print "gui/$(id -u)" 2>/dev/null | grep -E "^\s+[0-9]+ = " | head -40

# 4) 可疑脚本/二进制：非系统目录且近期修改
find /Applications /Library ~/Library -maxdepth 4 \( -name "*.plist" -o -name "*.sh" \) \
  -mtime -7 2>/dev/null | grep -vE "Caches|WebKit|CloudKit" | head -40

# 5) 系统扩展与 kext
systemextensionsctl list
kmutil showloaded --no-kernel-components 2>/dev/null | awk 'NR>1{print $NF}' | sort -u | grep -v "^com.apple" | head -20

# 6) 特权辅助工具
ls -la /Library/PrivilegedHelperTools/ 2>/dev/null

# 7) crontab
crontab -l 2>/dev/null
sudo ls -la /usr/lib/cron/tabs/ /etc/cron.d/ /etc/crontab 2>/dev/null

# 8) PAM / 授权插件（凭据捕获常用）
ls -la /Library/Security/SecurityAgentPlugins/ 2>/dev/null
cat /etc/pam.d/authorization 2>/dev/null | grep -v "^#" | head -20
ls -la /usr/lib/pam/ 2>/dev/null | grep -vE "apple|common" | head

# 9) 全局 shell 配置被篡改
ls -l /etc/zshrc /etc/zprofile /etc/zshenv /etc/paths /etc/paths.d/ 2>/dev/null

# 10) 描述文件与证书
sudo profiles show -type configuration 2>/dev/null | grep -iE "displayName|payloadType" | head -20
security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep -c labl

# 11) 出站连接基线
sudo lsof -i -n -P | grep -v ESTABLISHED | head -40
nettop -m tcp -t 1 -L 5 2>/dev/null | head -30

# 12) 监听端口
sudo lsof -i -n -P | grep LISTEN
```

### 14.4 行为基线工具（Objective-See 生态）

开源工具（Objective-See，Patrick Wardle 主导）是 macOS 自监听的实用补充：

- **LuLu**：出站网络过滤与授权
- **Santa**：二进制授权（白名单），可配合同步服务器，对"任何新二进制执行需批准"极为有效
- **BlockBlock**：监控常见持久化位置的写入
- **Timestep**：可视化本机二进制执行历史（按时间聚类，异常一眼可见）
- **Tock**：文件完整性 + 恶意 IOC 周期扫描
- **eslogger / fpm**：EndpointSecurity 事件流与打包工具（需 Apple 批准 entitlement，主要面向开发者）

> 注：这类工具本身需要系统扩展/特殊权限，安装即扩大信任面。选择开源、可审计、社区长期维护的项目，并**定期核对扩展清单**。

**DTrace 的现实**：`dtrace` 在 Apple Silicon 上不可用，在 Intel 上需要关闭 SIP 相关保护。因此 macOS 用户态可观测性主要依赖 **Unified Log**、`fs_usage`、`lsof`、EDR/ESF，而**不是** DTrace——这与 Solaris/Linux 直觉相反。

### 14.5 统一日志作为取证主力

```bash
# 最近 1 小时的进程创建（需相应权限）
log show --last 1h --predicate 'eventMessage CONTAINS "exec" AND process == "kernel"' --style compact | head -40

# TCC 授权事件（谁申请、结果如何）
log show --last 30d --predicate 'subsystem == "com.apple.TCC"' --style compact \
  | grep -iE "grant|prompt|request" | head -40

#  Gatekeeper / syspolicyd 判定
log show --last 14d --predicate 'process == "syspolicyd"' --style compact | head -40

# 系统扩展变更
log show --last 30d --predicate 'eventMessage CONTAINS[c] "OSSystemExtensionRequest"' --style compact | head -20

# 登录与授权失败（异常爆破迹象）
log show --last 7d --predicate 'eventMessage CONTAINS[c] "authentication" AND category == "com.apple.securityd"' --style compact | head -30
last -20
log show --last 3d --predicate 'eventMessage CONTAINS[c] "failed to authenticate"' --style compact | head -30

# 导出诊断包（失陷应急必做）
sudo /System/Library/CoreServices/ReportCrash sysdiagnose
# 或：按住电源/相应按键组合，或 `sudo sysdiagnose -F /tmp`
sudo sysdiagnose -F /tmp && ls -lh /tmp/sysdiagnose*
```

### 14.6 无文件与解释器承载行为

macOS 上大量攻击用**合法解释器**承载，无新文件落地：

- `/bin/bash -c`、`/usr/bin/python3`、`/usr/bin/osascript`、`/usr/bin/curl | sh`
- JXA（JavaScript for Automation）、AppleScript、`mdutil`、`mdfind` 滥用
- `open -a` 触发已授权应用执行（**TCC 混淆代理**：借已授权 Full Disk Access 的应用读取敏感数据）
- `launchctl submit` / `launchctl load` 运行时注册服务，plist 可放临时目录
- `plutil`/`defaults` 写入看似正常的偏好键实现逻辑持久化

**检测思路**：

- **混淆代理**：关注"哪个应用被用来访问数据"。典型合法被滥用者：终端、Finder、文本编辑器、已授予 ADA 的备份/同步工具
  ```bash
  # 谁在访问敏感目录（需 root）
  sudo fs_usage -w -f filesys | grep -E "\.aws|\.ssh|Keychains|Cookies|Chrome" | head -40
  ```
- **解释器链**：建立"哪个父进程可以合法产生 shell 子进程"的基线（通常只有终端类）
- **出站关联**：解释器发起外联（`python3`、`curl`、`osascript`）几乎都是异常

### 14.7 持久化审计节奏

| 频率 | 动作 |
|------|------|
| 每周 | `systemextensionsctl list`；登录项面板扫一眼；异常发热/风扇 |
| 每月 | 上文 14.3 全量脚本；TCC 三大权限审计；描述文件与根证书 |
| 每季 | `sfltool dumpbtm` 与上季差异比对；统一日志抽样；备份可恢复性验证 |
| 事件后 | sysdiagnose + 完整持久化清单 + 变更时间线 |

---

## 15. 取证、物理与现场防线

### 15.1 物理访问在 Mac 上的实际威胁

Apple Silicon + FileVault + 强登录密码组合下，"纯物理突破"门槛显著高于 Intel 时代（单用户模式旁路已成为历史）。剩余的现实风险：

1. **设备处于已登录状态**（最常见也最致命）：攻击者有数秒即可完成端口监听、读取钥匙串、注入进程、安装描述文件
2. **休眠而非关机**：唤醒只需 Touch ID/短密码，密钥材料仍在内存
3. **弱/4 位 PIN 或常见密码**：取证工具在有漏洞的系统上可循环尝试
4. **未修复的本地提权漏洞**：使 root shell 可在数秒内获得
5. **配件通道**：Thunderbolt/USB HID 注入、恶意充电/扩展坞
6. **供应链预装**：二手机器、官方渠道之外的翻新设备（固件级预置）

### 15.2 现场防线配置

```bash
# 立即锁屏（而非等待 5 分钟）
defaults -currentHost write com.apple.controlcenter "NSStatusItem Visible Item-0" -bool true 2>/dev/null
sysadminctl -screenLock immediate -password "…"    # 需要管理员授权，按提示执行
defaults write com.apple.screensaver idleTime -int 60

# 关闭自动登录（严重风险，很多人为了省事开着）
sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null

# 锁屏不显示通知内容
defaults write com.apple.notificationcenterui showDeliverOnLock -bool false 2>/dev/null
# 更可靠：系统设置 → 通知 → 显示预览 → 从不

# 禁止控制中心的敏感项在锁屏可达
# 系统设置 → 控制中心 → 逐项设为"登录时"

# 关机而非休眠（离开不可信环境前）
sudo pmset schedule shutdown …   # 或直接 sudo shutdown -h now

# 触控 ID/密码策略：多次失败后要求密码
sysadminctl -loginWindowLogoutOnAuthFailure on -password "…" 2>/dev/null
```

**行为习惯**：

- 进入任何无人看管场景前：**合盖（休眠）不如关机**；高威胁场景用关机
- 会议/机场/海关：**独立设备**，敏感数据不落本地
- 二手/受赠设备：**全新抹掉 + 恢复模式重装**，并检查是否被 MDM 登记（`profiles status -type enrollment`）
- 不使用他人/公共扩展坞与"充电站"

### 15.3 账户与远程服务面

```bash
# 列出所有本地账户（寻找隐藏/残留管理员）
dscl . -list /Users UniqueID | awk '$2>=500 && $2!=501' | sort -n
dscl . -read /Groups/admin GroupMembership

# 隐藏账户特征：UserID>=500 且 name 以 $ 结尾（CreateHiddenAccount 手法）
dscl . -list /Users | grep '\$$' 2>/dev/null

# root 账户状态（默认应为禁用）
dscl . -read /Users/root AuthenticationAuthority 2>/dev/null

# 安全令牌持有者（FileVault 解锁者）
sudo fdesetup list
sysadminctl -secureTokenStatus "$(whoami)" 2>/dev/null
```

**要点**：

- **日常使用标准账户，管理操作单独 admin 账户**：这是 macOS 上最被低估的加固。它让 `sudo`、TCC 高危授权、描述文件安装都需要另一个凭据，攻击者即便入侵会话也无法静默完成权限提升动作
- 删除不用的账户；离职者账户立即移除并撤销 FileVault 保护者身份
- 确认 root 未被长期启用

### 15.4 远程擦除与设备定位

- **Find My（查找）**：定位、播放声音、标记丢失、远程抹除；依赖网络与"查找"网络（离线蓝牙中继）
- **MDM 命令**：机构设备可被远程锁定/擦除/重装；企业应验证命令送达
- **局限**：设备被关机/放入屏蔽袋后，所有远程指令在恢复联网前无法执行 → **远程擦除不能作为唯一手段**
- **Activation Lock** 保护设备可用性，不保护数据

**预案（丢失时的正确顺序）**：

1. 立即另一台设备登录 `icloud.com/find` → 标记丢失 + 锁定
2. 确信不可回收 → 远程抹除
3. 修改关键账户密码（尤其邮件、金融、云）——**假定凭据已暴露**
4. 撤销该设备在所有服务中的会话（Apple ID 设备列表、Google、GitHub、密码库）
5. 检查 FileVault 保护者列表与 MDM 登记状态
6. 若机构设备，通知安全团队启动取证保留

### 15.5 取证视角：攻击者/调查者能看到什么

理解这一点才能做对决策：

- **FileVault 关闭状态下**：整机镜像可得，历史删除文件在块层/快照/APFS 元数据中大量可见
- **FileVault 开启但设备已登录**：与关闭差别不大（明文可读写）
- **FileVault 开启且关机**：需要凭据或漏洞；历史残留不可读（密钥销毁时例外）
- **APFS 快照与 Time Machine 本地快照**：可能保留"你以为删掉了"的完整版本
  ```bash
  tmutil listlocalsnapshots /
  diskutil apfs listSnapshots disk3s1 2>/dev/null
  tmutil enablelocal_snapshot  # 需要时创建；删除用 diskutil apfs deleteSnapshot
  ```
- **统一日志**：保留期有限但信息密度高（进程、授权、网络、Gatekeeper 判定）
- **偏好设置 plist、`.zsh_history`、最近打开项、书签数据库**（`~/Library/com.apple.recentitems`、`~/Library/Preferences/com.apple.recentitems.plist`、Safari/浏览器历史、`com.apple.LaunchServices` 数据库）是重建行为的主要来源
  ```bash
  # 查看"最近使用"的登记
  /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump 2>/dev/null | grep -iE "path:|bundle" | head -40
  ```

**极客推论**：如果需要**避免行为痕迹**，"删除文件"远远不够；需要理解快照、历史与日志的保留结构。反之，如果需要**证明失陷**，这些地方就是证据源。

### 15.6 系统级取证采集（应急）

```bash
# 一次性采集可疑面
mkdir -p /tmp/ir/$(date +%F) && cd $_
systemextensionsctl list > systemextensions.txt
sfltool dumpbtm > btm.txt 2>/dev/null
launchctl print system > launchd_system.txt 2>/dev/null
launchctl print "gui/$(id -u)" > launchd_gui.txt
sudo lsof -i -n -P > sockets.txt
ps auxww > processes.txt
crontab -l > crontab.txt 2>/dev/null
ls -laR /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents > persistence.txt
sudo profiles show -type configuration > profiles.txt
fdesetup status > filevault.txt; sudo fdesetup list > fde_users.txt
csrutil status > sip.txt
spctl --status > gatekeeper.txt
pmset -g log | tail -200 > power_log.txt
sudo sysdiagnose -F . && ls -lh sysdiagnose* 2>/dev/null
```

把这份产物保存并交予可信研究者，比在本机反复自查更有价值——**本机已被攻破时，本机工具的输出不可信**。

---

## 16. 分层加固清单、检测工具与持续防御

### 16.1 三档配置模板

**Tier 1：技术用户基线（T0-T1）**

| 项 | 要求 |
|----|------|
| 系统更新 | 自动 + 快速安全响应全开 |
| FileVault | 开启，恢复密钥离线保管 |
| 登录 | 强密码；`screenLock immediate`；关闭自动登录 |
| SIP / 认证根 | 开启（确认 `Enabled`） |
| Gatekeeper | 开启，绝不 `spctl --master-disable` |
| 应用来源 | App Store / 已公证 Developer ID；不 `xattr -d com.apple.quarantine` |
| TCC | 辅助功能/屏幕录制/全盘访问仅授予可完整解释其必要性的应用 |
| 二次验证 | 硬件密钥或 Passkey；禁用 SMS |
| 密码库 | 独立主密钥（不与登录密码同源） |
| 包管理 | 只用官方 tap/cask；锁定依赖与哈希 |
| 浏览器 | Safari/Chrome 更新 + uBlock Origin Lite/规范版；不点可疑下载 |
| 远程服务 | SSH、屏幕共享、文件共享默认关闭 |
| 显示扩展名 | Finder 始终显示扩展名 |
| 出站控制 | 至少 Little Snitch/LuLu 提示模式 |
| 休眠 | 默认（3）可接受 |

**Tier 2：敏感职业/资产（T2-T3 部分）**

Tier 1 全部，另加：

- **日常使用标准账户 + 单独 admin 账户**
- **Recovery Lock / 启动策略"完整安全性"** + 组织下禁止用户改动
- **锁定模式**：跨境、会议、抗议、敏感会面场景启用
- **iCloud 高级数据保护** + 恢复密钥金属备份异地
- **独立设备分离身份**：研究/工作/加密资产管理各一台
- **出站控制改为白名单默认拒绝**（LuLu/Santa 组合）
- **Santa 二进制授权**：新哈希一律询问
- **每月 TCC + 持久化审计**（第 14 章全脚本）；`sfltool dumpbtm` 季度比对
- **不装任何第三方内核扩展/驱动**；要求走 DriverKit
- **SSH/云凭据使用硬件密钥或短期 STS**；长期 AK/SK 不落盘
- **签名密钥（Apple Developer / GPG / 代码签名）**置于硬件密钥或隔离构建机
- **备份策略**：加密外置介质 + 验证可恢复性（每半年演练）
- **构建链隔离**：发布构建在干净环境；工程注入检查

**Tier 3：高价值目标（T3-T4）**

Tier 2 全部，另加：

- **威胁订阅**：Apple Security Responses、厂商定向攻击通告、国家级 CERT 预警
- **家庭/办公网络分段**， IDS/被动流量分析，DNS 观测与日志
- **休眠改 `hibernatemode 0` 或 25**，接受可用性代价
- **长期密钥完全离线**（冷钱包/根 GPG/CA）
- **一次性设备用于跨境与高风险行程**，敏感数据不落本地
- **与可信研究者预建立通道**，应急时直接交付 sysdiagnose
- **团队级响应预案**：法务、通知义务、账户接管、恢复顺序
- **每季度红队/ATT&CK 自评**，把防御假设施压测试
- 接受"某些攻击无法检测"，把目标从"防住"调整为"缩短驻留时间 + 降低损失半径"

### 16.2 工具矩阵

| 目标 | 原生 | 第三方 |
|------|------|--------|
| 入站控制 | 应用防火墙 `socketfilterfw` | — |
| 出站控制 | 无 | LuLu / Little Snitch / Radio Silence |
| 执行授权 | Gatekeeper | **Santa**（白名单）/ EDR |
| 持久化监控 | BTM（`sfltool`）、登录项 | **BlockBlock**、Tock |
| 执行可视化 | 统一日志 | **Timestep**、EDR |
| 行为审计 | `fs_usage`、`log show` | EndpointSecurity 类（需 Apple 批准） |
| 主机遥测 | `sysdiagnose`、报告 | osquery、T3、Falcon/SentinelOne/Defender |
| 签名校验 | `codesign`、`spctl`、`pkgutil` | — |
| 快照可见性 | `tmutil`、`diskutil apfs` | — |
| 密钥与凭据 | 钥匙串、iCloud Keychain | Bitwarden / KeePassXC / 1Password |

**说明**：`dtrace` 在 Apple Silicon 上不可用，Intel 上也需关闭 SIP；可观测性主要靠统一日志 + ESF 类工具。Docker/虚拟化会引入额外内核面，敏感场景避免常驻容器运行时。

### 16.3 常见反模式（不要做）

| 反模式 | 真实风险 |
|--------|---------|
| `spctl --master-disable` | 关闭来源检查，一次性废掉第 5 层 |
| `xattr -d com.apple.quarantine` 当作教程执行 | 绕过 Gatekeeper 评估 + 路径随机化 |
| 为"某工具需要"关闭 SIP | 废掉 SSV/AMFI/内核保护，全栈崩塌 |
| 授予陌生/临时二进制 Full Disk Access | 交出全部浏览器会话、钥匙串外凭据、`.ssh` |
| 用登录密码作为唯一密码库主密码 | 拿到登录密码即可静默导出钥匙串 |
| 长期保持已登录 + 外设随意接入 | HID 注入数秒立足 |
| 日常使用 admin 账户 | sudo 一次即 root，TCC 授权无人复核 |
| "装了杀毒就安全" | macOS 失陷多为授权/来源问题，非特征可表达 |
| 忽略 MDM 描述文件与根 CA | HTTPS 中间人与批量投递 |
| 只在被攻击后第一次看 `sfltool dumpbtm` | 无基线，无法判定异常 |
| 自动更新长期"稍后提醒" | 修补窗口内被动暴露（DPH、XPC 类缺陷均为实际利用） |

### 16.4 iOS 与 macOS 防线的分工（快速对照）

| 维度 | iOS | macOS |
|------|-----|-------|
| 代码来源 | 单一商店（欧盟例外） | 任意下载 + 包管理 + 编译 |
| 默认执行防线 | AMFI + 商店审核 | Gatekeeper + 公证（可关） |
| 沙盒 | 全应用强制 | 仅 App Store 强制 |
| 隐私授权 | 细粒度，无"全盘访问" | **Full Disk Access / 屏幕录制 / 辅助功能是提权捷径** |
| 物理旁路 | 已大幅收敛 | Apple Silicon 已收敛；Intel 遗留风险 |
| 内建清除 | 无（依赖更新） | XProtect + Remediator |
| 可观测性 | 用户几乎无法审计 | **可审计性强：日志、BTM、EDR、白名单** |
| 主要风险 | 零点击/水坑链、账户恢复 | **来源治理 + 授权纪律 + 供应链** |
| 极客重点 | 攻击面最小化 | **建立基线并检测偏离** |

这条差异是本报告的实践结论：**iOS 极客防线以"减少暴露面"为主，macOS 极客防线以"可观测与可审计"为主。** 在 Mac 上，你能做而 iPhone 上做不到的事，恰恰是长期防御的价值来源。

### 16.5 持续防御节奏

**每日（<10 秒）**

- 离开座位即锁屏；进入不可信环境前关机
- 任何 TCC 弹窗先读"谁在请求"
- 异常发热/风扇/流量 → 记一次审计

**每周**

- 系统与安全响应更新
- `systemextensionsctl list`、登录项面板扫视
- 浏览器扩展列表扫视

**每月**

- 运行第 14.3 全量脚本并比对基线
- TCC 三大权限逐项审查
- 描述文件与根证书审计
- Apple ID / 密码库已登录设备审查

**每季**

- `sfltool dumpbtm` 差异比对
- 备份恢复演练
- 恢复密钥可读性验证
- 依赖审计（`npm audit`、`brew outdated`、锁定文件复核）
- 威胁模型重估

**每年**

- 设备代际评估（是否仍在安全更新范围内）
- 独立账户/密码库策略重审
- Tier 等级重新定级

### 16.6 情报源

- **Apple 安全发布与 Security Responses**：Apple 安全发布页 + Security Response 文档（专门披露"已在真实定向攻击中被利用"的漏洞，如 MoveOneFile、FORCEDENTRY、DPH Attack 类）
- **CVE/NVD** 与 CISA KEV 目录（判断"是否已被利用"的最实用信号）
- **厂商研究**：Objective-See（工具与案例）、SentinelOne、Elastic、Little Snitch/LuLu 社区、iCloud/MDM 厂商通告、微软与谷歌威胁情报的 macOS 定向攻击报告
- **社区**：macOS 安全研究议程、ATT&CK for Mac 技术矩阵（把防御项逐条映射到技术编号，可检验覆盖面）

### 16.7 结语：macOS 防线的本质

macOS 拥有与 iOS 同源、甚至更强大的硬件与完整性底座（SEP、SIP、SSV、PAC、SPTM/TXM、FileVault），但它把这些底座架在**一个允许用户随意执行代码的通用系统**之上。结果是：

- **远程利用链的门槛比 Windows 高，但本地立足后的驻留比 iOS 容易得多**
- 决定成败的不是"有没有 0-day"，而是"用户是否清了隔离属性、点了允许、装了描述文件、给了全盘访问"
- 因此 macOS 极客防线的核心不是堆叠工具，而是三件事：
  1. **来源治理**：谁能在这台机器上执行
  2. **授权纪律**：TCC 三大权限按 root 级对待
  3. **可观测性**：持久化、扩展、出站、BTM 建立基线并定期比对

做到这三条，Mac 会成为比多数平台更难被长期驻留的目标。做不到，再多的硬件信任根也只是启动时被校验一次而已。

---

## 附录：一页速查

**开机后先确认的四件事**

```bash
csrutil status                                   # enabled
csrutil authenticated-root status                # enabled
fdesetup status                                  # FileVault is On
spctl --status                                   # assessments enabled
```

**每月四个命令**

```bash
systemextensionsctl list
sudo profiles show -type configuration
sfltool dumpbtm | less
log show --last 30d --predicate 'subsystem == "com.apple.TCC"' | grep -i grant
```

**三大高危权限的审查入口**

系统设置 → 隐私与安全性 → **辅助功能** / **屏幕录制与系统音频** / **全盘访问**
> 每一项都问："如果这个进程完全可信，我还需要别的防线吗？"

**必须立刻自查的三个动作**

1. 关闭自动登录、锁屏改为立即
2. 撤销所有你无法解释用途的 TCC 授权
3. 把关键账户从 SMS 迁到硬件密钥 / Passkey

**咨询ios系统请咨询 telegram：@pengqing666**

---

**报告完成日期**：2026 年 10 月 15 日

**版本**：1.0

**用途声明**：本报告为教育性质的防御分析，聚焦用户如何加固 macOS 设备、检测异常并准备应急响应。所有攻击案例均来自公开安全研究与厂商报告；文中命令用于本机审计与取证采集，不涉及任何漏洞利用细节或未公开技术。macOS 各版本机制的引入时间与可用范围随版本和机型存在差异，具体请以 Apple 官方平台安全文档为准。

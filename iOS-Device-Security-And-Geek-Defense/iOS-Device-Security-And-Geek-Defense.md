# iOS 设备安全与极客防线

## 目录

1. 引言：极客防线的定义与威胁建模
2. 硬件信任根：iOS 安全的物理基石
3. 安全启动链与操作系统完整性
4. 数据保护与加密体系
5. 运行时防线：内核、沙盒与强制访问控制
6. 设备访问防线：认证、锁屏与胁迫应对
7. 通信安全防线：消息、通话与元数据
8. 网络层防线：DNS、VPN、中继与链路
9. 应用与供应链防线
10. 浏览器与 Web 内容防线
11. 间谍软件与零点击攻击防线
12. 物理取证与现场防线
13. 极客工具箱：检测、取证、日志与监控
14. 账户、iCloud 与跨设备防线
15. 备份、恢复与灾难预案
16. 分层加固配置与持续防御

---

## 1. 引言：极客防线的定义与威胁建模

### 1.1 为什么需要"极客防线"

iOS 常被称为"开箱即安全"的移动平台。对于绝大多数用户而言，默认的 iOS 安全设置确实已经超越了市场上多数竞争对手。但"对普通用户足够"和"对高价值目标足够"之间存在巨大鸿沟。

"极客防线"（Geek Defense Line）指的是由具备技术能力的用户、安全研究人员和高风险从业者主动构建的**多层纵深防御体系**。它不依赖 Apple 的默认配置，而是在默认之上叠加：

- **主动加固**：关闭不必要的攻击面（AirDrop、通用控制、Siri 锁屏访问等）
- **被动检测**：部署日志采集、网络监控、异常告警机制
- **应急响应**：预先演练失陷处置、数据销毁、证据保全流程
- **威胁建模**：明确自身面临的对手等级，针对性配置防线

本报告面向的对象不是普通消费者，而是那些有理由相信自己会被针对性攻击的人：安全研究员、记者、活动人士、加密货币持有者、企业高管、逆向工程师，以及任何希望把 iOS 设备安全性推向工程极限的技术用户。

### 1.2 威胁建模：先定义对手，再构建防线

任何安全决策都必须从威胁建模开始。没有威胁模型的加固要么是浪费，要么是虚假的安全感。

**对手分级模型（Adversary Tier）：**

| 等级 | 对手类型 | 能力 | 成本 | 典型工具 |
|------|---------|------|------|---------|
| T0 | 随机网络犯罪 | 批量扫描、钓鱼、已知漏洞 | 极低 | 恶意广告、Credential stuffing |
| T1 | 小型犯罪团伙 | 定制钓鱼、购买exploit kit | 低-中 | GreyNoise 观察到的商业 exploit |
| T2 | 商业间谍软件厂商 | 零点击链、持久化、C2 | 高（单目标数十万美元） | NSO Pegasus、Cytrox Predator、QuaDream |
| T3 | 国家级 APT | 0-day 库、签名字节码、基础设施 | 极高 | 定制 implant、供应链介入 |
| T4 | 执法/取证机构 | 物理控制、Cellebrite/GrayKey | 中（合法授权） | UFED、GrayKey、硬件提取 |
| T5 | 内部威胁 | 设备访问、社会工程 | 低 | 偷窥、胁迫解锁、短暂物理接触 |

**防线设计原则：**

1. **分层**：每层假设上层已被突破
2. **纵深**：攻击者需要连续突破多层才能获得价值
3. **可观测**：无法检测的攻击等于无限期驻留
4. **可恢复**：假定最终会失陷，备份与重置流程必须就绪
5. **成本不对称**：让攻击成本高于收益

### 1.3 攻击面全景

一台现代 iPhone 的攻击面远比用户想象的宽阔：

```
┌──────────────────────────────────────────────────────┐
│                  iPhone 攻击面地图                     │
├──────────────┬──────────────┬────────────────────────┤
│  远程攻击面   │  近距攻击面    │  物理/本地攻击面        │
├──────────────┼──────────────┼────────────────────────┤
│ iMessage     │ Wi-Fi (AWD)  │ 充电 USB / Lightning   │
│ Push 服务     │ Bluetooth    │ SIM / eSIM             │
│ WebKit (Safari)│ NFC/钱包    │ 拆机 / 芯片微探         │
│ SMS/MMS      │ UWB 超宽带    │ 恢复模式 / DFU         │
│ FaceTime     │ AirDrop      │ 胁迫 / 偷窥            │
│ 邮件附件      │ 基站 (2G/伪) │ 冷启动内存提取          │
│ 零点击媒体解码 │ 车载/配件     │ 越狱检测绕过           │
│ App 更新     │              │                        │
└──────────────┴──────────────┴────────────────────────┘
```

**入口优先级（按实际攻击频率）：**

1. **社会工程 / 钓鱼**：占实际失陷案例的绝大多数，成本最低
2. **浏览器（WebKit）**：水坑攻击的主要载体，需用户点击
3. **消息类零点击**：iMessage 附件解析链，无需交互
4. **Push 通知服务**：历史exploit链的起点
5. **物理访问**：取证设备、短暂离手
6. **供应链**：越狱插件、快捷指令、企业签名应用

### 1.4 防线的三个层次

极客防线在实践上分为三个层次，用户应根据自己的威胁等级选择投入：

**第一层：基线加固（Baseline Hardening）** — 所有技术用户都应执行

- 保持系统最新
- 强密码与生物识别组合
- 关闭锁屏不必要功能
- 锁定模式的条件启用
- 基础隐私设置收紧

**第二层：主动监控（Active Monitoring）** — T2+ 威胁模型

- Sysdiagnose 定期采集
- 网络流量基线与异常检测
- 配置文件（Profile）审计
- 电池/流量/后台活动异常排查
- iMessage 过滤规则（如 MobileNet/Pegasus 检测规则）

**第三层：作战安全（Operational Security, OpSec）** — T3/T4 威胁模型

- 设备分离（身份/用途物理隔离）
- 熔断与销毁预案
- 长期无电隔离（Radio off / 设备留置）
- 取证反制（快速擦除、密钥清除）
- 通信协议分层（敏感话题只用 E2EE，且非 Apple ID 关联账号）

### 1.5 本报告的使用方法

后续 15 章按防线的层次从底层硬件到上层运营展开。每一章都包含：

- **技术原理**：机制如何工作，边界在哪里
- **攻击现实**：已知的绕过、滥用、历史案例
- **加固配置**：可执行的具体设置项
- **检测手段**：如何发现异常
- **权衡分析**：安全措施对可用性的代价

读者可以顺序阅读建立完整心智模型，也可以按第 16 章的分层清单直接执行。

---

## 2. 硬件信任根：iOS 安全的物理基石

### 2.1 Secure Enclave（SEP）架构

Secure Enclave Processor 是 iOS 硬件防线的核心。它是一颗独立封装在 SoC 内部的协处理器（早期为独立芯片，A7 之后集成进 SoC 但保持硬件隔离），运行 Apple 独有的 L5 微内核操作系统。

**关键特性：**

- **独立密钥层级**：SEP 拥有自己的 AES 引擎和一次性可编程（OTP）密钥（UID/HID key），这些密钥不在主 CPU 可访问的地址空间
- **独立随机数发生器**：硬件 TRNG
- **单调计数器**：防回滚（anti-rollback），密钥绑定时间戳
- **隔离总线**：SEP 与 AP（Application Processor）之间通过共享内存邮箱通信，主 CPU 无法直接读写 SEP 内部状态
- **最小攻击面**：L5 微内核代码量远小于 XNU，服务接口固定

**UID Key 的角色：**

```
UID Key（设备唯一、烧录于 SEP、永不离开）
    ↓
文件系统的 Class Key（AFS 密钥）
    ↓
每个文件的 Key Bag（密钥袋）
    ↓
文件内容 AES-GCM 解密
```

UID Key 是设备级物理绑定密钥。这意味着：

1. **数据无法从另一台设备读取**：把 NAND 移植到别的机器，没有 UID 就无法解密密钥袋
2. **Apple 也无法提取**：Apple 没有每台设备的 UID 副本，因此无法在设备解锁状态下为用户数据提供服务端解密（这是 iCloud 未开启端对端加密时"Apple 可访问"与"设备本地不可访问"区别的技术根因）
3. **取证工具必须在线爆破**：Cellebrite/GrayKey 的本质是在设备上通过漏洞利用不断尝试密码，无法离线加速

### 2.2 A14 及以后：内存加密（POE / MTE）

从 A14 Bionic 开始，Apple 引入了 **Pointer Authentication Codes (PAC)** 与 **Branch Authentication Codes (BRC)**，A17 Pro / M 系列进一步提供 **Exclusive Performance Monitor** 与更细粒度的内存保护。

**PAC 的作用：**

- 在 64 位指针的高位空闲比特中编码签名（基于 SP 的密钥）
- 任何指针使用前必须先 "AUTH"，被改写的指针会触发异常
- 极大提高了 ROP/JOP 面向返回编程攻击的成本

现代 iOS exploit 链中，攻击者常常需要先用信息泄露获取指针，再用某种方式绕过 PAC。Coruna、FORCEDENTRY 等案例都可以观察到 PAC 绕过模块占据了链路的相当比例。

**MTE（Memory Tagging Extension）**：Apple 在部分新硅片中采用类似 ARM MTE 的标记机制，在分配元数据打标签，访问时校验，检测 use-after-free。

### 2.3 SPTM 与 TXM：从 EL3 到内核完整性

iOS 17（2023）引入了 **Secure Page Table Monitor (SPTM)** 和 **Trusted Execution Monitor (TXM)**，取代旧式的 AMFI/KPP 组合，构成新的强制隔离层。

**架构分层：**

```
┌────────────────────────────────────────┐
│  EL3: SPTM (Secure Page Table Monitor) │  ← 管理所有页表，唯一权威
├────────────────────────────────────────┤
│  TXM: Trusted Execution Monitor         │  ← 验证内核/系统扩展完整性
├────────────────────────────────────────┤
│  Kernel (XNU) + DriverKit               │
├────────────────────────────────────────┤
│  User Application (沙盒)                 │
└────────────────────────────────────────┘
```

**SPTM 提供的保证：**

1. **DMA 保护**：外设发起的直接内存访问必须经过 SPTM 映射，恶意外设无法任意读写内核内存
2. **W^X 强制**：任何内存页都不能同时可写可执行，包括内核（历史上内核 RWX 页是常见的代码注入目标）
3. **内核代码只读**：即使内核被完全攻陷也无法修改自身页表
4. **拒绝执行攻击载荷**：写入的 shellcode 无法执行

**TXM 的作用：**

- 作为可信度量根，验证加载的每个内核二进制和系统扩展
- 维护 "monitor" 状态，可捕获内核违规行为（相当于 KPP 的现代化替代品）
- 崩溃时产生独立的 TXM panic log，用于事后取证

**对极客防线的意义**：SPTM/TXM 显著抬高了内核提权的门槛。历史 iOS 内核提权链常常依赖修改页表或注入可执行代码，这两条路都被切断。因此现代链路的下一步往往转向"寻找合法的、可写的、能改变内核控制流的数据结构"（如 kalloc 溢出后覆盖函数指针）。

### 2.4 Exclaves：面向第三方隔离执行（iOS 26）

Apple 在 2025 年 WWDC 公布了 **Exclaves** 框架，首次向第三方应用开放基于 SPTM 的 DMA 保护隔离域能力。

**核心模型：**

```
┌────────────────────────────────────────┐
│  应用主进程（不可信）                     │
├────────────────────────────────────────┤
│  Exclave 隔离域（客户客户）              │
│   - 独立内存映射                        │
│   - 应用主进程无法读取                    │
│   - 只能主动发送请求                     │
└────────────────────────────────────────┘
```

**意义：**

- 密钥材料、生物特征模板、AI 推理权重等可以放入 Exclave
- 即使主进程被完全攻陷（含内核漏洞利用），攻击者也无法直接读取 Exclave 内存
- Apple 声称这是"客户对客户的机密计算"（Customer-to-Customer Confidential Computing）

**极客关注点：**

- 关注哪些应用启用了 Exclaves（密码管理、健康、身份验证类）
- 未来该框架将逐步成为关键秘密存放的推荐位置

### 2.5 Boot ROM 与不可变固件

苹果设备的 **Boot ROM**（或称为 Secure Boot ROM）在芯片制造阶段一次性烧录（OTP ROM），永不改变。它的存在决定了整个信任链的可信起点。

**关键事实：**

- **checkm8 漏洞（CVE-2019-8660）**：A5–A11 芯片的 DFU Boot ROM 存在可被利用的 USB 恢复栈溢出，是**不可修补**的硬件漏洞。这是历史上第一个公开的、永久性的 iPhone  bootrom 缺陷
- 攻击影响：允许攻击者获得 SEP 之外的固件加载权限，为 checkm8 之后所有越狱工具（checkra1n、palera1n 等）提供了基础
- **应对方案**：如果威胁模型包含 T4 级执法取证或 T3 级国家力量，A11 及以下设备（iPhone X 及更早）存在硬件级不可消除的攻击面
- **A12 及以后**：Boot ROM 重写了 USB 栈，目前尚无公开的不可变漏洞

**防线建议**：任何承载高价值目标的 iPhone 至少应为 A12（XS）代。对于极端场景，Apple 官方在 iOS 中提供了 **Recovery Lock**（iOS 18+）以及 **USB Restricted Mode**，与 Boot ROM 层设计形成互补。

### 2.6 硬件指纹与设备绑定

iOS 设备通过多层硬件身份绑定保护数据：

**主要标识：**

- **UDID**：设备唯一标识（256 位哈希）， iTunes 时代用于激活锁定
- **ECID**：设备特定的熵数据，固件恢复时用于个性化签名（APTicket）
- **SEP UID**：SEP 内部一次性可编程密钥，永不可读出
- **T2/Secure Enclave Key Vault**：M 系列 / iPhone 15 Pro 后引入的更大密钥库

**激活锁（Activation Lock）依赖：**

- 硬件 ECID 与 Apple ID 服务器绑定
- 刷机/恢复后仍需要原 Apple ID 凭证才能重新激活
- 这是防"设备物理失窃"的最后防线，但对"数据提取"无作用

### 2.7 硬件攻击现实

**针对 SEP 的已知物理攻击：**

1. **故障注入（glitching）**：对电源/时钟注入毛刺，尝试绕过安全启动验证。历史上对 Apple S1（Watch）与早期 SEP 有过学术成功，但对 A10+ 主 iOS 设备没有公开的实用攻击
2. **差分功耗分析（DPA）**：提取加密密钥。Apple 在 SEP 中使用了掩码和恒定时间实现抵抗
3. **芯片翻转（FIB / focused ion beam）**：修改 SEP 电路。成本极高（百万美元级），只在实验室内有成功案例
4. **总线嗅探**：早期设备（A9 及以前）NAND 通过外部总线连接，可被嗅探。现代 SoC 集成后 NAND 也走内部封装

**防线结论**：

- 对绝大多数极客威胁模型，物理攻击 SEP 不现实
- 但需要**警惕冷启动攻击**：设备关机后短时间内内存内容仍可读，因此对高价值目标，长期不用时应**彻底关机（不是睡眠）**并避免物理接触
- 建议：**每日至少一次关机**，尤其在进入不可信环境前

### 2.8 硬件层配置清单

**推荐操作：**

| 操作 | 影响 | 建议 |
|------|------|------|
| 使用 A12 及以上设备 | 规避 checkm8 | 强制 |
| 关闭 USB 配件限制外的连接 | USB Restricted Mode | 高价值目标始终锁定 |
| 保持 iOS 最新 | 修补 SPTM/TXM | 强制 |
| 关闭"通过 USB 连接电脑" | 减少 DMA 面 | 高威胁 |
| 定期完全关机 | 阻断冷启动/取证 | 敏感场景 |
| 避免未知 MFi 配件 | 降低外设风险 | 强制 |

---

## 3. 安全启动链与操作系统完整性

### 3.1 启动链的逐级验证

iOS 启动过程是一条严格的密码学信任链，每一级验证下一级：

```
┌──────────────┐
│ Boot ROM      │  ← 出厂烧录，验证 LLB/IBSS 签名
└──────┬───────┘
       ↓
┌──────────────┐
│ Low-Level     │  ← Apple 签名，配置最小硬件
│ Bootloader    │
└──────┬───────┘
       ↓
┌──────────────┐
│ iBoot         │  ← Apple 签名，加载内核
└──────┬───────┘
       ↓
┌──────────────┐
│ DeviceTree    │  ← 硬件描述，签名
└──────┬───────┘
       ↓
┌──────────────┐
│ Kernelcache   │  ← 内核 + 系统扩展，签名
│  (XNU)       │
└──────┬───────┘
       ↓
┌──────────────┐
│ launchd       │  ← 系统服务
└──────────────┘
```

**每一级验证内容：**

- 签名必须来自 Apple 的固件签名私钥
- 版本号必须 ≥ 最低允许版本（防降级，SEP 单调计数器记录）
- 特定设备允许版本由 **APTicket**（BETicket 的产物）在恢复时个性化生成

### 3.2 APTicket 与降级保护

**APTicket（Apple Pipeline Ticket）**：

- 在恢复/更新时向 Apple 服务器请求，Apple 针对 ECID 签发当前允许的版本
- 存储在 SEP 内部（加密区）
- 决定了设备能启动哪个 iOS 版本

**降级防护（Anti-Rollback）：**

- SEP 的单调计数器递增记录"曾允许的最高版本"
- 即使 APTicket 文件被保留，也无法用旧 ticket 加载旧固件
- **例外**：当 Apple 主动停止签名旧版本时，历史 APTicket 立即失效——这是"验证窗口"（verification window）的机制

**极客注意点：**

- 一旦新版本发布且 Apple 停止签名，你就无法回到旧版本
- 对已知含漏洞的旧版本（如 CVE 未修补），你无法主动停留在旧版本——这是安全设计，但对某些需要兼容旧工具链的用户是障碍

### 3.3 Secure Boot 与 iBoot 变体

**iBoot 三种模式：**

1. **Normal Mode**：完整启动链验证，加载签名内核
2. **Recovery Mode**：加载 Apple 签名的恢复内核，允许升级但禁止降级
3. **DFU Mode**（Device Firmware Update）：跳过 iBoot，从 USB 加载 LLB/Restore 组件，用于完全恢复

**DFU 攻击面：**

- checkm8 影响的设备在 DFU 中可被植入攻击载荷
- 即使现代设备 DFU 只能刷入 Apple 签名固件，攻击者仍可通过恢复实现"擦除证据"，这对反取证有价值但对反攻击者同样有效
- iOS 恢复过程会重置激活锁状态，但服务器端仍保留绑定，非授权设备变砖

**Recovery Lock（iOS 18 引入）：**

- 用户可选择在恢复模式下要求 Face ID / 密码 + Apple ID 双重验证
- 显著提高了攻击者通过"短暂物理接触 → 恢复 → 绕过锁屏"的门槛
- 建议：所有高价值设备**必须开启**

### 3.4 Kernel Integrity Protection 与 KPP

在 SPTM 出现之前，iOS 使用 **Kernel Patch Protection (KPP)**，也称 **Clocks Protection**，运行在 EL3/安全监控中周期性校验内核代码段完整性。

**KPP 的历史弱点：**

- 校验存在时间窗口，攻击者可在窗口内执行修改
- 现代内核提权链（如 Triton/Triangulation 案例中的 XPU 组件）已能绕过或让校验器"自愿接受"修改
- 因此 Apple 用 SPTM 取代了 KPP，采用页表级强制

### 3.5 AMFI 与代码签名

**Apple Mobile File Integrity (AMFI)** 是内核扩展，负责执行代码签名策略：

- 拒绝运行未签名代码
- 拒绝运行 entitlement 未获 Apple 授权签名的代码
- 对 JIT、dyld 环境、调试等实施额外授权

**entitlement 层级：**

```
┌──────────────────────────────────────┐
│  Apple Internal Entitlements          │  ← 仅 Apple 系统进程
├──────────────────────────────────────┤
│  Special Entitlements                 │  ← 特定开发者经 Apple 审批
│  (get-task-allow, dynamic-codesigning)│
├──────────────────────────────────────┤
│  Regular Entitlements                 │  ← 常规开发者可用
│  (application-identifier, keychain)   │
└──────────────────────────────────────┘
```

**极客关注点：**

- **越狱检测**本质是检测 AMFI 是否被禁用或替换、系统分区是否可写
- 现代工具（如 Shadow、XNF）通过 hook 让越狱检测"看不见"，因此单纯依赖检测工具会漏检
- 更可靠的完整性判断：检查 boot nonce、SEP 状态、系统分区的静态哈希

### 3.6 Launch Constraints 与 SIP

macOS 上的 **System Integrity Protection (SIP)** 在 iOS 上是**始终启用、不可关闭**的等价机制（部分能力体现为 launch constraints 与 sandbox restrictions）。

**iOS 上的"系统只读"表现：**

- 系统分区在 APFS 上以签名快照形式挂载（Sealed Volume）
- 每个 inode 被哈希进入 Merkle Tree，运行时校验
- **Signed System Volume (SSV)** 让任何对系统文件的修改都会导致启动失败
- 从 iOS 16 起，即使越狱也无法持久修改系统文件——只能运行时 hook

**SSV 的战略意义：**

- 越狱工具必须从 checkm8/其他漏洞进入内核，运行时"欺骗"进程而不是修改磁盘
- 每次重启后系统回到干净状态（"Rootless / Tweakless"越狱，如 palera1n）
- 攻击者植入的持久化必须放在非密封分区（用户数据、配置文件），从而更容易被检测

### 3.7 系统完整性监控与验证方法

**用户可执行的验证：**

1. **检查 OTA 状态**：设置 > 通用 > 软件更新，确认设备正在运行 Apple 仍在签名的版本
2. **恢复模式探测**（谨慎）：正常设备在恢复模式仅显示连接线图标或 "Connect to iTunes"，越狱/修改过的设备可能显示额外信息
3. **查看安装描述文件**：设置 > 通用 > VPN 与设备管理，检查是否有异常配置
4. **iCloud 中"设备"列表**：确认没有陌生设备
5. **Apple ID 安全码与登录历史**：account.apple.com 检查
6. **系统诊断数据**：设置 > 隐私与安全 > 分析与改进 > 分析数据，查看是否出现 TXM panic / kernel panic 异常频率
7. **通过第三方工具（如 Covert Signals、iMazing 系统信息）检查设备状态**

**关键日志：**

- `sysdiagnose`：Apple 提供的深度日志导出，长按 F12 或设置中触发
- **Kernel panic log**：出现在分析数据中，包含堆栈回溯
- **TXM panic**：反映内核完整性尝试被阻断
- **Crash report**：包含进程、异常类型、PAC 校验错误

**极客防线要点**：定期导出 sysdiagnose 并保存基线，一旦怀疑失陷，将异常日志交给可信研究者分析。

### 3.8 启动链的攻击现实与防御

**已知攻击方式：**

1. **Boot ROM 漏洞**：无法修补，只能规避设备型号
2. **降级攻击**：通过保存 APTicket 与旧固件回退到有漏洞的 iOS（前提：Apple 未关闭验证）
3. **Recovery 攻击**：物理访问下尝试恢复模式绕过（Recovery Lock 阻挡）
4. **SSV 绕过**：极少数情况下 Merkle 树校验被绕过（历史上出现过，Apple 快速修补）
5. **iBoot 漏洞**：Apple 每代设备 iBoot 二进制会泄露（通过 OTA 或提取），攻击者可离线研究

**防御优先级：**

- **保持最新版本**：iBoot 与内核漏洞一旦公开，Apple 平均 30-90 天内修补
- **启用 Recovery Lock**
- **避免 DFU 意外触发**：不带入有物理访问威胁的环境

---

## 4. 数据保护与加密体系

### 4.1 类密钥体系（Class Keys）与保护等级

iOS 文件级加密的核心是 **Data Protection API**，它把文件按敏感度分到不同"保护等级"（class），每级由独立的密钥保护。

**五个保护类：**

| 类名 | 密钥派生 | 可访问时机 | 典型用途 |
|------|---------|-----------|---------|
| NSFileProtectionComplete | 用户密码 + UID | 仅在设备解锁时 | 密码库、健康、通讯 App 数据 |
| NSFileProtectionCompleteUnlessOpen | 用户密码 + UID | 已打开的文件可继续访问 | 长时间下载、后台任务 |
| NSFileProtectionCompleteUntilFirstUserAuthentication | 系统密钥 | 首次解锁后一直可访问 | 一般 App 数据、缓存 |
| NSFileProtectionNone | 只有 UID | 始终可访问 | 系统资源、内核 |
| NSFileProtectionRead (iOS 9+) | 分离读/写 | 精细控制 | 少用 |

**技术细节：**

- 每个文件有独立的 **File Key**（AES-128 或 256）
- File Key 加密在 **Keybag** 中，Keybag 通过 **Class Key** 解密
- Class Key 由**用户密码 + UID**通过 PBKDF2/scrypt 派生
- 用户密码改动只换 Class Key，不需要重新加密所有内容

### 4.2 快速撕毁（Effaceable Storage）与销毁

早期 iOS（A4-A6 时代）在 NAND 中保留一段"Effaceable Storage"，可以通过抹掉 AES 密钥立即让数据不可读。这一机制被 **FileVault 类似的即时擦除**继承。

**"抹掉所有内容和设置"的实际效果：**

- 主密钥被丢弃
- Keybag 被清空
- 硬件层面：所有历史数据变成密文垃圾，无法恢复
- **注意**：某些极端物理攻击（如 eFuse 读取、扫描 NAND 位）在理论上仍可能，但对普通场景"抹掉"是足够的

**远程擦除（Find My）：**

- 通过 MDM 或 iCloud 命令下发
- 依赖设备联网且未被隔离
- **极客提醒**：不要把远程擦除作为唯一手段，因为攻击者拿到设备第一时间会放入信号屏蔽袋/关机

### 4.3 键链（Keychain）与访问控制

iOS 的 Keychain 是系统级密钥/凭证存储，安全等级由 **kSecAttrAccessible** 决定：

**Keychain 可访问性类：**

```
kSecAttrAccessibleWhenUnlocked
  → 最严格：仅解锁时可读，锁屏后应用重启即失效
  
kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
  → 要求设备已设密码，且不允许迁移到其他设备

kSecAttrAccessibleAfterFirstUnlock
  → 首次解锁后可读，通常用于后台数据

kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
  → 不迁移、不备份到 iCloud Keychain

kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  → 组合最严格 + 不迁移

kSecAttrAccessibleAlways (已废弃)
```

**极客关注：**

- 密码管理器是否使用 **ThisDeviceOnly**：跨设备同步的凭据意味着云端有可解密副本
- **iCloud Keychain**：端到端加密（自 iOS 10.3 起），需要设备密码 + Apple ID 恢复因子，安全模型可接受但仍受恢复联系人风险
- **高级数据保护**（Advanced Data Protection, iOS 16.2+）：iCloud Keychain 只由设备参与恢复，去除 Apple 服务端恢复

### 4.4 APFS 加密与快照完整性

iOS 使用 **APFS（Apple File System）**，几个关键设计：

**加密形态：**

- **Standard Encryption**：软件 AES-XTS（数据卷）+ AES-CBC（元数据），密钥受保护由 UID
- **Hardware Encryption**（A9 起）：文件级密钥由 SED（Self-Encrypting Drive）在 NAND 控制器中执行

**克隆与快照：**

- Copy-on-Write：修改不覆盖原块，可能残留旧数据在块中（Trim 后销毁）
- 快照保留：APFS snapshots 让升级可回滚，也意味着**旧数据的物理存在时间被延长**
- iOS 上的 APFS snapshots 通常保留 24-72 小时后自动清理

**对取证的意义：**

- 逻辑加密完整但**元数据（文件大小、时间戳、路径）明文可见**
- 攻击者知道"什么被删除"往往比知道"内容是什么"更容易
- Apple 从 iOS 16 起进一步收紧 metadata 保护

### 4.5 端对端加密（E2EE）与密钥所有权

极客防线要求对每一项数据服务明确"密钥在谁手上"。

**Apple 端 E2EE 覆盖清单（自 iOS 16.2 起，需启用 Advanced Data Protection）：**

| 服务 | 默认 | 启用 ADP 后 |
|------|------|-----------|
| iMessage | 端对端 | 端对端 |
| FaceTime | 端对端 | 端对端 |
| Apple Pay | 端对端 | 端对端 |
| 通讯录 | 非 E2EE | **端对端** |
| 日历 | 非 E2EE | **端对端** |
| 提醒 | 非 E2EE | **端对端** |
| Safari 书签 | 非 E2EE | **端对端** |
| 密码 | 端对端 | 端对端 |
| 快捷指令 | 非 E2EE | **端对端** |
| 照片 | 非 E2EE | **端对端** |
| 文件 App / iCloud Drive | 非 E2EE | **端对端** |
| 备忘录 | 非 E2EE | **端对端** |
| 备份 | 非 E2EE | **端对端** |
| Siri / Mail / Safari 历史 | 非 E2EE | **不覆盖** |

**Apple 无法访问的**（因为设计上就是 E2EE）：iMessage、FaceTime、Apple Pay 交易详情、Screen Time（可配置）

**Apple 保留访问权（即使 ADP）**：iCloud Mail、Siri、日历邀请（涉及服务器功能）

### 4.6 iCloud 高级数据保护（ADP）设置要点

**启用条件：**

- iOS 16.2+
- 已启用双因子认证（2FA）
- 至少一个可信设备（Trusted Device）+ 恢复联系人 / 恢复密钥

**恢复机制：**

三选一：

1. 可信设备
2. 恢复联系人（最多 3 人，每人有密钥份额）
3. 28 字符恢复密钥（推荐组合使用）

**极客注意：**

- **恢复联系人**引入社交信任风险：联系人设备失陷会暴露份额
- **纯恢复密钥**：纸质/金属备份，任何一次接触都可能被拍照
- **推荐**：至少"可信设备 + 28 字符密钥"，恢复联系人只作为附加

### 4.7 加密时基与硬件时钟

iOS 的类密钥使用**单调计数器（monotonic counter）**防止旧密钥回滚：

- SEP 内部记录"当前世代"
- 每次密码修改、抹除、部分安全事件递增
- 攻击者无法用备份还原到旧密钥状态

**现实影响：**

- 备份还原后可能失去某些加密项（因为密钥世代改变）
- ADP 依赖此机制防止"用旧设备重放"

### 4.8 数据保护配置清单

**推荐设置：**

- 使用 6 位以上字母数字密码，避免 4 位纯数字
- 打开"数据保护"（默认）
- 启用 ADP（如果威胁模型是窃听而非可用性风险）
- 关闭 iCloud 云备份中含敏感数据的部分
- 定期修改 Apple ID 密码（尤其怀疑暴露后）
- 密码管理优先选 ThisDeviceOnly 或本地存储 + 用户自有同步

**避免：**

- 使用"始终允许"类 Keychain 条目（除非有强理由）
- 长期保留旧 iCloud 备份（含敏感历史）
- 把生物识别当成"数据密钥"（Face ID 只是解锁 Class Key 的授权手段，不是加密密钥本身）

---

## 5. 运行时防线：内核、沙盒与强制访问控制

### 5.1 XNU 内核安全机制总览

XNU 是 iOS/macOS 的混合内核（Mach + BSD + IOKit），运行在 ARM64 EL1（Exception Level 1）特权级。iOS 版对普通用户进程施加了一整套安全约束：

**主要机制：**

- **AMFI**：代码签名与 entitlement 强制
- **CSM (Code Signing Memory)**：验证可执行内存区域
- **Sandbox (Seatbelt)**：MAC（Mandatory Access Control）规则
- **mac (Mandatory Access Control labels)**：进程/文件/端口的标签系统
- **PAC/BTI**：控制流完整性
- **SPTM/TXM**：页表与完整性（iOS 17+）
- **entitlement + provisioning profile**：能力约束

### 5.2 App Sandbox 结构

每个第三方应用运行在独立沙盒中：

```
/var/mobile/Containers/Data/Application/<UUID>/
├── Documents/         ← 用户可见文件（iCloud 可能同步）
├── Library/
│   ├── Application Support/  ← 应用主存储
│   ├── Caches/
│   └── Preferences/          ← plist
├── tmp/
└── (系统级容器独立)
```

**沙盒强制机制：**

- 内核通过 **Seatbelt** 策略语言定义每个进程的规则
- 规则匹配文件路径、mach 服务、POSIX syscall、网络、系统调用
- **默认拒绝**（deny default）
- App 的 profile 由 AMFI 从签名的 entitlements 生成

**越狱/攻击如何绕过：**

1. **利用有较高 entitlement 的系统进程**：如 WebKit 通过 com.apple.fontservicesd 逃逸到共享服务
2. **利用 mach 服务**：许多系统服务对外开放，输入解析漏洞可提权
3. **符号链接攻击**：早期 iOS 曾有 sandbox escape 通过共享目录符号链接
4. **XPC 类型混淆**：现代链路（如 FORCEDENTRY 的 PDF 解析、Triangulation 的 RTKit）常见
5. **内核漏洞直接绕过**：获取内核任意读写后修改沙盒凭证

### 5.3 进程隔离与任务端口（task_for_pid）

**task_for_pid 权限：**

- Mach 任务端口提供对进程内存/线程的调试访问
- iOS 上默认只有具备 `task_for_pid-allow` entitlement 的进程（Apple 自家或调试器）能调用
- 越狱工具的核心成就之一就是绕过这个限制

**现代防护：**

- iOS 15 之后 `task_for_pid` 对 App Store 应用完全禁用
- Apple Silicon 上进一步限制 debugger attach

### 5.4 Mach IPC 与 XPC 攻击面

iOS 系统内部大量使用 Mach 端口与 XPC 服务通信。这些服务是攻击者从沙盒提权到系统服务的首选路径。

**关键攻击点：**

- **kernel_task**：进程 0，任何针对其端口的操作都极其敏感
- **launchd**：进程 1，负责启动服务
- **systemextensiond / neagentd**：网络扩展
- **sandboxd / cfprefsd / mediaserverd / audiod**
- **fontservicesd**：历史漏洞（Pegasus 曾利用）
- **diagnosd / mobileactivationd**

**防御设计：**

- XPC 服务通常有独立的 sandbox profile
- 服务的 mach 名字注册在 launchd，访问由沙盒规则控制
- iOS 17+ 对高风险服务进一步收紧（比如需要额外 entitlement 才能访问）

**极客关注：**

- 通过 sysdiagnose 分析异常 mach 消息流量是**高级检测手段**
- 大多数用户无法解读，但对 T3+ 目标，与安全研究社区共享日志是价值巨大的做法

### 5.5 内核扩展与 DriverKit

iOS 不允许第三方加载传统内核扩展（KEXT）。所有驱动必须走 **DriverKit**（Dext）：

- 用户态运行
- 严格的 entitlement
- 通过 IOKit 消息与内核通信

**优势：**

- 内核攻击面显著缩小
- 恶意驱动不再能直接执行内核代码

**残余风险：**

- IOKit 与内核通信接口仍是攻击面
- 历史上 RTKit（Real-Time 协处理器）驱动栈出过多次可利用漏洞，如 Triangulation 案例

### 5.6 强制代码完整性与 JIT

iOS 禁止应用运行时生成可执行代码（JIT 被严格限制）：

- WebKit JIT 需要特殊 entitlement + 内核支持
- 第三方 App 不允许 JIT（历史上导致开发者无法在 iOS 上运行 Lua/JS 引擎）
- iOS 16 起，Apple 开放了部分 JIT 场景（如 PlayCover 之外的官方支持）

**安全意义：**

- 阻止常见的"注入 shellcode → 跳转执行"模式
- 攻击者必须通过 ROP/JOP 复用已有代码
- PAC 让 ROP/JOP 也大幅复杂化

### 5.7 系统进程攻击现实

**已知的运行时攻击链（选择案例）：**

1. **Pegasus (NSO)**：iMessage 零点击 → WebKit 内存破坏 → 沙盒逃逸 → 提权 → 内核任意读写 → 移除痕迹
2. **FORCEDENTRY**：PDF 解析畸形 Calibri 字体 → 内核沙盒缺陷 → 提权
3. **Triangulation**：iOS RTKit 图像解码 → DMA 攻击 → 内核代码执行 → Boot ROM 隐藏持久化
4. **Operation Triangulation (KismetData/QuaDream 等)**：利用签名固件泄露与未修补设备

**极客防线要点：**

- **单一漏洞不足以失陷**：iOS 现代攻击需要多漏洞串联
- **但每一个漏洞都在补丁窗口内可利用**：延迟更新 = 暴露
- **锁定模式**：切断关键攻击面（如 JIT、部分 PDF 解析、水印消息处理）

### 5.8 运行时防线配置清单

**推荐操作：**

- 保持 iOS 最新版（SPTM/TXM 依赖）
- 关闭不必要的服务：Siri 锁屏、通知中心小部件、通用控制
- 敏感场景启用**锁定模式**
- 定期 sysdiagnose 存档（如每月一次）
- 关注 Apple 安全公告（每月的 CVE 列表）与 Citizen Lab 等研究机构的公开链分析
- 不使用来源不明的描述文件、快捷指令、越狱工具

---

## 6. 设备访问防线：认证、锁屏与胁迫应对

### 6.1 密码强度与解锁策略

iOS 数据保护类密钥的**强度上限受用户密码决定**。这是很多用户忽略的事实。

**密码熵估算（对 Class Key 派生）：**

- 4 位数字 PIN：约 13.3 bits
- 6 位数字：约 19.9 bits
- 8 位数字：约 26.6 bits
- 6 位混合字母数字：约 35.7 bits（大小写字母+数字）
- 12 位随机字母数字：约 71.4 bits

**Apple 的速率限制：**

- iOS 采用递增延迟 + Secure Enclave 内部计数器限制在线尝试
- 每次错误后短暂延迟，连续失败 10 次后进入更长间隔
- SEP 侧强制执行，攻击者不能通过外部高速通道爆破
- 但取证设备（Cellebrite 等）通过漏洞利用在设备上循环尝试，本质仍是"在线爆破"，只是速率高于用户手工
  - 对 4 位 PIN，Cellebrite 类设备可能在数小时至数天内完成
  - 对 6-8 位数字，成本上升
  - 对 12 位字母数字混合，实际上不可行

**极客建议：**

- **至少 8 位字母数字混合密码**
- 使用不易被 shoulder-surf 的字符（避免简单序列、生日、常见单词）
- 高威胁模型可考虑"自定义长口令"（12+ 位）

### 6.2 Face ID/Touch ID 的角色与限制

**关键设计：**

- 生物识别**不直接加密数据**
- 匹配成功后，Secure Enclave **释放** Class Key 到内存
- 生物特征模板存储在 SEP 内部，主系统不可读取

**攻击面：**

1. **胁迫解锁**：法律上多数法域可强制要求提供密码；Face ID 在部分司法辖区被认定为"物理特征"，宪法保护程度不同
2. **双胞胎/近亲**：Face ID 对同卵双胞胎有过记录，概率较低但存在
3. **注意力检测（Require Attention）**：默认开启，防止闭眼/被无意识解锁
4. **面具/照片**：现代 Face ID 使用 30,000+ 点红外结构光，几乎不可能被普通面具绕过；低成本硅胶面具偶尔成功
5. **医疗/麻醉/睡眠状态**：可能被动解锁，需要"注意力检测"开启

**防线建议：**

- **Require Attention for Face ID 保持开启**（默认）
- 高威胁场景下**关闭 "Side Button 双击解锁"或"允许在解锁前语音唤醒 Siri"**
- 需要快速禁用生物识别：侧边按钮 + 音量按钮**同时长按** → 触发 SOS 页，同时禁用生物识别直到重新输入密码

### 6.3 锁屏可访问项与关闭建议

锁屏状态下 iOS 允许一些功能"无需解锁"运行，每一个都是潜在攻击面：

**必审项目：**

| 项目 | 位置 | 高威胁建议 |
|------|------|-----------|
| 通知内容 | 设置 > 通知 | 关闭 "显示预览"（锁屏不显示） |
| 控制中心 | 设置 > 面容 ID 与密码 | 关闭锁屏访问（尤其 USB 配件、HomeKit） |
| Siri 访问 | 设置 > 面容 ID 与密码 > Siri | 关闭 |
| 回复消息 | 设置 > 通知 | 关闭 |
| 密码自动填充 | 设置 > 通用 > 面容 ID 与密码 | 关闭"解锁后自动填充" |
| 今天视图 | 设置 > 面容 ID 与密码 | 关闭 |
| 钱包 | 设置 > 面容 ID 与密码 | 视场景关闭 |
| USB 配件 | 设置 > 面容 ID 与密码 > USB 限制 | **保留开启**（重要） |
| 快捷按钮 | 设置 > 快捷按钮 | 避免映射到锁屏可达功能 |
| Home 键 | 视机型 | 关闭锁屏访问 |

### 6.4 USB Accessories Lock

**USB Restricted Mode（USB 限制模式）：**

- iOS 11.4.1+ 引入
- 设备锁定 1 小时后，Lightning/USB-C 端只接受充电，不接受数据
- 需要密码解锁后才能连接电脑
- **例外**：MFi 认证配件可以"唤醒"数据（历史上这是缺陷，Apple 逐步收紧）

**极客建议：**

- 高价值设备始终锁定
- 谨慎使用非 MFi 车充、公共充电站
- 特别警惕"充电劫持"配件（如 O.MG Cable、Wi-Fi Rubber Ducky 变体）

### 6.5 反胁迫与 Panic 机制

**Apple 内置机制：**

- **五连按侧边按钮**：紧急 SOS + 关机（在设置中可配置）
- **禁用生物识别**：SOS 页触发时会要求密码
- **抹掉数据**：连续失败 10 次密码（可选设置）
- **Stolen Device Protection（iOS 17.3+）**：远离常去地点时，密码修改、Apple Pay 卡片操作、iCloud 数据访问需要生物识别

**第三方方案（需谨慎）：**

- **自动化触发抹掉**（快捷指令 + 隐藏触发）
- **NFC 标签触发**：贴于隐蔽处，特定顺序扫描执行敏感操作（如关闭网络、执行"假密码"抹掉）
- **假密码**：iOS 本身不支持假密码，但可以在设置中启用"抹掉数据"，配合欺骗性密码
- **限制**：这些机制的可靠性和法律风险需谨慎评估

**极客注意**：任何"紧急擦除"方案在真正紧急时未必生效——iOS 抹掉数据本身需要用户认证或走 MDM 通道。最可靠的做法是"永远假定设备已被物理控制"，因此**敏感数据不落盘**（不存本地，只在端到端加密的服务端，或仅在需要时临时解密）。

### 6.6 Recovery Lock 与 Activation Lock

**Recovery Lock（iOS 18 引入）：**

- 进入恢复模式需要 Face ID / 密码 + Apple ID
- 阻挡攻击者通过恢复模式重置设备绕过锁屏
- 开启：设置 > 通用 > 传输或还原 iPhone > 恢复模式锁定

**Activation Lock（激活锁）：**

- 与 iCloud 绑定，重置后仍需 Apple ID
- 防盗窃，不防数据提取
- 高价值设备**必须开启"查找"**

**Apple ID 安全码 / Stolen Device Protection：**

- 在陌生位置执行敏感操作时要求生物识别（不能仅密码）
- 有效对抗"偷窥密码 + 短暂失手"

### 6.7 生物特征的法律与实际操作考量

**法律层面：**

- 多国判例区分"身体证据"（可强制）与"知识证据"（受第五修正案/沉默权保护，美国）
- 密码属于"知识"，Face ID 属于"身体"
- 因此从法律角度，仅使用生物识别在部分场景更脆弱
- 中国、欧盟等法域不同，需按当地法律评估

**实操建议：**

- 高威胁场景下**只用密码作为主解锁方式**，Face ID 作为便利手段
- 进入边境、抗议、集会前，主动**长按侧边+音量键**关闭生物识别
- 关机进入不可信区域，只留强密码

### 6.8 设备访问配置清单

- 至少 8 位混合密码
- Face ID 注意力检测开启
- 关闭锁屏 Siri / 通知内容 / 控制中心 / USB 配件
- 保持 USB Restricted Mode 开启
- 启用 Recovery Lock
- 启用 Stolen Device Protection
- 开启"抹掉数据"（10 次失败）——评估误触发风险
- 训练自己使用侧边+音量按钮快速禁用生物识别
- 高威胁场景：仅使用密码，物理隔离 Face ID

---

## 7. 通信安全防线：消息、通话与元数据

### 7.1 iMessage 安全模型

iMessage 是 iOS 生态最核心的即时通信工具，也是**零点击攻击的经典入口**。

**协议要点：**

- 端到端加密（Apple 自有协议，未开源）
- 密钥通过 Apple ID / 电话号码关联到 Apple 服务器（PKI 目录）
- 消息路由通过 Apple Push Notification service (APNs)
- 附件通过 Media Attachment Service 中转
- 支持"删除所有人""撤销发送""过滤未知发送者"

**信任模型问题：**

1. **Apple 服务器可访问元数据**：谁给谁发、时间、消息大小、附件类型
2. **密钥透明目录由 Apple 控制**：不像 Signal 的 E2EE + Safety Number，Apple 没有独立的密钥指纹验证机制
3. **备份**：iCloud 备份中的 iMessage 历史默认非 ADP 覆盖范围（因为需要服务端功能），但**开启 ADP 后变为端到端**
4. **零点击面**：历史上多个 CVE 出现在图片解码、PDF、URL 预览路径

**加固：**

- **Filter Unknown Senders 开启**（设置 > 信息 > 未知与过滤信息）
- **关闭 Lock Screen 通知内容预览**
- **禁用"文本消息转发给非苹果设备"中的 SMS/MMS 附件预览**（无法完全禁用，需依赖 iOS 更新）
- **锁定模式默认禁用**部分 iMessage 附件的复杂解析
- **谨慎接受未知号码的媒体附件**

### 7.2 APNs 与推送元数据

**Apple Push Notification service 是所有 Apple 通信服务的骨干**：

- 设备通过长连接 HTTP/2 与 APNs 保持在线
- 每个 App 的推送通过 APNs 中转
- Apple 服务器知道"某设备正在接收来自某 App 的推送"

**隐私意义：**

- Apple 可推断使用模式：什么时间收到通知、通知频率、发送方 App
- APNs 载荷本身端到端加密（自 iOS 16 起 TLS 保护，Apple 只看到目标 token 和 topic）
- Topic 与 bundle ID 关联，仍可映射到 App

**加固建议：**

- 关闭不必要 App 的通知权限（减少元数据信号）
- 敏感 App 使用"隐藏通知"策略

### 7.3 传统 SMS/MMS 风险

SMS 明文传输，依赖 SS7/Diameter 网络。这些协议有几十年历史，攻击手段成熟：

**已知攻击：**

1. **SS7 定位**：任何 SS7 网络接入者可查询设备位置
2. **SMS 拦截**：通过 SS7 或 SIM swap 拦截 OTP
3. **Pegasus 变体**：某些厂商通过 SS7 触发 iMessage 载荷到达
4. **SimJacker**：向 SIM 卡发送特殊 OTA 二进制命令，在部分旧 SIM 上可植入后门

**极客建议：**

- **不再使用 SMS 作为二次验证因子**（改用 TOTP、硬件密钥、Passkeys）
- 敏感服务通过 SIM PIN（PIN1/PIN2）加锁，防止换机读取
- 与运营商协商**关闭 SIM swap 远程通道**（只允许线下 + 二次验证）
- **eSIM 优势**：更难物理拔取，但换机远程仍可能发生
- 关闭"文本转发到 Mac/iPad"，减少多设备暴露

### 7.4 FaceTime 与实时通话

**协议：**

- 端到端加密（DTLS-SRTP）
- 建立通话密钥时通过 Apple 服务器
- 元数据（通话方、时间、时长）Apple 可见

**加固：**

- 仅在设备解锁状态下允许接听（避免锁屏时音频被录音）
- 关闭"从其他设备接听 FaceTime"
- 高威胁场景不使用 FaceTime（Apple 服务器可见元数据），改用 Signal / Session / Briar 类工具
- **Group FaceTime**：Apple 官方声明端到端加密，但密钥协商经过 Apple 服务器

### 7.5 Signal 与第三方 E2EE

**Signal 相较 iMessage 的优势：**

- **开源协议（Double Ratchet + X3DH）**，学术界公开审计
- **元数据最小**：Sealed Sender 让 Signal 服务器不知道发送方
- **密钥验证**：Safety Number 可人工核对
- **不依赖手机号**（自 2024 年起支持用户名）

**Signal 的弱点：**

- 元数据（何时上线、注册电话号码）仍部分留存
- 云端注册依赖电话号，可能被 SIM swap 攻击

**极客选择建议：**

- **敏感通信优先 Signal**（或 Session, Berty, Briar）
- **iMessage 用于日常便利**
- 两者共存，按对话敏感度分流

### 7.6 元数据（Metadata）防线

元数据泄露常被低估。你的电话记录、时间、频率、联系人往往比内容更 revealing。

**关键元数据来源：**

| 来源 | 内容 | 控制手段 |
|------|------|---------|
| 电信运营商 | 通话/短信/流量基站 | 无法完全规避，可通过预付费 SIM |
| Apple（iCloud、iMessage、APNs） | 通信对象、时间、附件类型 | 减少依赖、启用 ADP |
| App 本身 | 使用模式、位置、联系人 | 权限最小化 |
| 相机 EXIF / 文件元数据 | GPS、设备、时间 | 发送前剥离 |
| Wi-Fi 探针 | MAC 地址、连接历史 | 私有 MAC 地址 |
| 蓝牙 | 附近设备 | 不使用时关闭 |
| NFC / 交通卡 | 位置与出行 | 不主动使用非必需 |

**加固：**

- 关闭**分享我的位置**（除非有具体用途）
- **图片发送前用 iOS 自带的"选项"关闭位置、All Data**
- 高威胁目标考虑** burner iPhone + 现金预付 SIM**
- 定期审计 App 权限
- 谨慎使用共享日历/家庭

### 7.7 通信防线配置清单

- 关闭 SMS 作为 2FA，改用 TOTP/硬件密钥/passkey
- 启用 iMessage 未知发送者过滤
- 锁屏不显示消息内容
- 敏感对话迁至 Signal / Session
- 关闭"分享位置"到不必要联系人
- 定期审计已登录设备（Apple ID）
- 相机/图片默认剥离位置与设备信息
- 高威胁场景：一次性设备 + 一次性号码

---

## 8. 网络层防线：DNS、VPN、中继与链路

### 8.1 传输层安全（TLS）与证书透明度

iOS 全局强制 **App Transport Security (ATS)**：所有网络流量默认 HTTPS。

**TLS 实现细节：**

- Network.framework 与 URLSession
- 支持 TLS 1.3（默认优先）
- BoringSSL（源自 OpenSSL，但独立分支）
- 证书必须使用 SHA-256 签名
- 强制 forward secrecy（PFS）在 TLS 1.3 下

**证书固定（Certificate Pinning）：**

- 通过 URLSession 的 delegate 或 Network.framework 的 trust 对象实现
- 应用可以只信任已知证书/公钥
- 关键 App（密码管理器、Signal）都实现了 pinning

**极客注意：**

- **本地 HTTPS 中间人（如 Charles、mitmproxy）**依赖用户安装根证书
- 高威胁用户**定期审计已安装的描述文件和根证书**：设置 > 通用 > 关于 > 证书信任设置
- 越狱设备可能允许非标准证书注入

### 8.2 加密 DNS（DoH / DoT）

iOS 14+ 支持 **DNS over HTTPS / DNS over TLS**：

**启用方式：**

- 通过描述文件（如 iCloud Private Relay 内置）
- 通过支持 DoH 的 VPN Profile
- 通过配置文件（如 `https://dns.quad9.net/dns-query`）

**攻击现实：**

- 未使用加密 DNS 时，ISP/中间网络可看到所有域名查询
- 现代攻击者可对 DNS 应答注入，实现钓鱼、CDN 劫持
- 企业网络可能强制内网 DNS，绕过 Private Relay

**加固：**

- 优先方案：**iCloud Private Relay**（双中继，同时保护 DNS 与 IP）
- 备选：可信 DoH 提供商（Quad9、Cloudflare、Mullvad DNS）
- 敏感场景：全程 WireGuard/OpenVPN 隧道

### 8.3 iCloud Private Relay

**架构（隐私设计的核心）：**

```
Device ──[加密层 1]── Apple Ingress ──[加密层 2]── 第三方 Relay (Fastly) ── 目标服务器
```

- Apple 知道你的 IP，但通过 TLS 1.3 + 双层加密看不到目标域名
- Fastly 知道目标域名，但只看到 Apple 内部 IP，不知道你是谁
- **任何一方无法同时看到"谁访问哪里"**

**限制：**

- 只保护 Safari 和部分 AppKit/Network 流量
- 不覆盖 UDP/QUIC 某些场景
- 企业网络可能屏蔽（443 端口非标准域名被防火墙阻断）
- 与某些需要地理定位的站点冲突（要求区域 IP 服务）

**极客评估：**

- **优点**：默认协议下比传统 VPN 更少的信任假设
- **缺点**：DNS 查询元数据仍在 Apple 一侧可推断（时间、频率），且是中心化架构
- **组合使用**：Private Relay 与 Mullvad/IVPN 类严格无日志 VPN 分别覆盖不同威胁

### 8.4 VPN 与网络扩展

iOS 允许第三方实现 **Network Extension**（NEPacketTunnelProvider / NEAppProxyProvider）：

**常见用途：**

- WireGuard, NordVPN, Proton, Mullvad 等
- 企业 VPN（Cisco AnyConnect, GlobalProtect, Pulse）
- 广告拦截（AdGuard DNS Profile 而非 VPN）

**安全考虑：**

- **企业 VPN 描述文件**：可能捕获所有流量、执行证书中间人
- 高威胁用户**避免安装企业 VPN**除非必要
- 检查已安装描述文件：设置 > 通用 > VPN 与设备管理

**WireGuard 特别提示：**

- 开源、密码学审计良好
- iOS WireGuard App 密钥保存在本地，服务器日志取决于配置
- 自建 WireGuard 是极客常见选择

### 8.5 Wi-Fi 隐私与安全

**MAC 地址随机化：**

- iOS 8+ 引入私有 Wi-Fi 地址
- 每个 SSID 使用不同随机 MAC
- 攻击者难以通过 Wi-Fi 探针跨网络跟踪设备

**加固：**

- 每个网络单独"专用 Wi-Fi 地址"开关（默认开启）
- 关闭"询问是否加入热点"（避免自动暴露 SSID 探测）
- 关闭"WLAN 自动加入已知网络"，敏感场景避免误连 Evil Twin

**已知攻击：**

- **FragAttacks**：802.11 帧聚合/分片处理缺陷，iOS 受影响面较小
- **KRACK**：WPA2 密钥重装攻击，现代 iOS 已修补
- **WPA3 SAE 降级**：仍存在部分场景
- **Evil Twin + Captive Portal**：钓鱼常用，用户应核对网络名与登录页

### 8.6 蜂窝网络与 IMSI

**风险层次：**

- **伪基站（Stingray/IMSI catcher）**：强制设备降级到 2G 或伪造 4G 网络
- **SS7/Diameter 攻击**：跨越运营商核心网的漏洞
- **被动定位**：任何时刻基站都能定位（约几百米精度）

**iOS 侧防御：**

- iOS 16+ 支持在开发者模式下关闭 2G
- 现代基带固件拒绝无认证 2G 回落（取决于运营商）
- **Airplane Mode** 是最可靠的手段
- 敏感场景使用**屏蔽袋（Faraday bag）**

**极客进阶：**

- 高威胁用户考虑使用**Tor 走蜂窝网络**（需 Orbot 类应用，或 OnionCat over VPN）
- 定期更换 eSIM/预付费号码
- 关注基带 CVE：历史上基带漏洞（如齐港联发科基带、Intel XMM）曾出现远程利用

### 8.7 蓝牙与近场

**风险：**

- **BlueBorne（2017）**：跨设备蓝牙栈漏洞，无需配对
- **AirDrop 隐私**：历史版本可能广播设备名
- **BLE 追踪**：可穿戴、Find My 网络配件可能被利用

**加固：**

- 敏感环境关闭蓝牙
- AirDrop 设为"仅联系人"或"接收关闭"（默认 10 分钟后关闭接收）
- 关注 AirDrop 攻击面：Citizen Lab 曾报告通过 AirDrop 传播间谍软件的历史案例（如 CVE 已修）

### 8.8 网络层配置清单

- 优先 HTTPS-only 网络
- 定期审计已安装的描述文件与根证书
- 使用 Private Relay 或严格无日志 VPN
- 关闭 2G 回落（如支持）
- Wi-Fi 每个 SSID 使用私有 MAC
- 敏感场景使用飞行模式 + 屏蔽袋
- 高威胁用户自建 WireGuard 或 Onion 路由
- 蓝牙/AirDrop 默认关闭

---

## 9. 应用与供应链防线

### 9.1 App Store 审核机制与信任模型

**审核流程：**

- 每个提交由自动化 + 人工审核
- 检查：恶意行为、隐私合规、内容、安全、功能
- 开发者身份验证（DUNS、组织身份）

**审核局限：**

- 审核关注"策略合规"，不保证"没有漏洞"
- 历史案例：XcodeGhost（2015）——被污染的 Xcode 生成的合规二进制绕过静态审核
- DarkSword（2025）——通过合规 App 引导用户下载 Web 恶意载荷
- **企业签名 + MDM 滥用**：绕过 App Store 的路径仍存在

**信任要点：**

- App 上架不等于安全
- 权限声明（Privacy Manifest, iOS 17+）是数据收集透明度的开始

### 9.2 侧载（Sideloading）与替代商店

**iOS 17+ 在欧盟**（DMA 法规下）：

- 支持 **Alternative App Marketplaces**
- 支持 Web Distribution（浏览器直接下载）
- Entitlement 需 Apple 审核

**风险：**

- 恶意市场可分发被篡改的 App
- Web Distribution 缺乏完整审核
- **极客建议**：只从自己搭建或高度信任的来源侧载

**AltStore / SideStore：**

- 使用个人 Apple ID 免费签名
- 7 天有效期，需要定期续期
- 是合法的开发者侧载方式
- 注意：**AltStore 的 AltServer 需要 macOS 或 Windows 助手，攻击者可能利用助手通道**

**越狱（Jailbreak）：**

- 完全放弃 Apple 的运行时防线
- 破坏 SSV 完整性检测（依赖运行时 hook）
- 引入大量第三方 tweak 攻击面
- **强烈不推荐**高价值目标越狱

### 9.3 企业签名与描述文件

**企业证书（Apple Developer Enterprise Program, ADEP）：**

- 允许企业内部分发未上架 App
- 历史上被大规模滥用（盗版 App 分发）
- 2019 起 Apple 收紧，吊销多个滥用证书

**MDM 描述文件：**

- 允许企业远程管理设备
- **可安装根 CA → 强制 HTTPS 中间人**
- **可强制 VPN → 全流量路由到企业网络**
- **可远程锁定/擦除**

**极客警觉：**

- 免费 Wi-Fi、充电服务、"开发者测试"等场景索要安装描述文件是红旗
- 定期查看：设置 > 通用 > VPN 与设备管理 > 配置描述文件
- 卸载可疑 MDM 需要密码，若已丢失控制权需要重置设备

### 9.4 应用权限最小化

**iOS 权限模型（详见第 10 章）：**

- 位置：仅使用时/一次/始终
- 照片：完全/有限/无
- 麦克风/相机：仅询问
- 通讯录：授权/拒绝
- 健康：细粒度
- 蓝牙、本地网络、日历、提醒、HomeKit 等

**关键审计：**

- 设置 > 隐私与安全性：分类查看
- 每周或每月审查一次"上次访问日期"

### 9.5 App Intents 与跨应用数据流

App Intents 让快捷指令调用第三方功能，跨应用数据流动：

**风险：**

- 恶意 App 通过 Intent 请求大量数据
- 自动化触发导致隐蔽数据外发

**建议：**

- 只安装来自可信来源的快捷指令
- 审查自动化触发条件（详见 iOS 快捷指令与自动化隐私报告）
- 敏感 App 不参与快捷指令

### 9.6 供应链攻击案例与教训

**历史案例：**

1. **XcodeGhost（2015）**：中国开发者从镜像下载被污染 Xcode，产出带后门的合法签名 App， infect 微信、滴滴、网易云音乐等
2. **DarkSword（2025）**：攻击者通过合规 App 引导用户下载恶意描述文件或 Web 载荷，实施钓鱼与监控
3. **Coruna（2024-25）**：泄露的 NSO 工具链，包含多个 CVE 利用，通过 WebKit 链攻击
4. **Triangulation（2023）**：RTKit/Boot ROM 攻击链，跨设备持久化
5. **ShadowPawn（2024）**：通过 Apple 更新推送污染攻击面

**教训：**

- 只从官方渠道下载开发工具（Xcode、CocoaPods、SDK）
- 校验 SHA-256 与签名
- 定期审计已安装描述文件
- 保持 iOS 最新

### 9.7 应用层配置清单

- 只从 App Store 安装，除非明确理解侧载风险
- 敏感场景拒绝 MDM 描述文件
- 每月审查已安装 App 与权限
- 卸载不用的 App（减少内核暴露面）
- 不使用来源不明的快捷指令、描述文件
- 开发者：只使用官方/校验过的工具链

---

## 10. 浏览器与 Web 内容防线

### 10.1 WebKit 在 iOS 中的地位

iOS 上 Safari 与所有 Web View 都基于 **WebKit**（iOS 17.4+ 在欧盟允许替代引擎如 Blink，但需 Web Content Engine 授权）。

**架构：**

```
┌─────────────────────────────────────┐
│  Safari App / WKWebView (主进程)     │
├─────────────────────────────────────┤
│  WebContent (渲染进程，沙盒)          │
├─────────────────────────────────────┤
│  Networking (进程)                  │
├─────────────────────────────────────┤
│  GPU Process                        │
└─────────────────────────────────────┘
```

**Multi-process**：iOS 15+ 完全多进程，一个标签崩溃不影响其他；沙盒分离渲染。

### 10.2 关键攻击面

1. **JavaScriptCore（JSC）**：JS 引擎，历史漏洞多（Pegasus 曾利用 JSC 类型混淆）
2. **BlastReduce / 图像解码器**：JPEG XL、HEIC、PDF
3. **字体渲染（CoreText / libFontParser）**：FORCEDENTRY 是字体解析
4. **媒体处理**：WebCodecs、Media Source Extensions
5. **GPU 命令队列**：Metal 相关
6. **IndexedDB、WebSQL 遗留**

**极客防线：**

- **锁定模式默认禁用 JIT**：显著削弱 JSC 内存破坏可利用性
- **拒绝未知消息中的媒体自动下载**
- **谨慎访问水坑网站**：记者、活动人士目标最集中

### 10.3 Safari 隐私特性

**内置功能：**

- **ITP (Intelligent Tracking Prevention)**：阻止第三方 Cookie、限制跨站追踪
- **Privacy Report**：显示被阻止的追踪器数量
- **Hide My Email**：随机邮件别名
- **Fingerprint Resistance**：标准化 canvas、字体、屏幕信息
- **Private Browsing with Face ID**：无痕窗口需生物识别
- **Advanced Fraud Protection**（iOS 17.4+）：抵抗欺诈登录页面
- **Jailbreak detection for web content**（间接）：锁定模式默认关闭高级 JS

**设置建议：**

- 追踪防制：全部开启
- 屏蔽所有 Cookie：可选（影响可用性）
- 隐私报告定期查看
- JavaScript：默认开启，敏感场景可考虑关闭（牺牲可用性）
- 下载：不自动打开
- 摄像头/麦克风权限：默认询问，定期审计

### 10.4 WebKit 漏洞链的现实

**典型链条：**

```
1. 用户访问被入侵的网页（水坑 / 恶意广告 / 短信链接）
        ↓
2. 触发 JSC 类型混淆 / WebAssembly 漏洞 / 图像解析缺陷
        ↓
3. 沙盒内任意读写 (Arbitrary R/W in WebContent)
        ↓
4. 绕过 PAC → 控制流劫持
        ↓
5. 沙盒逃逸 (mach 端口滥用 / IOKit 漏洞)
        ↓
6. 内核提权 (SPTM/TXM 前的 KPP 绕过 或 现代页表漏洞)
        ↓
7. 安装间谍软件，抹除日志
```

**每个漏洞的"黑市价值"（据媒体与研究者披露）：**

- 高质量 WebKit 零点击：$1M+
- 完整 iOS 链：$2-10M
- 一次性链（单点提权）：$100K-$500K

### 10.5 浏览器防线配置清单

- 只使用 Safari（不使用伪装"安全浏览器"的第三方 App）
- 保持 WebKit 更新（等同 iOS 更新）
- 敏感场景启用**锁定模式**（默认限制 JIT 与部分媒体解析）
- 关闭"从其他设备 Safari"（避免链式暴露）
- 定期查看网站权限（摄像头/麦克风/位置）
- 不点击短信/邮件中的链接（尤其图片消息）
- 敏感场景使用**独立浏览器 App + 无痕模式**，避免与 iCloud 同步
- 高威胁：iCloud 邮箱 + 独立 WebKit 视图，不与主设备关联

---

## 11. 间谍软件与零点击攻击防线

### 11.1 商业间谍软件生态

**主要玩家：**

- **NSO Group**（以色列，Pegasus）
- **Cytrox**（希腊/北马其顿，Predator）
- **QuaDream**（法国，Helios）
- **Intellexa**（Cobalt Sparrow）
- **Variston**（Vipersphing，历史）
- **KismetData / Cellwiz**
- **Positive Tech**（俄罗斯，RCES）
- **Cyberspy**（意大利，WithSelect）
- **Reserved Labs / Danguo**（中国，历史）

**共同特征：**

- 面向政府客户销售
- 声称"仅用于反恐/刑侦"
- 实际客户涵盖威权政体、记者目标、异见人士
- 售价从 $10 万/年到 $1000 万/年
- 单目标部署成本可达数十万至百万美元

### 11.2 零点击（Zero-Click）与 One-Click

**One-Click：**

- 需要用户点击链接或附件
- 水坑攻击、恶意广告、短信诱导
- 是绝大多数实际使用的模式

**Zero-Click：**

- 无需用户交互
- 通过 iMessage 附件、推送通知、系统服务解析
- 极昂贵，通常只针对最有价值的目标
- 已知实例：Pegasus 的 Karma（Karma 404）、FORCEDENTRY、KISMETDATA 案例、部分 Predator 攻击

### 11.3 攻击链解剖：以 FORCEDENTRY 为例

**背景：**

- 2021 年 8 月，Citizen Lab 观察到针对加拿大律师与活动人士的 NSO 攻击
- 通过 iMessage 发送一个特制 GIF（实际内嵌 PDF）
- 目标**无需点击**即可失陷
- 使用了 CVE-2021-30860（CoreGraphics font parsing, ATSPath）

**流程：**

1. 攻击者向目标 iMessage 发送 GIF 附件（实际是含 Type 1 字体攻击载荷的 PDF）
2. iOS 后台预览服务（如 IMDServer）在锁屏状态下解析该 PDF
3. 字体解析路径中的整数溢出导致内存破坏
4. 破坏被利用来获取任意读写
5. 结合未修补内核漏洞提权
6. 部署 payload，修改通知记录，抹除证据

**极客防线：**

- Apple 在 CVE 披露后 12 小时内发布紧急补丁（iOS 14.8 于 2021-09-13 发布）
- **未更新设备是最大风险**
- 锁定模式（iOS 16 引入）默认限制部分预览路径

### 11.4 攻击链解剖：Coruna（2024）

**背景：**

- 2024 年 3 月，Citizen Lab 与 Lookout 联合披露
- 通过**合规的 iOS App** 与网页联动实施定向攻击
- 使用了 iOS WebKit + GPU + 内核多组漏洞
- 覆盖 iOS 16.6.1 ~ 17.0（当时最新）
- 目标：阿联酋相关记者、外交人员

**特点：**

- **Coruna 不是间谍软件本身**，是"漏洞利用投递器"
- 载荷最终部署第三方监控框架（如 FinSpy 类）
- 强调"低置信度、高覆盖"（相比 Pegasus）
- 泄露的工具包被多个 smaller 厂商使用

**极客防线：**

- Apple 于 iOS 17.4/17.5 修补主要 CVE
- **Coruna 攻击链的公开泄露**意味着未来会出现更廉价的类似攻击
- 保持更新是首要

### 11.5 攻击链解剖：Triangulation（2023）

**背景：**

- Kaspersky 与 Citizen Lab 联合分析
- 使用了 **RTKit 图像解码器漏洞 + Boot ROM 隐藏持久化**
- 首次观察到通过 **Apple 更新机制植入 bootkit**
- 目标跨越多个国家，通过充电配件（"恶意充电器"）传播

**独特之处：**

- 攻击代码存储在 Boot ROM 之外的 iBoot 变量区
- 重启后仍保留（persistence）
- 利用合法 Apple 更新过程植入
- **首个公开的固件级持久化 iOS 攻击**

**极客防线：**

- 只使用原装或认证充电配件
- 不在陌生环境长时间接入未知 USB 电源
- 定期查看 iOS 版本、启动状态、恢复模式表现

### 11.6 检测手段

**Apple 官方：**

- **Security Research Devices**：Apple 向认证研究者提供特殊设备用于分析
- **STF (State Warning API)**：iOS 16.4+，App 可订阅国家支持攻击警报
- **Apple 邮件通知**：若识别到针对性攻击，Apple 通过安全邮箱通知用户
- **锁定模式（Lockdown Mode）**：既是预防，也是"公开承认自己是目标"的信号

**第三方检测工具：**

- **MVT (Mobile Verification Toolkit)**：Citizen Lab 开源，用于分析备份或 sysdiagnose
  - 检查指标：可疑配置文件、可疑进程、异常持久化、已知 IOC
  - 需要 macOS/Linux 电脑 + 备份提取
- **iLEAPP / ALEAPP**：Alexis Brignoni 开发的日志提取工具
- **mvt-ios** 命令示例：
  ```
  mvt-ios check_backup --backup-path <itunes_backup_path>
  mvt-ios check_sysdiagnose --sysdiagnose <path>
  ```
- **Mosyle Monitor / Kandji**：企业 MDM 附加安全审计

**局限：**

- MVT 依赖已知 IOC，对**新 0-day 与未知 IOC 无效**
- 端对端加密 + 时间戳篡改使攻击者不留痕迹
- 建议**结合行为异常**判断：
  - 电池消耗异常
  - 数据使用量异常
  - 设备发热（后台工作）
  - 摄像头/麦克风指示点偶现
  - 网络流量出现"心跳式"周期性外发

### 11.7 疑似失陷的应急响应

**步骤：**

1. **不要立即关机**：断电会丢失内存证据（虽然现代 iOS 内存难以提取）
2. **进入飞行模式**：阻断 C2 通信
3. **备份 sysdiagnose**：长按电源+音量（视机型），或设置中触发
4. **联系可信研究者或 Apple**：
   - security@apple.com
   - Citizen Lab：research@citizenlab.ca
   - Access Now 数字安全热线
5. **转移敏感账户**（用另一台设备）：改密码、注销设备
6. **不要修复**：在证据提取前不要重装或抹掉
7. **必要时物理隔离**：屏蔽袋中保存设备

### 11.8 间谍软件防线配置清单

- **保持最新版本**（CVE 修补窗口最小）
- 高威胁目标**主动开启锁定模式**
- **每月运行 MVT 分析 sysdiagnose 或备份**
- 关注 Apple Security Updates 公告与 Citizen Lab 报告
- 敏感通信迁至非 Apple 平台（Signal / Session）
- 拒绝未知来源附件（iMessage、邮件、WhatsApp）
- 使用硬件安全密钥（YubiKey）保护 Apple ID

---

## 12. 物理取证与现场防线

### 12.1 取证设备：Cellebrite 与 GrayKey

**Cellebrite UFED/Physical Extractor：**

- 以色列厂商，被执法机关广泛采购
- 支持从 iPhone 提取完整文件系统（若已解锁或密码可爆破）
- 通过 0-day/1-day 漏洞 + 高速自动化尝试密码
- 官方"平均破解时间"针对数字密码给出参考：4 位 PIN 数分钟，6 位数天到数周

**GrayKey（Grayshift）：**

- 美国厂商，主打执法级破解
- 通过 USB 连接设备，在锁定界面利用漏洞循环尝试
- 支持 iOS 12-17（截至最新报告）
- 每次尝试 20 分钟冷却时间（Apple 与 GrayKey 谈判结果）
- 对长字母数字密码无效

**极客防线：**

- **强密码是唯一防御**：8 位以上字母数字混合让取证工具在合理时间内无解
- **快速锁定**：默认 30 秒自动锁屏，敏感场景改为"立即"
- **短按侧边按钮 + 音量键 = SOS 页 + 禁用生物识别**：进入不可信环境前主动执行

### 12.2 冷启动攻击与内存保护

**冷启动攻击（Cold Boot Attack）：**

- 早期设备（A9 之前）在关机后几十秒内内存内容仍可读
- 攻击者用压缩空气/异丙醇冷冻内存模块，读取后恢复密钥
- **现代 iOS（A10+）**：内存加密 + 快速断电保护，几乎不可行

**实际防御：**

- 高威胁场景：进入不可信环境前**关机**（不是睡眠）
- 敏感数据使用 **ThisDeviceOnly 类**：设备锁屏后立刻不可访问

### 12.3 短暂物理接触（"Grab-and-run"）威胁

**攻击模型：**

- 攻击者在数秒内拿到设备
- 目标：解锁读取消息、拍照、复制内容
- 或植入持久化 MDM 描述文件（越狱工具、快捷指令后门）

**防线：**

- 侧边按钮**立即锁屏**（电源按钮或超时）
- 关闭锁屏通知内容预览
- **短按电源+音量禁用生物识别**：训练条件反射
- **Stolen Device Protection** 防止陌生位置操作
- 不放置于易取处（会议桌上、口袋外置）

### 12.4 海关与边境检查

**现实威胁：**

- 部分国家要求旅客解锁手机，或"临时扣押"设备
- 拒绝可能面临遣返、拘留
- CBP（美国海关）历史上被报道使用取证工具批量扫描

**预案：**

- **旅行用一次性设备 + 一次性号码**：不含敏感数据
- **主设备留在家中**
- 无法留家时，敏感数据不落本地，需要时解密
- 关键账户启用硬件 2FA + 短会话超时
- 提前设置：清除剪贴板历史、关闭 iCloud 同步、锁定模式

### 12.5 设备丢失与远程处置

**"查找"（Find My）能力：**

- 定位（含离线状态通过 Find My 网络）
- 播放声音
- 标记丢失（锁屏消息）
- 远程抹除

**局限：**

- 需要设备有电且联网（Find My 网络允许离线定位，蓝牙广播）
- 抹除命令仅在设备联网后执行
- 攻击者拔出 SIM/关机可阻止大部分指令

**增强：**

- 高价值设备使用**内置 SIM + 常开数据**（Find My 更可靠）
- 关键服务通过 **MDM** 部署，允许强制远程命令
- 定期演练"丢失 → 抹除"流程

### 12.6 现场取证的法律与战术考量

**法律：**

- 部分国家可要求提供密码
- 生物识别保护程度弱于密码
- 美国判例：密码属于"testimonial"（受第五修正案保护）；Face ID 属于"physical"（较弱）

**战术：**

- 长时间被拘留：使用强密码 + 定期修改
- 短期接触：物理设备不离手
- 边境场景：一次性设备
- 高风险冲突地区：**假密码**（在支持抹掉数据的前提下），配合快速销毁

### 12.7 现场配置清单

- 强密码（≥10 位混合）
- 立即锁屏（30 秒或更短）
- 关闭锁屏可见内容
- Stolen Device Protection 开启
- 快速禁用生物识别训练
- 高威胁场景使用一次性设备
- 敏感数据不落本地

---

## 13. 极客工具箱：检测、取证、日志与监控

### 13.1 Sysdiagnose 采集与分析

**触发方式：**

- 长按：音量上 + 音量下 + 电源 约 1.5 秒（iPhone 8 及以后）
- 或设置 > 通用 > 关于 > 诊断（部分版本）

**内容：**

- 内核日志、系统日志
- launchd 状态
- 进程列表
- 网络配置、路由表
- 已安装描述文件
- Crash 与 spin 报告
- 电源事件
- 时间同步状态
- **注意**：sysdiagnose 不包含应用数据、消息内容等，主要是系统级诊断

**分析：**

- 用 **mvt** 或 **console.app/pspf** 类工具浏览
- 关注：异常进程、异常网络、异常描述文件、异常启动项、异常 kernel log

**基线策略：**

- 每月一次 sysdiagnose 存档
- 差分分析：新的可疑进程/服务/descriptor

### 13.2 Mobile Verification Toolkit（MVT）

**功能：**

- 解析 iTunes 备份或 sysdiagnose
- 匹配 IOC（Indicators of Compromise）
- 检测可疑域名、进程、描述文件、持久化机制

**使用：**

```
# 分析备份
mvt-ios check_backup --backup-path ./backup
# 分析 sysdiagnose
mvt-ios check_sysdiagnose --sysdiagnose ./sysdiagnose.tar.bz2
# 强制检测模式
mvt-ios check_backup --backup-path ./backup --check-model
```

**IOC 源：**

- **STIX 2.1 格式**
- MVT 社区提供默认 IOC 集合
- 各研究机构（Amnesty、Front Line Defenders）发布针对性 IOC

**局限：**

- 依赖已知 IOC
- 对**未部署或已抹除痕迹**的攻击无效
- **仅检测，不阻断**

### 13.3 iLEAPP / ALEAPP / BraveSearch

**Alexis Brignoni 生态：**

- **iLEAPP**：iOS Logs, Events, And Plist Parser
- **ALEAPP**：Android 对应版本
- **BraveSearch**：多工具联合搜索

**用途：**

- 快速解析备份中的 sqlite、plist、日志
- 提取网络请求历史、位置历史、App 活动
- 用于个人取证与事故复盘

### 13.4 网络流量监控

**方案：**

- **本地抓包**（mitmproxy + iOS 描述文件）：仅用于自己调试，高威胁时避免安装描述文件
- **上游路由器抓包**：Wireshark 在家庭网关上被动分析
- **Pi-hole / AdGuard Home**：DNS 层记录查询，识别可疑域名
- **Suricata / Zeek**：家庭 IDS，检测异常连接

**极客做法：**

- 家庭路由器上启用日志
- 定期审查 iPhone 访问过的域名
- 陌生 IP / 高频心跳 = 潜在 C2

### 13.5 电池/流量/后台异常

**低技术但高效：**

- 设置 > 电池：查看近期耗电异常的 App
- 设置 > 蜂窝网络：数据使用排行
- 设置 > 通用 > iPhone 储存空间：不认识的 App 或异常缓存

**攻击者特征：**

- 间谍软件为维持 C2 与数据回传，通常导致：
  - 电池比正常快 20-40% 消耗
  - 数据使用出现"心跳式"周期
  - 设备发热（后台 CPU）
  - 摄像头/麦克风指示点偶尔自亮
  - 服务/网络延迟异常

### 13.6 描述文件审计

**关键：**

设置 > 通用 > VPN 与设备管理

- 检查所有已安装 Profile
- 关注：根证书、VPN、MDM、Web Content Filter

**可疑特征：**

- 名称模糊（"Wi-Fi 证书"、"内部 CA"）
- 从免费 Wi-Fi、邮件、开发者工具安装
- 包含"根 CA"或"内容过滤器"

**处理：**

- 立即删除并重置设备
- 如已启用 HTTPS 中间人，假定流量已被监控

### 13.7 Apple 服务器端安全事件

**查询：**

- 访问 account.apple.com 检查已登录设备
- Apple 系统状态：https://www.apple.com/support/systemstatus/
- Apple 安全公告：https://support.apple.com/en-us/HT201222

**关键：**

- 若发现陌生设备：立即移除 + 改密码 + 检查备份
- 关注 Apple 邮件通知（"State-sponsored 攻击"警告）

### 13.8 极客工具箱清单

| 工具 | 用途 | 平台 |
|------|------|------|
| MVT | IOC 匹配 | macOS/Linux |
| iLEAPP | 备份解析 | macOS |
| Console.app | 实时日志 | macOS |
| Wireshark | 网络分析 | 全平台 |
| Pi-hole | DNS 观测 | Raspberry Pi |
| Bitwarden/Passkeys | 密码 | 全平台 |
| YubiKey | 硬件 2FA | 硬件 |
| Faraday Bag | 隔离 | 硬件 |
| Mullvad / WireGuard | VPN | 全平台 |
| Signal / Session | E2EE 通信 | 全平台 |
| Apple Configurator | 设备审计 | macOS |

---

## 14. 账户、iCloud 与跨设备防线

### 14.1 Apple ID：整个安全模型的中心

**Apple ID 是几乎所有 Apple 服务的信任根：**

- 数据同步
- 设备查找与远程擦除
- App 购买与订阅
- iMessage 路由
- FaceTime、Siri、Apple Pay
- 备份与恢复

**攻击 Apple ID 的动机：**

- 直接获取 iCloud 备份（含历史消息、照片）
- 关闭"查找"以让 stolen iPhone 可解锁使用
- 通过 ADP 之前的账户恢复绕过端对端保护
- 定位用户、修改设备配置

### 14.2 Apple ID 攻击案例

**历史事件：**

1. **2012 Mat Honan 事件**：通过 Amazon 客服 + Apple 客服社会工程重置 Apple ID，远程抹掉设备
2. **2014 iCloud 裸照泄露（"The Fappening"）**：安全问题答案 + 邮件账户失陷
3. **近年 iForgot 钓鱼**：伪装 Apple 邮件诱导输入凭证
4. **SIM swap + SMS 2FA**：绕过弱二次验证

**教训：**

- **安全问题**已废弃，改为 2FA
- **SMS 2FA 应完全弃用**，改用 TOTP / 硬件密钥
- **恢复联系人**需谨慎：任何一位联系人的账户失陷都可能被利用

### 14.3 双因子与硬件密钥

**Apple 支持的 2FA 因子：**

- 受信设备推送（默认）
- SMS 验证码（**不推荐**）
- TOTP（在密码管理器中）
- 硬件安全密钥（YubiKey 5, SoloKeys, Feitian）通过 NFC/蓝牙/USB 使用

**推荐组合：**

- 主因子：硬件密钥
- 备用因子：另一枚硬件密钥（不同型号，异地存放）
- 恢复方式：**28 字符恢复密钥**，纸质/金属
- 可选：恢复联系人（严格筛选）

### 14.4 Stolen Device Protection

**iOS 17.3+ 引入：**

- 在非常驻地点时，敏感操作需生物识别（不允许密码回退）
- 包括：修改密码、添加/移除设备、查看 iCloud 数据、Apple Cash、Safari 密码

**极客建议：**

- 强制开启
- 与强密码组合，构成"知识 + 生物 + 位置"三因子

### 14.5 家庭共享与儿童账户

**风险：**

- 家庭成员可发起购买、访问共享日历、位置
- 儿童账户可能被社会工程利用（伪装"家长"请求）

**建议：**

- 家庭组只加入完全信任的成员
- 儿童设备通过 MDM 管理
- 关闭不必要的家庭共享（照片流、位置）

### 14.6 跨设备信任关系

**Apple 设备通过 iCloud + Continuity 建立信任：**

- Handoff：设备间任务传递
- 通用控制：Mac 直接控制 iPad
- 侧载 App（Mac 上运行 iPad 应用）
- iCloud Keychain：密码跨设备

**极客关注：**

- 每增加一个受信设备，就增加一个潜在攻击入口
- **定期审计已登录设备**：account.apple.com > 设备
- 移除不用的旧设备
- 关闭 Handoff 与通用控制（若不需要）

### 14.7 iCloud 备份的隐私代价

**iCloud 备份包含：**

- App 数据（未加密内容取决于 App 与 ADP）
- 消息历史（iMessage 备份非 E2EE 除非 ADP）
- 照片、视频
- 设备设置
- HomeKit 配置
- 健康数据（部分）

**攻击价值：**

- 一份未受 ADP 保护的备份等同于**镜像设备的所有内容**
- Apple 服务端可能配合执法要求访问元数据
- 备份存储在多个数据中心（地理管辖权复杂）

**极客策略：**

- **启用 ADP**（端到端加密）
- 敏感账户**不使用 iCloud 备份**
- 定期删除旧备份（尤其是身份迁移、职业变化后）

### 14.8 账户防线配置清单

- Apple ID 密码 ≥ 16 位随机
- 硬件安全密钥作为主 2FA 因子
- 关闭 SMS 2FA
- 开启 Stolen Device Protection
- 每月审查已登录设备
- 启用 ADP
- 恢复密钥金属卡异地存放
- 家庭组成员最小化
- 敏感账户独立 Apple ID

---

## 15. 备份、恢复与灾难预案

### 15.1 备份层次

**极客防线要求"数据 + 配置 + 密钥"三层备份：**

| 层次 | 内容 | 备份方式 |
|------|------|---------|
| 数据 | 照片、文件、消息 | iCloud / 加密外置 SSD |
| 配置 | MDM Profile、网络、密码 | 密码管理器 |
| 密钥 | Apple ID、恢复密钥、密码库主密码 | 金属卡 + 异地 |

### 15.2 本地备份 vs 云备份

**iTunes/Finder 本地备份：**

- 加密备份：AES-256，密码派生
- **注意**：备份密码丢失 = 数据永久不可访问，Apple 无恢复
- 更长的备份频率限制（连接电脑）

**iCloud 备份：**

- 自动、增量
- 未启用 ADP 时 Apple 可访问
- 加密（在传输与存储），但**密钥在 Apple 一侧**
- ADP 后：Apple 无法访问

**极客选择：**

- **主备份**：iCloud + ADP（便利）
- **离线备份**：加密外置 SSD，每季度一次
- **密钥备份**：纸质/金属，异地存放

### 15.3 密码管理器与 Keychain

**推荐架构：**

- iCloud Keychain 作为日常便利
- Bitwarden / 1Password / KeePassXC 作为强备份
- 硬件 YubiKey 作为最终防线

**避免：**

- 单一密码管理器无备份
- 主密码写在设备中
- 使用在线"密码检查器"

### 15.4 灾难场景演练

**场景 1：设备丢失**

1. 立即另一设备登录 icloud.com
2. 定位 → 播放声音 → 标记丢失
3. 若确信不可回 → 抹除
4. 移除设备账户
5. 更改关键密码（尤其 iCloud、邮件、支付）

**场景 2：Apple ID 失陷**

1. 立即改密码（另一设备/网络）
2. 检查已登录设备列表
3. 撤销可疑 session
4. 检查转发邮件规则、恢复邮箱
5. 启用硬件 2FA

**场景 3：疑似间谍软件**

1. 飞行模式 + 保存 sysdiagnose
2. 联系可信研究者
3. 从**另一台干净设备**转移敏感账户
4. 决定：抹除 / 重装 / 保留设备作为证据

**场景 4：物理扣押**

1. 事先设置：关机 → 只留强密码
2. 敏感数据不落本地（云端 E2EE）
3. 已知被扣押：立即从远程移除设备账号（如果有可信伙伴）

### 15.5 恢复流程

**DFU/恢复模式重置：**

1. 连接电脑
2. 触发 DFU
3. 通过 Finder/iTunes "恢复 iPhone"
4. 重新配置为**新设备**（不恢复旧备份，若怀疑失陷）
5. 逐步迁移必要数据

**注意**：恢复后仍需 Apple ID 通过激活锁。若怀疑 Apple ID 已泄露，**先改 Apple ID 密码**再恢复。

### 15.6 密码学备份最佳实践

**28 字符恢复密钥：**

- 打印两份，纸质袋防水
- 金属备份（如 "Cryptosteel Capsule"）
- 存放两个不同物理地址
- 每 12 个月验证一次可读

**硬件密钥：**

- 至少 2 枚（不同型号）
- 一枚日常携带，一枚保险柜
- 型号避免过老（固件漏洞风险）

### 15.7 备份与恢复清单

- 主备份：iCloud + ADP
- 离线备份：加密 SSD
- 恢复密钥：金属 + 异地
- 硬件 2FA：双密钥
- 每半年演练一次灾难恢复
- 敏感账户定期轮换密码

---

## 16. 分层加固配置与持续防御

### 16.1 三级配置模板

针对不同的威胁模型，推荐三档配置：

**Tier 1：技术用户基线（对应 T0-T1）**

- 保持最新 iOS
- 8 位混合密码
- Face ID + 注意力检测
- 关闭锁屏通知内容
- 保留默认 USB Restricted Mode
- 开启 Find My、Activation Lock
- 2FA（推送 + TOTP）
- 关闭"分享位置"到非必要联系人
- App 权限月度审查

**Tier 2：敏感职业/资产（对应 T2-T3 部分场景）**

- 上述所有 +
- Recovery Lock 开启
- Stolen Device Protection 开启
- iCloud Advanced Data Protection
- 硬件安全密钥（YubiKey）
- iMessage 未知发送者过滤
- 敏感沟通迁至 Signal / Session
- 锁定模式在特定环境（会议、抗议、跨境）启用
- 每月 MVT 分析备份
- 只从 App Store 安装，拒绝 MDM 描述文件
- 密码管理器 + 金属备份恢复密钥

**Tier 3：高风险目标（对应 T3-T4）**

- 上述所有 +
- 主设备 + 一次性设备分离
- 敏感数据不落本地（只走 E2EE 服务）
- 家庭网络 IDS（Suricata）+ DNS 观测（Pi-hole）
- 定期完全关机（每次进入不可信环境前）
- 屏蔽袋存放
- 与研究者建立通信渠道
- 团队/律师/联系人预先安排应急响应
- 每季度审计已登录设备 + 硬件密钥 + 恢复流程演练
- 关注 Apple Security Research 邮件、Citizen Lab 报告

### 16.2 每日/每周/每月操作节奏

**每日（5 秒）**

- 进入陌生环境前：短按侧边+音量键，禁用生物识别
- 若怀疑：查看电池/流量异常

**每周（10 分钟）**

- 检查系统更新
- 审查 App 权限变动
- 检查"上次访问"日志

**每月（30-60 分钟）**

- 导出 sysdiagnose 存档
- MVT 分析
- Apple ID 登录设备审查
- 描述文件审计
- 备份完整性验证

**每季度（半天）**

- 灾难恢复演练
- 恢复密钥物理验证
- 密码轮换（关键账户）
- 硬件密钥固件检查
- 阅读最新 Citizen Lab 报告与 Apple 安全公告

**每年**

- 威胁模型重新评估
- 设备代际评估（是否仍在支持）
- 备份迁移（介质老化）

### 16.3 常见反模式（不要做）

**危险做法：**

- 4 位数字 PIN
- 短信 2FA
- iCloud 备份未开启 ADP
- 安装来路不明的描述文件（"开发者认证"邮件）
- 越狱 + tweak 处理敏感数据
- 用同一设备承载身份/资产/日常
- 长期"下次再更新"
- 关闭 Find My 或 Recovery Lock
- 只用 Face ID，从不输入密码
- 敏感对话使用 SMS/微信/iMessage 而非 E2EE

**伪安全做法：**

- 依赖"越狱检测 App"作为完整性判断
- 认为 iCloud 有密码就安全
- 认为 Apple 会主动通知所有攻击（真实情况：仅在有把握识别到国家级攻击时才发通知）
- 认为关闭 Siri 就防住了语音监听

### 16.4 与其他报告的协同

本报告与既有报告构成体系：

- **iOS 高风险人群开启"锁定模式"**：Tier 3 具体操作
- **iOS 持久化与数据窃取**：间谍软件防线的具体检测点
- **iOS 及时更新系统**：修补窗口管理
- **iOS 应用锁定与隐藏**：本地数据分层
- **iOS 反追踪与网络隐私**：网络层防线深化
- **iOS App 追踪透明度**：应用层数据流控制
- **iOS iCloud 高级数据保护**：账户与备份层
- **iOS 锁屏与 Face ID 安全**：设备访问层深化
- **iOS 隐私权限管理与沙盒机制**：运行时防线
- **iOS 快捷指令与自动化隐私**：自动化攻击面

### 16.5 持续学习与情报源

**必订阅：**

- **Apple Security Advisories**：https://support.apple.com/en-us/HT201222
- **Citizen Lab Blog**：https://citizenlab.ca/blog/
- **Amnesty Security**：https://www.amnesty.org/
- **Project Zero (Google)**：https://projectzero.googleblog.com/（跨平台视角）
- **Krebs on Security**：https://krebsonsecurity.com/
- **Have I Been Pwned**：监控邮箱泄露

**CVE 数据库：**

- NVD：https://nvd.nist.gov/
- Apple 每月发布 iOS CVE 列表

**工具与社区：**

- MVT：https://github.com/mvt-project/mvt
- iLEAPP：https://github.com/abrignoni/iLEAPP
- r/securityiOS、r/cybersecurity

**播客与讲座：**

- Darknet Diaries（案例）
- DEF CON / CCC iOS 议题
- CanSecWest / Pwn2Own 移动组

### 16.6 结语：防线是过程，不是产品

极客防线的核心不是任何单一功能、工具或配置——它是一套**持续的过程**：

1. **理解威胁**：明确谁可能攻击、为什么、以什么手段
2. **减小暴露**：默认拒绝、最小化、分层
3. **保持更新**：CVE 修补是最便宜的防御
4. **主动监测**：假定失陷，寻找异常
5. **准备响应**：演练、备份、联系人
6. **迭代演进**：每年重新评估威胁模型和防线

iOS 提供的安全基座是行业里最坚固的之一。但**再坚固的基座也不能替代使用者的判断**。锁定模式对绝大多数人过度，对极少数人不足；强密码对绝大多数人多余，对某些人是唯一防线。真正的极客防线，是理解这些权衡，并为自己做出正确选择。

---

**附录：iOS 极客防线设置速查表**

**基础层：**

| 项 | 路径 | 建议 |
|---|------|------|
| 系统更新 | 设置 > 通用 > 软件更新 | 自动 + 立即 |
| 密码 | 设置 > 面容 ID 与密码 > 更改密码 | 12+ 位混合 |
| 自动锁定 | 设置 > 显示与亮度 | 30 秒或立即 |
| 面容 ID 注意力 | 设置 > 面容 ID 与密码 | 开启 |
| 锁屏通知 | 设置 > 通知 | 关闭预览 |
| USB 限制 | 设置 > 面容 ID 与密码 | 开启 |

**进阶层：**

| 项 | 路径 | 建议 |
|---|------|------|
| Recovery Lock | 设置 > 通用 > 传输或还原 iPhone | 开启 |
| Stolen Device Protection | 设置 > 面容 ID 与密码 | 开启 |
| ADP | 设置 > [Apple ID] > iCloud > 高级数据保护 | 开启 |
| 硬件 2FA | account.apple.com > 登录和安全 | 添加 |
| 未知发送者过滤 | 设置 > 信息 | 开启 |
| iMessage 关闭非 Apple 附件预览 | 系统级 | 保持最新 |

**极客层：**

| 项 | 路径 | 建议 |
|---|------|------|
| 锁定模式 | 设置 > 隐私与安全 | 高风险场景开启 |
| Sysdiagnose | 硬件按键 | 每月存档 |
| MVT 分析 | 电脑端 | 每月 |
| 描述文件审计 | 设置 > 通用 > VPN 与设备管理 | 每月 |
| Apple ID 设备审查 | account.apple.com | 每月 |

---

**报告完成日期**：2026 年 10 月 15 日

**版本**：1.0

**用途声明**：本报告为教育性质的防御分析，聚焦于用户如何保护自身设备与数据。所有引用的攻击案例均来自公开研究（Citizen Lab、Lookout、Amnesty、Kaspersky 等）与 Apple 官方安全公告，不包含未公开的漏洞细节或使用方法。

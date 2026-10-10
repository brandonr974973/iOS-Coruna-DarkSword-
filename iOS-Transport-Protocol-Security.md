# iOS 传输与协议安全全景分析：从 TLS 到无线协议的攻击面、风险链与防御指南

> 本报告系统梳理 iOS 生态中传输层与网络协议的安全风险，覆盖 App Transport Security（ATS）、TLS/SSL 与证书锁定、AirPlay/AirDrop/Continuity 等 Apple 私有无线协议、蓝牙与 Wi-Fi 攻击面、蜂窝基带协议栈、NFC、VPN 与 DNS 泄漏等关键领域。结合 2024–2026 年公开漏洞研究成果（包括 AirBorne、AirCollect、BLE Re-Pairing、5Ghoul 等），给出完整的攻击链分析与防御建议。

---

## 一、iOS 传输安全架构总览

### 1.1 传输层安全模型

iOS 的传输安全体系可以分为以下几个层次：

- **应用层**：App Transport Security（ATS）策略、证书锁定（Certificate Pinning）、自定义加密协议
- **传输层**：TLS 1.2/1.3、DTLS、Secure Transport / Network.framework
- **网络层**：IPsec、VPN（IKEv2 / IPsec / L2TP）、Wi-Fi（WPA3 / EAP）
- **链路层**：蓝牙 BLE、NFC、AWDL（Apple Wireless Direct Link）、蜂窝基带协议栈
- **物理层**：射频信号、近场通信

每一层都存在独立的攻击面，且层与层之间可能存在跨层攻击链。

### 1.2 Apple 的安全传输设计原则

- **强制 HTTPS**：自 iOS 9 起 ATS 默认要求所有 HTTP 连接使用 TLS
- **硬件加速加密**：Secure Enclave 参与密钥管理，AES 加速引擎
- **私有协议生态**：AirDrop、AirPlay、Handoff、Continuity 等基于 BLE + AWDL 的私有协议
- **网络扩展框架**：Network Extension / NEFilterProvider / NEDNSProxyProvider
- **iCloud Private Relay**：基于 Oblivious HTTP 的隐私代理

---

## 二、App Transport Security（ATS）与 TLS 安全

### 2.1 ATS 机制原理

ATS 是 Apple 在 iOS 9 引入的传输安全策略，强制要求所有网络连接满足以下最低标准：

- **TLS 版本**：TLS 1.2 及以上
- **证书算法**：RSA 2048 位及以上或 ECC 256 位及以上
- **哈希算法**：SHA-256 及以上
- **前向保密**：要求使用 ECDHE 或 DHE 密钥交换
- **cipher suite 白名单**：仅允许强加密套件

### 2.2 ATS 例外与安全风险

尽管 ATS 默认配置较为安全，但开发者可以通过 Info.plist 配置例外：

- **NSExceptionAllowsInsecureHTTPLoads**：允许特定域名使用 HTTP
- **NSExceptionMinimumTLSVersion**：降低特定域名的 TLS 最低版本
- **NSExceptionRequiresForwardSecrecy**：关闭特定域名的前向保密要求
- **NSAllowsArbitraryLoads**：全局禁用 ATS（最危险的配置）
- **NSAllowsLocalNetworking**：允许本地网络使用 HTTP

**实际风险**：大量 App 因兼容性问题全局或局部关闭 ATS，导致中间人攻击风险显著上升。2024–2026 年的应用安全审计显示，仍有约 15–20% 的金融类 App 存在 ATS 配置不当的问题。

### 2.3 TLS 实现层面的风险

- **SSLVerifyLevel 降级**：部分 App 在 NSURLSession 配置中手动关闭证书验证
- **自签名证书信任**：企业部署中常见安装自定义 CA 根证书，扩大了 CA 信任链攻击面
- **TLS 指纹识别**：攻击者可通过 JA3/JA4 指纹识别 iOS 设备和 App 版本
- **TLS 1.3 0-RTT**：早期数据（Early Data）可能面临重放攻击

### 2.4 证书锁定（Certificate Pinning）

#### 2.4.1 原理

证书锁定是 ATS 之上的额外保护层，App 在代码中硬编码服务器证书或公钥的哈希值，即使系统信任了恶意 CA，也无法通过锁定检查。

iOS 上常见的实现方式：

- **NSURLSessionDelegate 手动验证**：在 `urlSession(_:didReceive:completionHandler:)` 中检查证书链
- **第三方库**：TrustKit、Alamofire 的 ServerTrustManager
- **Network.framework**：在 NWConnection 中配置 SecTrust 评估

#### 2.4.2 证书锁定的绕过技术

截至 2026 年，已知的 iOS 证书锁定绕过技术包括：

1. **Frida + Objection 动态 Hook**：通过运行时注入替换 SSL 验证函数
2. **Binary Instrumentation**：修改 IPA 中的 Mach-O 二进制，patch 验证逻辑
3. **SSL Kill Switch 3**：基于 Substrate/Substitute 的系统级 Hook（需越狱）
4. **Repackaging**：反编译 → 移除锁定代码 → 重签名
5. **Proxy 工具集成**：mitmproxy / Burp Suite 配合自定义 CA 和 Frida 脚本
6. **iOS 17+ 非越狱方案**：利用企业证书重签名 + dylib 注入

#### 2.4.3 增强锁定的防御策略

- **公钥锁定优于证书锁定**：证书可能更换但公钥不变
- **多证书锁定**：同时锁定主证书和备份证书
- **锁定失败处理**：连接失败时不应降级到不安全的回退方案
- **锁定更新机制**：通过远程配置支持证书轮换

---

## 三、Apple 私有无线协议安全

### 3.1 AirPlay 协议与 AirBorne 漏洞（CVE-2025-24132 系列）

#### 3.3.1 AirPlay 协议概述

AirPlay 是 Apple 的无线音视频流传输协议，基于以下技术栈：

- **发现层**：Bonjour / mDNS（多播 DNS）
- **传输层**：HTTP + RTSP + RTP
- **加密层**：Ed25519 签名 + X25519 密钥交换 + AES-128-CTR
- **配对层**：安全配对协议（Secure Pairing），支持 PIN 码和自动配对

#### 3.3.2 AirBorne：可蠕虫传播的零点击 RCE

2025 年 4 月，Oligo Security 披露了名为 **AirBorne** 的严重漏洞系列，影响所有支持 AirPlay 的 Apple 设备：

**漏洞原理**：

- AirPlay 接收端在解析来自发送端的特定音频流数据时存在内存损坏漏洞
- 攻击者可以构造恶意的 AirPlay 广播包，在同一 Wi-Fi 网络内自动触发
- **零点击**：受害者无需任何操作，只要设备在同一网络且 AirPlay 可用
- **无需配对**：漏洞发生在配对握手之前，绕过了 AirPlay 的安全配对机制

**影响范围**：

- iPhone、iPad、Apple TV、HomePod、Mac
- CVE-2025-24132（DoS）及关联的 RCE 变体
- 新加坡 CSA 发布安全警报 AL-2025-042

**攻击链**：

1. 攻击者接入目标 Wi-Fi 网络（或利用开放 Wi-Fi）
2. 发送恶意 mDNS 广播，宣告自己为 AirPlay 接收器
3. 目标设备自动发现并尝试连接
4. 恶意 AirPlay 数据包触发内存损坏
5. 执行任意代码，可能获得完整设备控制权

**修复**：Apple 在 iOS 18.5 / macOS 15.5 中修复，加强了 AirPlay 协议解析的输入验证。

### 3.2 AirDrop 协议与隐私泄露

#### 3.2.1 AirDrop 协议架构

AirDrop 基于 Apple Wireless Direct Link（AWDL），协议流程如下：

1. **发现阶段**：通过 BLE 广播发现请求（Discovery BLE Advertisement）
2. **身份验证**：交换哈希化的电话号码和邮箱（SHA-256）
3. **连接建立**：通过 AWDL 建立点对点 Wi-Fi 连接
4. **文件传输**：TLS 加密传输

#### 3.2.2 AirCollect：电话号码哈希逆向

2021 年德国达姆施塔特工业大学的研究团队发现：

- AirDrop 在发现阶段广播的电话号码哈希（SHA-256）可以被附近设备截获
- 由于电话号码的熵有限（10-15 位数字），可以通过**暴力枚举**在数分钟内还原真实号码
- **AirCollect** 工具实现了高效的大规模哈希碰撞攻击
- 攻击者可以在公共场所（地铁、商场）批量收集附近用户的电话号码

**Apple 的修复**：
- iOS 16.2 起引入 **Contact Verification Server**，不再直接广播完整哈希
- 改为使用服务器辅助的私有集合交集（Private Set Intersection）协议
- 但研究者指出，2026 年的新分析（arxiv 2606.26967）显示仍可能存在信息泄漏

#### 3.2.3 AirDrop 的其他攻击面

- **恶意文件投递**：发送包含恶意 payload 的文件（PDF、图片等），利用解析器漏洞
- **钓鱼攻击**：通过 AirDrop 发送伪装为系统通知的钓鱼内容
- **拒绝服务**：大量 AirDrop 请求导致目标设备弹窗轰炸
- **AWDL 协议漏洞**：AWDL 实现中的内存安全问题可能导致 RCE

### 3.3 Continuity 协议与 BLE 隐私

#### 3.3.1 Continuity 协议族

Apple 的 Continuity 功能族包括 Handoff、Instant Hotspot、Nearby Continuity 等，均基于 BLE 广播：

- **Handoff**：在设备间传递任务上下文
- **Instant Hotspot**：发现并连接个人热点
- **Nearby Info**：设备间交换身份和 proximity 信息
- **AutoFill / Password Sharing**：通过 BLE 近场共享密码

#### 3.3.2 BLE Continuity 协议的安全问题

2020–2026 年的多项研究揭示了 Continuity BLE 协议的系统性安全问题：

**数据泄漏**：

- BLE 广播中包含设备型号、Apple ID 部分哈希、Wi-Fi 配置等敏感信息
- 即使设备锁定，BLE 广播仍在持续发送
- 攻击者可以通过被动监听 BLE 广播追踪设备的物理位置

**协议降级与中间人**：

- 2021 年 USENIX Security 论文 "Disrupting Continuity" 展示了 BLE 中间人攻击
- 攻击者可以伪造 Continuity 消息，触发目标设备的自动连接行为
- BLE Re-Pairing 攻击（BLERP，NDSS 2026）：通过 BLE 重新配对劫持已建立的信任关系

**近场攻击**：

- 伪造 Handoff 消息诱导用户打开恶意 App
- 伪造 Instant Hotspot 广播诱导设备连接到攻击者控制的热点
- AutoFill 中间人：拦截 BLE 密码共享过程

---

## 四、蓝牙安全

### 4.1 iOS 蓝牙攻击面

iOS 使用蓝牙的场景包括：

- **音频**：AirPods、蓝牙音箱、车载系统
- **输入设备**：键盘、鼠标、触控板
- **Continuity**：Handoff、AirDrop、Nearby
- **定位**：AirTag、Find My 网络
- **CarPlay**：车载信息娱乐系统

### 4.2 已知漏洞与攻击

#### 4.2.1 BLE 协议栈漏洞

- **CVE-2026-20650**：Apple OS 蓝牙 DoS 漏洞（2026 年 2 月披露），可导致蓝牙服务崩溃
- **BIAS（Bluetooth Impersonation AttackS）**：跨平台蓝牙配对绕过，影响 iOS 的蓝牙经典模式
- **KNOB（Key Negotiation of Bluetooth）**：蓝牙加密协商降级攻击
- **BLESA**：BLE 重新连接时的身份验证绕过

#### 4.2.2 AirPods 与音频攻击

- **AirPods 固件漏洞**：通过恶意 BLE 广播触发固件更新中的内存损坏
- **音频注入**：通过蓝牙 A2DP 协议注入恶意音频数据
- **按键注入**：蓝牙 HID 设备欺骗，注入虚拟按键操作

#### 4.2.3 Find My / AirTag 攻击

- **AirTag 追踪滥用**：虽然 Apple 引入了反追踪机制，但仍有绕过报告
- **Find My 网络协议分析**：BLE 广播中的加密弱点可能被用于设备定位
- **NFC 标签模拟**：通过 NFC 模拟 AirTag 触发 Find My 网络消息

### 4.3 蓝牙防御现状

- iOS 使用随机化 BLE 地址防止被动追踪
- AirPods 等配件使用自研加密协议
- Find My 网络使用端到端加密和密钥轮换
- 但蓝牙协议栈的闭源性使得独立安全审计困难

---

## 五、Wi-Fi 协议安全

### 5.1 iOS Wi-Fi 攻击面

- **WPA3 实现**：iOS 支持 WPA3-Personal（SAE）和 WPA3-Enterprise
- **Wi-Fi 感知（Wi-Fi Aware）**：iOS 尚未全面支持，但相关协议栈已存在
- **Captive Portal**：公共 Wi-Fi 认证页面
- **Wi-Fi 配置描述文件**：企业 Wi-Fi 配置（EAP-TLS / EAP-TTLS）
- **iCloud Wi-Fi**：自动同步 Wi-Fi 密码

### 5.2 已知攻击

#### 5.2.1 WPA3 攻击

- **Dragonblood**：WPA3-SAE 协议的降级攻击和侧信道攻击
- **EDP（Eavesdropping on Dragonblood's Patch）**：补丁后仍存在的变体攻击
- iOS 已修补已知 Dragonblood 变体，但新变体仍在持续研究中

#### 5.2.2 Wi-Fi 驱动与固件

- **Broadcom Wi-Fi 芯片漏洞**：历史上有多个严重漏洞（Broadpwn 等），影响 iPhone
- **Wi-Fi 固件 RCE**：通过恶意管理帧触发固件中的内存损坏
- **Wi-Fi 驱动漏洞**：iOS 的 Apple Wi-Fi 驱动中的内存安全问题

#### 5.2.3 公共 Wi-Fi 风险

- **Captive Portal 钓鱼**：伪造认证页面窃取凭证
- **DNS 劫持**：在公共 Wi-Fi 上劫持 DNS 响应
- **SSL Stripping**：降级 HTTPS 到 HTTP（ATS 可防御，但部分 App 例外）
- **同网络嗅探**：嗅探未加密的 mDNS、SSDP 等协议

### 5.3 Wi-Fi 隐私保护

- **MAC 地址随机化**：iOS 默认对每个 Wi-Fi 网络使用不同的私有 MAC 地址
- **iCloud Private Relay**：通过双代理架构隐藏真实 IP
- **限制 Wi-Fi 信息泄漏**：iOS 限制 App 获取当前 Wi-Fi 的 SSID 和 BSSID

---

## 六、蜂窝基带协议安全

### 6.1 基带架构

iOS 使用 Qualcomm 基带芯片（近年）或 Intel 基带（旧机型），基带运行独立的实时操作系统（RTOS），与 iOS 主系统通过 IPC 通信：

- **基带处理器（BP）**：独立 CPU、独立内存、独立固件
- **应用处理器（AP）**：运行 iOS
- **通信接口**：共享内存 + IPC 消息队列
- **协议栈**：LTE/5G NR 协议栈运行在基带侧

### 6.2 基带攻击面

#### 6.2.1 蜂窝协议栈漏洞

- **Over-The-Air 基带 RCE**：腾讯 Keen Lab 在 USENIX 2021 展示了通过 5G 协议栈的远程基带代码执行
- **5Ghoul**：5G 协议实现漏洞系列，可导致 DoS 和潜在 RCE
- **LLFuzz**：使用 LLM 引导的模糊测试发现基带协议下层漏洞（2025–2026）
- **单包瘫痪**：2025 年研究发现单个畸形数据包可导致基带崩溃

#### 6.2.2 IMSI 捕获与位置追踪

- **IMSI Catcher（Stingray）**：伪基站捕获用户 IMSI 和位置
- **5G SUCI 保护**：5G 引入 Subscription Concealed Identifier，但实现中仍有侧信道
- **TMSI 去匿名化**：通过信令攻击还原临时标识符

#### 6.2.3 跨域攻击

- **基带到 AP 的逃逸**：基带 RCE 后通过 IPC 接口攻击 iOS 主系统
- **SMS 攻击**：通过 Class 0 SMS 或 SIM Toolkit 触发特权操作
- **SS7/Diameter 攻击**：运营商级别的信令攻击，可拦截通话和短信

### 6.3 基带安全现状

- 基带固件闭源且无法独立审计
- Apple 通过基带固件更新修复漏洞
- 5G 协议在安全设计上优于 4G（SUCI、SUPI 保护）
- 但实现层面的内存安全问题持续存在

---

## 七、NFC 安全

### 7.1 iOS NFC 能力

- **NFC Tag Reading**：读取 NDEF 标签（iOS 11+）
- **Background Tag Reading**：后台自动读取（iOS 12+）
- **NFC Writing**：写入 NDEF 标签（iPhone XR/XS 及以上）
- **Apple Pay**：基于 NFC 的支付（Secure Element）
- **Car Key**：数字车钥匙（UWB + NFC）
- **Home Key**：智能门锁（NFC）
- **Express Mode**：免解锁快速刷卡

### 7.2 NFC 攻击面

- **NDEF 解析漏洞**：恶意 NDEF 记录触发 NFC 解析器中的内存损坏
- **NFC 中继攻击**：延长 NFC 通信距离，用于无钥匙进入攻击
- **Apple Pay 侧信道**：通过 NFC 时序分析推断交易信息
- **Car Key 中继**：UWB + NFC 组合的中继攻击
- **恶意标签**：包含自动触发 URL 的 NDEF 标签，诱导用户访问钓鱼页面

### 7.3 NFC 防御

- Secure Element 隔离 NFC 支付密钥
- 距离限制（NFC 物理特性，通常 < 4cm）
- 用户确认机制（Express Mode 除外）
- NDEF 解析沙箱化

---

## 八、VPN 与 DNS 安全

### 8.1 iOS VPN 架构

iOS 支持以下 VPN 协议：

- **IKEv2/IPsec**：系统原生支持，企业常用
- **IPSec (Cisco)**：旧版兼容
- **L2TP/IPsec**：旧版兼容
- **WireGuard**：通过第三方 App（使用 Network Extension）
- **Always-On VPN**：通过 MDM 配置强制 VPN

### 8.2 VPN 安全风险

#### 8.2.1 VPN 绕过漏洞

- **Kill Switch 失败**：VPN 断开时流量可能泄漏（非 Always-On 场景）
- **IPv6 泄漏**：部分 VPN 仅代理 IPv4，IPv6 流量直接暴露
- **DNS 泄漏**：VPN 未正确接管 DNS 解析，系统 DNS 请求绕过 VPN 隧道
- **WebKit 代理泄漏**：2026 年研究发现 WebKit 中 IP 和 DNS 泄漏影响代理浏览器和 iCloud Private Relay

#### 8.2.2 VPN App 安全问题

- **权限过大**：VPN App 需要 "Add VPN Configurations" 权限，可拦截所有流量
- **日志记录**：部分 VPN App 记录用户浏览行为
- **流量注入**：恶意 VPN App 可以修改、注入或重定向流量
- **配置劫持**：通过描述文件安装恶意 VPN 配置

### 8.3 DNS 安全

- **DNS over HTTPS (DoH)**：iOS 14+ 支持加密 DNS
- **DNS over TLS (DoT)**：iOS 14+ 支持
- **iCloud Private Relay**：Apple 的隐私 DNS 代理
- **NEDNSProxyProvider**：App 级别的 DNS 代理框架
- **DNS 劫持风险**：未加密 DNS 可被中间人篡改

---

## 九、网络中间人攻击

### 9.1 中间人攻击向量

#### 9.1.1 证书信任链攻击

- **恶意 CA 证书安装**：通过 MDM 或描述文件安装攻击者控制的 CA
- **企业代理**：企业环境中的 SSL 解密代理
- **系统级信任**：iOS 根证书存储中的 CA 数量持续增加

#### 9.1.2 网络层中间人

- **ARP 欺骗**：在同一局域网中伪造 ARP 响应
- **DNS 劫持**：篡改 DNS 响应将流量重定向
- **SSL Stripping**：降级 HTTPS 到 HTTP
- **HTTP/2 Downgrade**：强制降级到不安全的协议版本

#### 9.1.3 设备级中间人

- **描述文件安装**：安装恶意配置描述文件，修改网络设置
- **代理配置**：通过 Wi-Fi 代理设置重定向流量
- **VPN 配置**：安装恶意 VPN 配置拦截所有流量

### 9.2 中间人检测

- **证书锁定**：检测非预期 CA 签发的证书
- **证书透明度（CT）**：验证证书是否在公开日志中记录
- **HPKP（已废弃）**：HTTP Public Key Pinning 已被浏览器废弃
- **Network Extension 监控**：使用 NEFilterProvider 监控网络流量

---

## 十、跨协议攻击链

### 10.1 典型攻击链

#### 10.1.1 Wi-Fi + AirPlay 攻击链

1. 攻击者接入公共 Wi-Fi
2. 发送恶意 AirPlay 广播（AirBorne）
3. 目标设备自动响应
4. 利用 AirPlay 解析漏洞实现 RCE
5. 横向移动到同一网络的其他设备

#### 10.1.2 BLE + Continuity + Wi-Fi 攻击链

1. BLE 监听获取目标设备信息
2. 伪造 Continuity 消息触发 Instant Hotspot
3. 目标设备自动连接到攻击者的伪造热点
4. 在伪造热点上实施中间人攻击
5. 窃取或篡改网络流量

#### 10.1.3 基带 + SMS + WebKit 攻击链

1. 通过 IMSI Catcher 定位目标
2. 发送恶意 SMS（Class 0 或 SIM Toolkit）
3. SMS 触发基带异常行为
4. 结合 ForgedInfection 等链接触发 WebKit 漏洞
5. 实现完整设备控制

#### 10.1.4 AirDrop + 解析器攻击链

1. 在公共场所广播 AirDrop 发现请求
2. 截获目标设备的电话号码哈希
3. 暴力破解还原电话号码（AirCollect）
4. 通过 AirDrop 发送恶意文件
5. 利用 PDF / 图片解析器漏洞实现 RCE

### 10.2 攻击难度评估

| 攻击链 | 所需条件 | 用户交互 | 影响 |
|--------|----------|----------|------|
| Wi-Fi + AirPlay | 同一网络 | 无需（零点击） | RCE |
| BLE + Continuity | 物理接近（~100m） | 可能无需 | MITM / 数据窃取 |
| 基带 + SMS | IMSI Catcher | 无需 | 定位 / 潜在 RCE |
| AirDrop + 解析器 | 物理接近（~10m） | 需要接受文件 | RCE + 隐私泄漏 |

---

## 十一、防御建议

### 11.1 开发者层面

1. **严格 ATS 配置**：不关闭 ATS，不使用例外配置
2. **实施证书锁定**：使用公钥锁定 + 备份证书 + 远程更新机制
3. **安全协议解析**：对所有网络输入实施严格验证，特别是自定义协议
4. **安全 BLE 通信**：Continuity 类功能使用端到端加密和身份验证
5. **最小权限原则**：不请求不必要的网络权限
6. **网络监控**：使用 Network.framework 的监控 API 检测异常连接

### 11.2 用户层面

1. **保持系统更新**：及时安装 iOS 安全更新
2. **谨慎接受 AirDrop**：设置为 "仅联系人" 或关闭
3. **警惕公共 Wi-Fi**：使用 VPN 加密所有流量
4. **审查描述文件**：定期检查并删除不必要的配置描述文件
5. **关闭不必要的无线功能**：不使用时关闭蓝牙、Wi-Fi、NFC
6. **启用锁定模式**：高风险用户启用 iOS 锁定模式

### 11.3 企业层面

1. **MDM 强制 ATS**：通过 MDM 策略强制 App 使用 ATS
2. **VPN 策略**：部署 Always-On VPN，配置 Kill Switch
3. **加密 DNS**：部署 DoH/DoT，阻止明文 DNS
4. **网络分段**：企业 Wi-Fi 实施客户端隔离
5. **AirPlay 管控**：通过 MDM 限制 AirPlay 接收设备
6. **基带安全监控**：检测 IMSI Catcher 等异常蜂窝信号

### 11.4 Apple 平台层面

1. **持续强化 ATS**：提高最低 TLS 版本要求，减少例外配置
2. **私有协议审计**：对 AirPlay、AirDrop、Continuity 进行系统性安全审计
3. **基带隔离**：加强基带与 AP 之间的 IPC 安全边界
4. **BLE 隐私增强**：进一步减少 BLE 广播中的可识别信息
5. **NFC 沙箱化**：加强 NDEF 解析的安全隔离
6. **透明度报告**：定期发布传输层安全修复的详细信息

---

## 十二、关键 CVE 与漏洞索引

| CVE / 名称 | 类型 | 影响协议 | 年份 | 严重性 |
|------------|------|----------|------|--------|
| AirBorne (CVE-2025-24132) | RCE / DoS | AirPlay | 2025 | 严重 |
| AirCollect | 隐私泄漏 | AirDrop (BLE/AWDL) | 2021 | 高 |
| CVE-2026-20650 | DoS | Bluetooth | 2026 | 中 |
| BIAS | 认证绕过 | Bluetooth Classic | 2020 | 高 |
| KNOB | 加密降级 | Bluetooth | 2019 | 高 |
| BLESA | 认证绕过 | BLE | 2020 | 高 |
| BLERP | 信任劫持 | BLE Continuity | 2026 | 高 |
| Dragonblood | 降级攻击 | WPA3-SAE | 2020 | 中 |
| 5Ghoul | DoS / RCE | 5G NR | 2023 | 严重 |
| Broadpwn | RCE | Wi-Fi Firmware | 2017 | 严重 |
| Keen Lab 5G RCE | RCE | 5G 基带 | 2021 | 严重 |
| WebKit Proxy Leak | 隐私泄漏 | WebKit / HTTP | 2026 | 中 |

---

## 十三、参考资料

1. Apple, "Preventing Insecure Network Connections," developer.apple.com
2. OWASP MASTG, "iOS App Transport Security," MASVS-NETWORK
3. Oligo Security, "AirBorne: Wormable Zero-Click RCE in Apple AirPlay," 2025
4. TU Darmstadt, "Disrupting Continuity of Apple's Wireless Ecosystem Security," USENIX Security 2021
5. HAL Science, "An Updated Analysis of Apple Continuity BLE Protocols," 2026
6. NDSS 2026, "BLERP: BLE Re-Pairing Attacks and Defenses"
7. AirCollect, "Efficiently Recovering Hashed Phone Numbers Leaked via Apple AirDrop," ACM / ePrint 2021
8. arxiv 2606.26967, "Systematic Vulnerability Research in the Apple AirDrop Protocol," 2026
9. Keen Lab / Tencent, "Over The Air Baseband Exploit: Gaining Remote Code Execution on 5G Smartphones," USENIX 2021
10. HAL Science, "SoK: Insecurity of Cellular Basebands," 2026
11. Qualcomm Security Bulletins, docs.qualcomm.com
12. MySK Blog, "IP and DNS Leaks in WebKit Affecting Proxy Browsers," 2026
13. CSIS Singapore, "Multiple Vulnerabilities in Apple AirPlay Protocol," AL-2025-042
14. Help Net Security, "Wireless vulnerabilities are doubling every few years," 2026
15. Help Net Security, "AirDrop and Quick Share vulnerabilities," 2026

---

*报告完成日期：2026-10-09 | 作者专注于 iOS 系统安全研究*

*如需进一步咨询 iOS 系统安全问题，请联系 telegram：https://t.me/one00190*

---

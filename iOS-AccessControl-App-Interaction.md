# iOS 访问控制与应用层交互限制 — 防御性安全深度分析

> **版本**: 1.0 | **日期**: 2026-10-11  
> **分类**: 防御性安全分析 | **受众**: iOS 安全研究员、应用开发者、渗透测试工程师  
> **咨询ios系统请咨询 telegram：https://t.me/one00190**

---

## 目录

1. [引言与威胁模型](#1-引言与威胁模型)
2. [iOS 安全架构总览](#2-ios-安全架构总览)
3. [沙箱机制深度分析](#3-沙箱机制深度分析)
4. [Entitlements 权限体系](#4-entitlements-权限体系)
5. [Keychain 访问控制](#5-keychain-访问控制)
6. [Data Protection 文件加密体系](#6-data-protection-文件加密体系)
7. [App Sandbox 文件系统隔离](#7-app-sandbox-文件系统隔离)
8. [URL Scheme 与 Inter-App 通信](#8-url-scheme-与-inter-app-通信)
9. [Universal Links 安全机制](#9-universal-links-安全机制)
10. [App Groups 共享数据访问控制](#10-app-groups-共享数据访问控制)
11. [Pasteboard 剪贴板访问限制](#11-pasteboard-剪贴板访问限制)
12. [后台任务与交互限制](#12-后台任务与交互限制)
13. [通知与推送交互控制](#13-通知与推送交互控制)
14. [Accessibility API 交互限制](#14-accessibility-api-交互限制)
15. [App Extension 安全架构](#15-app-extension-安全架构)
16. [第三方 SDK 访问控制审计](#16-第三方-sdk-访问控制审计)
17. [IPC 攻击面与防御](#17-ipc-攻击面与防御)
18. [Apple 与 Android 访问控制对比](#18-apple-与-android-访问控制对比)
19. [防御加固清单](#19-防御加固清单)
20. [行业案例与教训](#20-行业案例与教训)
21. [未来趋势与演进方向](#21-未来趋势与演进方向)
22. [参考法规与合规要求](#22-参考法规与合规要求)
23. [附录：工具与资源](#23-附录工具与资源)

---

## 1. 引言与威胁模型

### 1.1 为什么访问控制是 iOS 安全的核心

iOS 的访问控制体系是纵深防御（Defense in Depth）的关键层。与网络层、传输层安全不同，访问控制决定了**应用能做什么、能访问什么、能与其他应用如何交互**。即使攻击者绕过了网络层防护，访问控制体系仍然是阻止横向移动和数据窃取的最后屏障。

### 1.2 核心威胁模型

```
┌─────────────────────────────────────────────────────────────────┐
│                    iOS 访问控制威胁模型                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐       │
│  │  沙箱逃逸    │   │  权限提升    │   │  数据越权    │       │
│  │  Sandbox     │   │  Privilege   │   │  Unauthorized│       │
│  │  Escape      │   │  Escalation  │   │  Data Access │       │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘       │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              攻击目标层                               │      │
│  │  · 其他应用数据  · Keychain 条目  · 系统服务         │      │
│  │  · 用户隐私数据  · 共享容器      · 后台任务         │      │
│  └──────────────────────────────────────────────────────┘      │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐       │
│  │  IPC 劫持    │   │  剪贴板窃取  │   │  Extension   │       │
│  │  通信拦截    │   │  Clipboard   │   │  权限滥用    │       │
│  │  Hijacking   │   │  Theft       │   │  Abuse       │       │
│  └──────────────┘   └──────────────┘   └──────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 攻击面分类

| 攻击面 | 描述 | 风险等级 | 典型攻击 |
|--------|------|----------|----------|
| 沙箱边界 | 进程隔离与系统调用过滤 | 严重 | 内核漏洞逃逸沙箱 |
| Entitlements | 应用权限声明与检查 | 高 | 伪造或窃取 entitlement |
| Keychain | 凭证存储访问控制 | 高 | 跨应用读取 Keychain 条目 |
| 文件系统 | 应用容器与数据保护 | 中高 | 未加密数据访问 |
| URL Scheme | 应用间通信入口 | 中 | Scheme 劫持与参数注入 |
| Pasteboard | 剪贴板数据共享 | 中 | 敏感数据剪贴板泄露 |
| Background | 后台执行权限 | 中 | 后台数据外泄 |
| Extension | 扩展宿主权限继承 | 中高 | Extension 权限提升 |

### 1.4 防御目标

- **最小权限原则**: 应用仅获得完成任务所需的最小权限集
- **纵深防御**: 多层访问控制确保单层失效不导致全面沦陷
- **数据隔离**: 不同应用、不同安全级别的数据严格隔离
- **可审计性**: 所有访问控制决策可追踪、可审计
- **用户知情同意**: 敏感权限必须获得用户明确授权

---

## 2. iOS 安全架构总览

### 2.1 分层安全模型

```
┌─────────────────────────────────────────────────────────────┐
│                    用户空间 (User Space)                      │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │  App A  │  │  App B  │  │  App C  │  │ System  │       │
│  │ Sandbox │  │ Sandbox │  │ Sandbox │  │  Apps   │       │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘       │
│       │             │             │             │            │
│  ─────┴─────────────┴─────────────┴─────────────┴─────      │
│              访问控制策略层 (MAC/DAC)                         │
│  ─────────────────────────────────────────────────────       │
│       │             │             │             │            │
│  ┌────┴─────────────┴─────────────┴─────────────┴────┐      │
│  │         Apple Mobile File Integrity (AMFI)         │      │
│  │         Sandbox Extension Framework                 │      │
│  │         entitlementd / taskgated                   │      │
│  └───────────────────────────────────────────────────┘      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                    内核空间 (Kernel Space)                    │
│  ┌───────────────────────────────────────────────────┐      │
│  │  Mandatory Access Control (MAC) Framework          │      │
│  │  ├── Sandbox.kext — 进程沙箱策略执行               │      │
│  │  ├── AMFI.kext — 代码签名与 entitlement 验证       │      │
│  │  └── AppleImage4 — 固件完整性验证                   │      │
│  ├───────────────────────────────────────────────────┤      │
│  │  VFS Layer — 文件系统访问控制                       │      │
│  │  IPC Subsystem — 进程间通信过滤                     │      │
│  │  Network Stack — 网络访问控制                       │      │
│  └───────────────────────────────────────────────────┘      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                    硬件安全层                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │Secure Enclave│  │   AES Engine │  │  UID 密钥    │     │
│  │  (SEP)       │  │  (硬件加速)  │  │  (不可导出)  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 关键安全组件

| 组件 | 功能 | 访问控制角色 |
|------|------|-------------|
| **Sandbox.kext** | 进程沙箱策略执行 | 限制系统调用、文件访问、网络访问 |
| **AMFI.kext** | 代码签名验证 | 确保只运行签名代码，检查 entitlement |
| **entitlementd** | Entitlement 守护进程 | 管理应用权限声明 |
| **taskgated** | 任务门控守护进程 | 调试器附加权限控制 |
| **Secure Enclave** | 硬件安全飞地 | 密钥管理、生物识别验证 |
| **Data Protection** | 文件级加密 | 基于设备锁定状态的访问控制 |

### 2.3 访问控制决策流程

```
应用发起访问请求
       │
       ▼
┌──────────────────┐
│ Entitlement 检查 │─── 无权限 ──→ 拒绝
│ (AMFI 验证)      │
└────────┬─────────┘
         │ 有声明
         ▼
┌──────────────────┐
│ 用户授权检查     │─── 未授权 ──→ 请求权限 / 拒绝
│ (TCC 框架)       │
└────────┬─────────┘
         │ 已授权
         ▼
┌──────────────────┐
│ 沙箱策略检查     │─── 不允许 ──→ 拒绝
│ (Sandbox.kext)   │
└────────┬─────────┘
         │ 允许
         ▼
┌──────────────────┐
│ Data Protection  │─── 设备锁定 ──→ 返回 EACCES
│ 密钥可用性检查   │
└────────┬─────────┘
         │ 密钥可用
         ▼
┌──────────────────┐
│ 执行访问操作     │
│ 返回结果         │
└──────────────────┘
```

---

## 3. 沙箱机制深度分析

### 3.1 沙箱架构概述

iOS 沙箱基于 FreeBSD 的 MAC (Mandatory Access Control) 框架构建，每个第三方应用在独立沙箱中运行。沙箱策略定义了进程可以执行的操作集合。

```
┌─────────────────────────────────────────────────────────┐
│                    应用沙箱结构                           │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              App Container                       │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐   │   │
│  │  │  Bundle   │  │  Documents│  │  Library  │   │   │
│  │  │  (只读)   │  │  (读写)   │  │  (读写)   │   │   │
│  │  └───────────┘  └───────────┘  └───────────┘   │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐   │   │
│  │  │    tmp    │  │  Caches   │  │ Preferences│   │   │
│  │  │  (读写)   │  │  (读写)   │  │  (读写)   │   │   │
│  │  └───────────┘  └───────────┘  └───────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  沙箱策略:                                              │
│  ├── 文件: 仅访问自身容器 + 用户授权的文件              │
│  ├── 网络: 允许（受 ATS 约束）                         │
│  ├── IPC: 限制为白名单服务                              │
│  ├── 设备: 限制为白名单设备类                           │
│  └── 系统调用: 过滤危险调用                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 3.2 沙箱策略解析

iOS 沙箱策略使用 SBPL (Sandbox Profile Language) 定义，这是一种基于 Scheme 的声明式语言。

```scheme
;; 典型第三方应用沙箱策略（简化版）
(version 1)
(deny default)                    ;; 默认拒绝所有操作

;; 文件访问
(allow file-read*
    (subpath "/private/var/mobile/Containers/Data/Application/<UUID>")
    (subpath "/private/var/mobile/Containers/Bundle/Application/<UUID>"))

(allow file-write*
    (subpath "/private/var/mobile/Containers/Data/Application/<UUID>")
    (subpath "/private/var/mobile/Containers/Data/Application/<UUID>/tmp")
    (subpath "/private/var/mobile/Containers/Data/Application/<UUID>/Library/Caches"))

;; 网络访问
(allow network*)                  ;; 允许所有网络连接（受 ATS 约束）

;; IPC 访问
(allow mach-lookup
    (global-name "com.apple.lsdsession")
    (global-name "com.apple.backboardd")
    ;; ... 白名单系统服务
)

;; 系统调用过滤
(allow process-exec)
(deny process-info*)              ;; 禁止查看其他进程信息
(deny signal (target others))     ;; 禁止向其他进程发送信号

;; 设备访问
(allow iokit-open
    (iokit-user-client-class "AGXCommandQueue")
    (iokit-user-client-class "AGXSharedUserClient")
    ;; GPU 相关用户客户端
)
```

### 3.3 沙箱逃逸攻击向量

| 攻击向量 | 描述 | 历史案例 | 防御状态 |
|----------|------|----------|----------|
| 内核漏洞 | 利用内核 bug 突破沙箱 | Pegasus (CVE-2016-4655) | 持续修补 |
| Mach 端口滥用 | 通过 Mach IPC 攻击系统服务 | 多个越狱工具使用 | iOS 14+ 大幅收紧 |
| IOKit 漏洞 | 利用设备驱动漏洞 | IOHIDFamily 漏洞 | 驱动隔离加强 |
| Entitlement 伪造 | 伪造 entitlement 获取特权 | 早期越狱使用 | AMFI 硬件验证 |
| 符号链接攻击 | 通过 symlink 访问沙箱外文件 | 早期 iOS 漏洞 | VFS 层防护 |

### 3.4 沙箱调试与分析

安全研究员可以使用以下工具分析沙箱策略：

```bash
# 提取应用沙箱策略
# 需要越狱设备
sandbox-exec -p '(version 1)(deny default)(allow default)' \
    /usr/libexec/sandboxd -c dump <pid>

# 使用 sandblaster 反编译沙箱配置
python sandblaster.py --decode sandbox.bin

# 运行时沙箱监控
log stream --predicate 'subsystem == "com.apple.sandbox"' --info

# 检查应用的 entitlement
codesign -d --entitlements :- /path/to/app.app/AppBinary
```

### 3.5 沙箱最佳实践

```swift
// 正确：使用系统 API 访问文件
class FileManager {
    func saveUserData(_ data: Data, filename: String) throws {
        let documentsURL = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask).first!
        let fileURL = documentsURL.appendingPathComponent(filename)
        
        // 设置文件保护级别
        try data.write(to: fileURL, options: .completeFileProtection)
        
        // 设置文件属性
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: fileURL.path
        )
    }
}
```

---

## 4. Entitlements 权限体系

### 4.1 Entitlement 机制概述

Entitlements 是嵌入在应用代码签名中的键值对，声明应用被允许使用的特定功能和服务。它们是 iOS 访问控制的核心机制之一。

```
┌─────────────────────────────────────────────────────────┐
│                Entitlement 验证流程                      │
│                                                         │
│  应用安装时:                                            │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐         │
│  │ 解析      │───→│ 验证签名 │───→│ 存储到   │         │
│  │ 二进制   │    │ 提取     │    │ 系统数据 │         │
│  └──────────┘    │ Entitle- │    │ 库       │         │
│                  │ ments    │    └──────────┘         │
│                  └──────────┘                          │
│                                                         │
│  运行时检查:                                            │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐         │
│  │ 应用请求 │───→│ 查询     │───→│ 返回权限 │         │
│  │ 特权操作 │    │ AMFI     │    │ 允许/拒绝│         │
│  └──────────┘    └──────────┘    └──────────┘         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 4.2 常见 Entitlement 分类

#### 4.2.1 系统服务 Entitlement

| Entitlement | 功能 | 审批要求 |
|-------------|------|----------|
| `com.apple.developer.applesignin` | Sign in with Apple | 无特殊要求 |
| `com.apple.developer.healthkit` | HealthKit 健康数据 | 需在 Info.plist 声明用途 |
| `com.apple.developer.homekit` | HomeKit 智能家居 | 无特殊要求 |
| `com.apple.developer.passkit` | Apple Pay / Wallet | 商家协议 |
| `com.apple.developer.siri` | Siri 集成 | 无特殊要求 |
| `com.apple.developer.associated-domains` | Associated Domains | 需域名验证 |
| `com.apple.developer.in-app-payments` | IAP 支付 | Apple 商家协议 |

#### 4.2.2 网络与通信 Entitlement

| Entitlement | 功能 | 安全风险 |
|-------------|------|----------|
| `com.apple.developer.networking.HotspotConfiguration` | 热点配置 | 中 |
| `com.apple.developer.networking.multipath` | Multipath TCP | 中 |
| `com.apple.developer.networking.wifi-info` | WiFi 信息 | 高 |
| `com.apple.developer.networking.vpn.api` | VPN 配置 | 高 |
| `com.apple.developer.networking.networkextension` | 网络扩展 | 严重 |

#### 4.2.3 受限 Entitlement（需 Apple 审批）

| Entitlement | 功能 | 限制原因 |
|-------------|------|----------|
| `com.apple.private.security.*` | 私有安全 API | 内部使用 |
| `com.apple.private.tcc.*` | TCC 权限管理 | 可绕过用户授权 |
| `com.apple.private.accounts.*` | 账户系统私有 API | 可访问所有账户 |
| `com.apple.private.keychain.*` | Keychain 私有 API | 可跨应用读取凭证 |
| `com.apple.springboard.*` | SpringBoard 控制 | 可控制主屏幕 |

### 4.3 Entitlement 安全审计

```bash
# 检查应用的 entitlement
codesign -d --entitlements :- MyApp.app/MyApp

# 输出示例
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>com.apple.developer.applesignin</key>
    <array><string>Default</string></array>
    <key>com.apple.developer.associated-domains</key>
    <array>
        <string>applinks:example.com</string>
        <string>webcredentials:example.com</string>
    </array>
    <key>com.apple.developer.healthkit</key>
    <true/>
    <key>keychain-access-groups</key>
    <array>
        <string>TEAMID.com.example.myapp</string>
        <string>TEAMID.com.example.shared</string>
    </array>
</dict>
</plist>
```

### 4.4 Entitlement 攻击与防御

| 攻击类型 | 描述 | 防御措施 |
|----------|------|----------|
| Entitlement 注入 | 修改二进制注入额外 entitlement | 代码签名验证、AMFI |
| 签名重放 | 使用旧签名绕过新限制 | 签名包含时间戳和 CDHash |
| Entitlement 嗅探 | 分析应用使用的 entitlement | 代码混淆、反调试 |
| 权限降级攻击 | 利用旧版 entitlement 获取特权 | 定期更新 entitlement 策略 |

---

## 5. Keychain 访问控制

### 5.1 Keychain 架构

Keychain 是 iOS 的安全凭证存储系统，使用硬件加密保护敏感数据。

```
┌─────────────────────────────────────────────────────────┐
│                  Keychain 架构                           │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Keychain Services API               │   │
│  │  SecItemAdd / SecItemCopyMatching / SecItemUpdate│   │
│  └─────────────────────────┬───────────────────────┘   │
│                            │                            │
│  ┌─────────────────────────┴───────────────────────┐   │
│  │              securityd 守护进程                   │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐   │   │
│  │  │ ACL 检查  │  │ 加密/解密 │  │ 同步管理  │   │   │
│  │  └───────────┘  └─────┬─────┘  └───────────┘   │   │
│  └───────────────────────┼─────────────────────────┘   │
│                          │                              │
│  ┌───────────────────────┴─────────────────────────┐   │
│  │          Keychain 数据库 (keychain-2.db)         │   │
│  │  ┌─────────────────────────────────────────┐    │   │
│  │  │ 加密数据 (AES-256-GCM)                  │    │   │
│  │  │ 密钥: Class Key (由 UID + Passcode 派生) │    │   │
│  │  └─────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Secure Enclave                      │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐   │   │
│  │  │ UID 密钥  │  │ 派生密钥  │  │ 生物识别  │   │   │
│  │  │ (不可导出)│  │ 生成引擎  │  │ 验证      │   │   │
│  │  └───────────┘  └───────────┘  └───────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 5.2 Keychain 访问控制列表 (ACL)

Keychain 条目通过 ACL (Access Control List) 控制哪些应用可以访问。

```swift
import Security

class KeychainAccessControl {
    
    enum Accessibility {
        case unlocked              // 设备解锁后可访问
        case unlockedThisDeviceOnly // 不迁移到新设备
        case unlockedAfterFirstAuth // 首次解锁后可访问
        case foreground            // 仅前台可访问
        case biometric             // 需要生物识别
    }
    
    static func createAccessControl(
        accessibility: Accessibility,
        requireBiometry: Bool = false
    ) -> SecAccessControl? {
        
        var protection: CFString
        
        switch accessibility {
        case .unlocked:
            protection = kSecAttrAccessibleWhenUnlocked
        case .unlockedThisDeviceOnly:
            protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .unlockedAfterFirstAuth:
            protection = kSecAttrAccessibleAfterFirstUnlock
        case .foreground:
            protection = kSecAttrAccessibleWhenUnlocked
        case .biometric:
            protection = kSecAttrAccessibleWhenUnlocked
        }
        
        var flags: SecAccessControlCreateFlags = []
        
        if requireBiometry {
            flags.insert(.userPresence)
            if #available(iOS 15.0, *) {
                flags.insert(.biometryCurrentSet)
            }
        }
        
        var error: Unmanaged<CFError>?
        return SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            protection,
            flags,
            &error
        )
    }
    
    // 存储敏感凭证（需要生物识别）
    static func storeBiometricProtected(
        account: String,
        service: String,
        data: Data
    ) -> Bool {
        
        guard let accessControl = createAccessControl(
            accessibility: .biometric,
            requireBiometry: true
        ) else { return false }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
            kSecAttrAccessGroup as String: nil
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}
```

### 5.3 Keychain 共享访问组

```
┌─────────────────────────────────────────────────────────┐
│            Keychain Access Group 架构                    │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   App A     │  │   App B     │  │   App C     │    │
│  │  Team: ABC  │  │  Team: ABC  │  │  Team: XYZ  │    │
│  │  Group:     │  │  Group:     │  │  Group:     │    │
│  │  com.shared │  │  com.shared │  │  com.other  │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │            │
│         ▼                ▼                ▼            │
│  ┌─────────────────────────────────────────────────┐   │
│  │           Keychain Access Groups                 │   │
│  │                                                  │   │
│  │  ┌──────────────────────────────────────────┐   │   │
│  │  │ ABC.com.shared                           │   │   │
│  │  │ ├── App A 可读写                         │   │   │
│  │  │ └── App B 可读写                         │   │   │
│  │  └──────────────────────────────────────────┘   │   │
│  │                                                  │   │
│  │  ┌──────────────────────────────────────────┐   │   │
│  │  │ XYZ.com.other                            │   │   │
│  │  │ └── App C 可读写                         │   │   │
│  │  └──────────────────────────────────────────┘   │   │
│  │                                                  │   │
│  │  注意: App C 无法访问 ABC.com.shared            │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

```swift
class SharedKeychain {
    
    static let accessGroup = "TEAMID.com.example.shared"
    
    static func writeShared(token: String) -> Bool {
        let data = token.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.auth",
            kSecAttrAccount as String: "auth_token",
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }
    
    static func readSharedToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.auth",
            kSecAttrAccount as String: "auth_token",
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
```

### 5.4 Keychain 攻击面分析

| 攻击类型 | 描述 | 风险等级 | 防御措施 |
|----------|------|----------|----------|
| Keychain 转储 | 越狱设备上提取所有 Keychain | 严重 | 使用生物识别保护 |
| 备份提取 | 从未加密备份提取 Keychain | 高 | 使用加密备份 |
| Access Group 配置错误 | 过于宽泛的共享组 | 中 | 最小化共享组范围 |
| 弱 Accessibility | 使用 `kSecAttrAccessibleAlways` | 中 | 使用更严格的保护级别 |
| 侧信道攻击 | 通过时序分析推断 Keychain 内容 | 低 | 恒定时间比较 |

### 5.5 Keychain 安全最佳实践

```swift
class SecureKeychainStore {
    
    // 1. 使用最严格的 Accessibility
    static let defaultAccessibility = 
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    
    // 2. 敏感数据使用生物识别保护
    static func storeSecret(_ secret: Data, label: String) throws {
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        ) else {
            throw KeychainError.accessControlCreationFailed
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.myapp.secrets",
            kSecAttrAccount as String: label,
            kSecValueData as String: secret,
            kSecAttrAccessControl as String: access,
            kSecAttrSynchronizable as String: false
        ]
        
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.addFailed(status)
        }
    }
    
    // 3. 应用卸载时清理 Keychain
    static func cleanupOnUninstall() {
        let secClasses = [
            kSecClassGenericPassword,
            kSecClassInternetPassword,
            kSecClassCertificate,
            kSecClassKey,
            kSecClassIdentity
        ]
        
        for secClass in secClasses {
            let query: [String: Any] = [kSecClass as String: secClass]
            SecItemDelete(query as CFDictionary)
        }
    }
}
```

---

## 6. Data Protection 文件加密体系

### 6.1 Data Protection 架构

iOS Data Protection 使用分层密钥体系加密文件系统中的数据。

```
┌─────────────────────────────────────────────────────────────┐
│                Data Protection 密钥层级                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Level 0: UID (Hardware Unique Key)                 │   │
│  │  ├── 256-bit AES 密钥                               │   │
│  │  ├── 烧录在 Secure Enclave 中                       │   │
│  │  ├── 不可导出、不可读取                             │   │
│  │  └── 每个设备唯一                                   │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                            │                                 │
│  ┌─────────────────────────┴───────────────────────────┐   │
│  │  Level 1: Passcode (用户密码)                        │   │
│  │  ├── PBKDF2 派生 (至少 10,000 轮)                   │   │
│  │  ├── 与 UID 结合生成 Master Key                     │   │
│  │  └── 可选：无密码时跳过                              │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                            │                                 │
│  ┌─────────────────────────┴───────────────────────────┐   │
│  │  Level 2: Class Keys (保护类密钥)                    │   │
│  │  ├── Complete: 设备锁定时不可访问                   │   │
│  │  ├── CompleteUnlessOpen: 已打开文件可继续写入       │   │
│  │  ├── CompleteUntilFirstUserAuthentication: 首次解锁后│   │
│  │  └── None: 始终可访问（不推荐）                     │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                            │                                 │
│  ┌─────────────────────────┴───────────────────────────┐   │
│  │  Level 3: Per-File Keys (每文件密钥)                 │   │
│  │  ├── 每个受保护文件生成唯一密钥                     │   │
│  │  ├── 使用 Class Key 加密 Per-File Key               │   │
│  │  └── 加密后的 Per-File Key 存储在文件元数据中       │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                            │                                 │
│  ┌─────────────────────────┴───────────────────────────┐   │
│  │  Level 4: File Content (文件内容)                    │   │
│  │  ├── 使用 Per-File Key 进行 AES-256-CBC 加密        │   │
│  │  ├── 或使用 AES-256-XTS (iOS 15+)                   │   │
│  │  └── 包含 HMAC 完整性校验                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 保护级别详解

| 保护级别 | 常量 | 密钥可用性 | 适用场景 |
|----------|------|------------|----------|
| **Complete** | `FileProtectionType.complete` | 仅当设备解锁 | 高度敏感数据（支付信息、医疗数据） |
| **CompleteUnlessOpen** | `FileProtectionType.completeUnlessOpen` | 解锁时读写，锁定时可继续写入已打开文件 | 下载中的大文件 |
| **CompleteUntilFirstUserAuthentication** | `FileProtectionType.completeUntilFirstUserAuthentication` | 首次解锁后直到重启 | 后台任务需要的数据（默认推荐） |
| **None** | `FileProtectionType.none` | 始终可用 | 不推荐，仅用于必须开机即访问的数据 |

### 6.3 文件保护实现

```swift
import Foundation

class DataProtectionManager {
    
    static func createProtectedFile(
        data: Data,
        filename: String,
        protection: FileProtectionType = .complete
    ) throws -> URL {
        
        let documentsURL = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask).first!
        let fileURL = documentsURL.appendingPathComponent(filename)
        
        try data.write(to: fileURL, options: .complete)
        
        try FileManager.default.setAttributes(
            [.protectionKey: protection],
            ofItemAtPath: fileURL.path
        )
        
        return fileURL
    }
    
    static func checkFileProtection(url: URL) -> FileProtectionType? {
        do {
            let attributes = try FileManager.default
                .attributesOfItem(atPath: url.path)
            return attributes[.protectionKey] as? FileProtectionType
        } catch {
            return nil
        }
    }
    
    // 批量审计目录中的文件保护
    static func auditDirectoryProtection(url: URL) -> [String: FileProtectionType?] {
        var results: [String: FileProtectionType?] = [:]
        
        let fileManager = FileManager.default
        guard let enumerator = fileManager.enumerator(at: url,
            includingPropertiesForKeys: [.fileProtectionKey]) else {
            return results
        }
        
        while let fileURL = enumerator.nextObject() as? URL {
            let protection = checkFileProtection(url: fileURL)
            results[fileURL.lastPathComponent] = protection
        }
        
        return results
    }
    
    // 确保敏感文件使用正确的保护级别
    static func enforceProtectionPolicy(directory: URL) throws {
        let sensitiveExtensions = ["key", "pem", "p12", "db", "sqlite"]
        
        let fileManager = FileManager.default
        guard let enumerator = fileManager.enumerator(at: directory,
            includingPropertiesForKeys: [.fileProtectionKey]) else {
            return
        }
        
        while let fileURL = enumerator.nextObject() as? URL {
            let ext = fileURL.pathExtension.lowercased()
            if sensitiveExtensions.contains(ext) {
                let current = checkFileProtection(url: fileURL)
                if current != .complete && current != .completeUntilFirstUserAuthentication {
                    try fileManager.setAttributes(
                        [.protectionKey: FileProtectionType.complete],
                        ofItemAtPath: fileURL.path
                    )
                }
            }
        }
    }
}
```

### 6.4 Data Protection 攻击向量

| 攻击类型 | 描述 | 前提条件 | 防御 |
|----------|------|----------|------|
| 冷启动攻击 | 设备断电后从 RAM 提取密钥 | 物理访问、专业设备 | 设备加密、Secure Enclave |
| 备份提取 | 从未加密 iTunes 备份提取 | 本地备份访问 | 使用加密备份 |
| 越狱后提取 | 越狱设备上直接读取密钥 | 越狱设备 | 无法防御（密钥在内存中） |
| DMA 攻击 | 直接内存访问提取密钥 | 物理访问、特定硬件 | Apple Silicon 防护 |

---

## 7. App Sandbox 文件系统隔离

### 7.1 应用容器结构

每个 iOS 应用运行在独立的容器中，容器定义了应用可以访问的文件系统范围。

```
/var/mobile/Containers/
├── Bundle/Application/
│   └── <UUID-A>/                    # App A 的安装目录
│       └── MyApp.app/
│           ├── MyApp                # 可执行文件
│           ├── Info.plist
│           ├── Frameworks/
│           └── ...                  # 只读，代码签名保护
│
├── Data/Application/
│   └── <UUID-A>/                    # App A 的数据目录
│       ├── Documents/               # 用户数据，iTunes 可见
│       ├── Library/
│       │   ├── Caches/              # 缓存，可被系统清理
│       │   ├── Preferences/         # 偏好设置
│       │   ├── Cookies/             # HTTP Cookies
│       │   └── Application Support/ # 应用支持文件
│       └── tmp/                     # 临时文件
│
├── Group/Container/
│   └── group.com.example.shared/    # App Group 共享容器
│       ├── Documents/
│       ├── Library/
│       └── tmp/
│
└── SystemData/                      # 系统数据
```

### 7.2 文件系统访问规则

| 路径 | 读权限 | 写权限 | 说明 |
|------|--------|--------|------|
| 自身 Bundle | 允许 | 禁止 | 代码签名保护，只读 |
| 自身 Data 容器 | 允许 | 允许 | 完全读写 |
| 其他应用容器 | 禁止 | 禁止 | 沙箱严格隔离 |
| 系统目录 | 部分 | 禁止 | 仅允许读取特定公共目录 |
| 共享 Group 容器 | 允许 | 允许 | 同一 App Group 的应用可访问 |
| 用户照片 | 需授权 | 需授权 | 通过 Photos framework |
| 通讯录 | 需授权 | 需授权 | 通过 Contacts framework |

### 7.3 文件 URL 安全处理

```swift
// 防止路径遍历攻击
class PathTraversalGuard {
    
    enum PathError: Error {
        case traversalDetected
        case invalidPath
        case outsideSandbox
    }
    
    static func sanitizeFilename(_ filename: String) throws -> String {
        let cleaned = filename
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "\\", with: "_")
        
        let noTraversal = cleaned
            .replacingOccurrences(of: "..", with: "")
        
        let noNull = noTraversal
            .replacingOccurrences(of: "\0", with: "")
        
        guard noNull.count <= 255 else {
            throw PathError.invalidPath
        }
        
        guard !noNull.isEmpty else {
            throw PathError.invalidPath
        }
        
        return noNull
    }
    
    static func resolvePath(
        userInput: String,
        baseDirectory: URL
    ) throws -> URL {
        let sanitized = try sanitizeFilename(userInput)
        let resolvedURL = baseDirectory.appendingPathComponent(sanitized)
        let standardized = resolvedURL.standardizedFileURL
        
        guard standardized.path.hasPrefix(baseDirectory.standardizedFileURL.path) else {
            throw PathError.traversalDetected
        }
        
        return standardized
    }
}
```

---

## 8. URL Scheme 与 Inter-App 通信

### 8.1 URL Scheme 机制

iOS 应用可以通过自定义 URL Scheme 相互通信。

```
┌─────────────────────────────────────────────────────────┐
│              URL Scheme 通信流程                         │
│                                                         │
│  ┌──────────┐                    ┌──────────┐          │
│  │  App A   │                    │  App B   │          │
│  │          │                    │          │          │
│  │ 调用:    │                    │          │          │
│  │ openURL  │                    │          │          │
│  └────┬─────┘                    └────┬─────┘          │
│       │                               │                │
│       │  myapp://action?param=value   │                │
│       │ ─────────────────────────────→│                │
│       │                               │                │
│       │                    ┌──────────┤                │
│       │                    │ 1. 验证  │                │
│       │                    │ Scheme  │                │
│       │                    │ 已注册  │                │
│       │                    └────┬─────┘                │
│       │                         │                      │
│       │                    ┌────┴─────┐                │
│       │                    │ 2. 调用  │                │
│       │                    │ AppDelegate│              │
│       │                    │ .openURL │                │
│       │                    └────┬─────┘                │
│       │                         │                      │
│       │                    ┌────┴─────┐                │
│       │                    │ 3. 处理  │                │
│       │                    │ 请求并   │                │
│       │                    │ 返回结果 │                │
│       │                    └──────────┘                │
│       │                               │                │
│       │  回调: callback://result      │                │
│       │ ←─────────────────────────────│                │
│       │                               │                │
└─────────────────────────────────────────────────────────┘
```

### 8.2 URL Scheme 安全配置

```xml
<!-- Info.plist: 声明应用支持的 URL Scheme -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>com.example.myapp</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
            <string>myapp-v2</string>
        </array>
    </dict>
</array>

<!-- Info.plist: 声明允许查询的 Scheme（iOS 9+） -->
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>wechat</string>
    <string>alipay</string>
    <string>myapp-other</string>
</array>
```

### 8.3 URL Scheme 安全处理

```swift
import UIKit

class SecureURLSchemeHandler: NSObject, UIApplicationDelegate {
    
    // 已注册的处理命令白名单
    private let allowedCommands: Set<String> = [
        "open", "share", "payment", "callback"
    ]
    
    // 已注册的可回调域名白名单
    private let allowedCallbackHosts: Set<String> = [
        "myapp.com", "auth.myapp.com"
    ]
    
    func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    ) -> Bool {
        
        // 1. 验证 URL 格式
        guard let scheme = url.scheme?.lowercased(),
              scheme == "myapp" else {
            return false
        }
        
        // 2. 验证来源应用（iOS 9+）
        if let sourceApp = options[.sourceApplication] as? String {
            guard isTrustedSourceApp(sourceApp) else {
                return false
            }
        }
        
        // 3. 解析和验证命令
        guard let host = url.host?.lowercased(),
              allowedCommands.contains(host) else {
            return false
        }
        
        // 4. 验证参数
        guard validateParameters(url: url, command: host) else {
            return false
        }
        
        // 5. 处理命令
        return handleCommand(url: url, command: host, options: options)
    }
    
    private func isTrustedSourceApp(_ bundleId: String) -> Bool {
        let trustedApps: Set<String> = [
            "com.apple.mobilesafari",
            "com.google.chrome.ios",
            "com.tencent.xin",
            "com.alipay.iphoneclient"
        ]
        return trustedApps.contains(bundleId)
    }
    
    private func validateParameters(url: URL, command: String) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        
        for item in components.queryItems ?? [] {
            guard let value = item.value else { continue }
            
            // 检查 SQL 注入模式
            let sqlPatterns = ["'", "\"", ";", "--", "/*", "*/"]
            for pattern in sqlPatterns {
                if value.contains(pattern) { return false }
            }
            
            // 检查 XSS 模式
            let xssPatterns = ["<script", "javascript:", "onerror=", "onload="]
            for pattern in xssPatterns {
                if value.lowercased().contains(pattern) { return false }
            }
            
            // 检查路径遍历
            if value.contains("..") || value.contains("/etc/") || value.contains("/var/") {
                return false
            }
            
            // 检查回调 URL 安全性
            if item.name == "callback" || item.name == "redirect_uri" {
                guard let callbackURL = URL(string: value),
                      let host = callbackURL.host,
                      allowedCallbackHosts.contains(host) else {
                    return false
                }
            }
        }
        
        return true
    }
    
    private func handleCommand(
        url: URL,
        command: String,
        options: [UIApplication.OpenURLOptionsKey: Any]
    ) -> Bool {
        switch command {
        case "open": return handleOpenCommand(url: url)
        case "share": return true
        case "payment": return true
        case "callback": return true
        default: return false
        }
    }
    
    private func handleOpenCommand(url: URL) -> Bool { return true }
}
```

### 8.4 URL Scheme 劫持防御

```swift
class URLSchemeHijackDefense {
    
    // 推荐：使用 Universal Links 替代 URL Scheme
    static func openWithUniversalLink(
        universalLink: URL,
        fallbackScheme: URL,
        completion: @escaping (Bool) -> Void
    ) {
        UIApplication.shared.open(universalLink, options: [:]) { success in
            if success {
                completion(true)
            } else {
                UIApplication.shared.open(fallbackScheme, options: [:], completion: completion)
            }
        }
    }
}
```

---

## 9. Universal Links 安全机制

### 9.1 Universal Links 架构

Universal Links 使用标准 HTTPS 链接打开应用，解决了 URL Scheme 的安全问题。

```
┌─────────────────────────────────────────────────────────┐
│            Universal Links 验证流程                      │
│                                                         │
│  应用安装时:                                            │
│  ┌──────────┐         ┌──────────┐         ┌────────┐ │
│  │ iOS 系统 │         │ Apple CDN│         │ 开发者 │ │
│  └────┬─────┘         └────┬─────┘         └───┬────┘ │
│       │                    │                    │      │
│       │  请求 AASA 文件    │                    │      │
│       │ ──────────────────→│                    │      │
│       │                    │  缓存 AASA         │      │
│       │ ←──────────────────│                    │      │
│       │                    │                    │      │
│       │  上传 AASA 到网站  │                    │      │
│       │                    │ ←──────────────────│      │
│       │                    │                    │      │
│  用户点击链接时:                                        │
│  ┌──────────┐         ┌──────────┐         ┌────────┐ │
│  │ Safari/  │         │ iOS 系统 │         │  App   │ │
│  │ 其他应用 │         │          │         │        │ │
│  └────┬─────┘         └────┬─────┘         └───┬────┘ │
│       │                    │                    │      │
│       │  点击 https://     │                    │      │
│       │  example.com/path  │                    │      │
│       │ ──────────────────→│                    │      │
│       │                    │                    │      │
│       │                    │  检查 AASA:        │      │
│       │                    │  - 域名匹配        │      │
│       │                    │  - App ID 匹配     │      │
│       │                    │  - 路径匹配        │      │
│       │                    │                    │      │
│       │                    │  匹配成功          │      │
│       │                    │ ──────────────────→│      │
│       │                    │                    │      │
│       │                    │  打开应用          │      │
│       │ ←──────────────────│                    │      │
│       │                    │                    │      │
└─────────────────────────────────────────────────────────┘
```

### 9.2 AASA 文件配置

```json
// apple-app-site-association (放在 https://example.com/.well-known/)
{
    "applinks": {
        "details": [
            {
                "appIDs": [
                    "TEAMID.com.example.myapp",
                    "TEAMID.com.example.myapp.enterprise"
                ],
                "components": [
                    {
                        "/": "/products/*",
                        "comment": "匹配所有产品页面"
                    },
                    {
                        "/": "/users/*/profile",
                        "comment": "匹配用户资料页"
                    },
                    {
                        "/": "/orders/*",
                        "exclude": true,
                        "comment": "排除订单页（敏感数据）"
                    },
                    {
                        "/": "/auth/*",
                        "comment": "认证相关页面"
                    }
                ]
            }
        ]
    },
    "webcredentials": {
        "apps": [
            "TEAMID.com.example.myapp"
        ]
    },
    "appclips": {
        "apps": [
            "TEAMID.com.example.myapp.Clip"
        ]
    }
}
```

### 9.3 Universal Links 安全处理

```swift
import UIKit

class UniversalLinkHandler {
    
    struct DomainConfig {
        let domain: String
        let allowedPaths: [String]
        let excludedPaths: [String]
        let requireAuth: Bool
    }
    
    private let configs: [DomainConfig] = [
        DomainConfig(
            domain: "example.com",
            allowedPaths: ["/products/*", "/users/*/profile", "/auth/*"],
            excludedPaths: ["/orders/*", "/admin/*"],
            requireAuth: false
        ),
        DomainConfig(
            domain: "secure.example.com",
            allowedPaths: ["/account/*", "/settings/*"],
            excludedPaths: [],
            requireAuth: true
        )
    ]
    
    func handleUniversalLink(url: URL) -> Bool {
        guard let host = url.host?.lowercased(),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" else {
            return false
        }
        
        guard let config = configs.first(where: { $0.domain == host }) else {
            return false
        }
        
        let path = url.path
        guard isValidPath(path, config: config) else {
            return false
        }
        
        if config.requireAuth {
            guard isAuthenticated() else {
                savePendingURL(url)
                requestAuthentication()
                return true
            }
        }
        
        return routeToPage(url: url, config: config)
    }
    
    private func isValidPath(_ path: String, config: DomainConfig) -> Bool {
        for excluded in config.excludedPaths {
            if matchPath(path, pattern: excluded) { return false }
        }
        for allowed in config.allowedPaths {
            if matchPath(path, pattern: allowed) { return true }
        }
        return false
    }
    
    private func matchPath(_ path: String, pattern: String) -> Bool {
        let regexPattern = pattern
            .replacingOccurrences(of: "*", with: "[^/]+")
        guard let regex = try? NSRegularExpression(pattern: "^" + regexPattern + "$") else {
            return false
        }
        let range = NSRange(path.startIndex..., in: path)
        return regex.firstMatch(in: path, range: range) != nil
    }
    
    private func isAuthenticated() -> Bool { return true }
    private func savePendingURL(_ url: URL) { }
    private func requestAuthentication() { }
    private func routeToPage(url: URL, config: DomainConfig) -> Bool { return true }
}
```

### 9.4 Universal Links vs URL Scheme 安全对比

| 安全特性 | URL Scheme | Universal Links |
|----------|------------|-----------------|
| 劫持风险 | 高 | 低 |
| 传输安全 | 不适用 | HTTPS 加密 |
| 域名验证 | 无 | 必须验证 AASA 文件 |
| 回退行为 | 无应用响应时静默失败 | 自动在浏览器打开 |
| 用户确认 | 首次需要确认 | 无需确认 |
| 推荐度 | 不推荐（仅兼容旧版） | 推荐 |

---

## 10. App Groups 共享数据访问控制

### 10.1 App Groups 架构

App Groups 允许同一开发者的多个应用（包括 Extension）共享数据。

```
┌─────────────────────────────────────────────────────────┐
│              App Groups 共享架构                         │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Main App  │  │  Extension  │  │  Watch App  │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │            │
│         └────────────────┼────────────────┘            │
│                          │                             │
│                          ▼                             │
│  ┌─────────────────────────────────────────────────┐   │
│  │         Shared Container                        │   │
│  │         group.com.example.myapp                 │   │
│  │                                                  │   │
│  │  /var/mobile/Containers/Shared/Group/           │   │
│  │  └── <UUID>/                                    │   │
│  │      ├── Documents/          (共享文件)          │   │
│  │      ├── Library/            (共享库数据)        │   │
│  │      │   ├── Caches/                            │   │
│  │      │   ├── Preferences/    (共享偏好)          │   │
│  │      │   └── Application Support/               │   │
│  │      └── tmp/                (临时文件)          │   │
│  │                                                  │   │
│  │  共享 Keychain:                                 │   │
│  │  └── keychain-access-groups:                    │   │
│  │      └── TEAMID.group.com.example.myapp         │   │
│  │                                                  │   │
│  │  共享 UserDefaults:                             │   │
│  │  └── UserDefaults(suiteName: "group.com...")    │   │
│  │                                                  │   │
│  │  共享 Darwin 通知:                              │   │
│  │  └── CFNotificationCenterGetDarwinNotifyCenter()│   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 10.2 安全共享数据实现

```swift
import Foundation

class SecureAppGroupSharing {
    
    let groupIdentifier = "group.com.example.myapp"
    
    lazy var sharedDefaults: UserDefaults? = {
        UserDefaults(suiteName: groupIdentifier)
    }()
    
    // 安全写入共享数据
    func writeSharedValue(_ value: Any, forKey key: String) {
        guard let defaults = sharedDefaults else { return }
        guard isValidSharedKey(key) else { return }
        
        let valueToStore: Any
        if isSensitiveKey(key), let data = value as? Data {
            valueToStore = encryptData(data) ?? data
        } else {
            valueToStore = value
        }
        
        defaults.set(valueToStore, forKey: key)
        defaults.synchronize()
        postDarwinNotification(key)
    }
    
    // 安全读取共享数据
    func readSharedValue<T>(forKey key: String) -> T? {
        guard let defaults = sharedDefaults else { return nil }
        guard isValidSharedKey(key) else { return nil }
        
        guard let value = defaults.value(forKey: key) else { return nil }
        
        if isSensitiveKey(key), let data = value as? Data {
            return decryptData(data) as? T
        }
        return value as? T
    }
    
    // Darwin 通知
    func postDarwinNotification(_ name: String) {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let notificationName = "\(groupIdentifier).\(name)" as CFString
        CFNotificationCenterPostNotification(
            center,
            CFNotificationName(notificationName),
            nil, nil, true
        )
    }
    
    private let allowedSharedKeys: Set<String> = [
        "user_preferences", "app_state", "sync_token", "last_update"
    ]
    
    private let sensitiveKeys: Set<String> = ["sync_token", "auth_token"]
    
    private func isValidSharedKey(_ key: String) -> Bool {
        return allowedSharedKeys.contains(key)
    }
    
    private func isSensitiveKey(_ key: String) -> Bool {
        return sensitiveKeys.contains(key)
    }
    
    private func encryptData(_ data: Data) -> Data? { return data }
    private func decryptData(_ data: Data) -> Data? { return data }
}
```

### 10.3 App Groups 安全审计清单

| 检查项 | 风险 | 建议 |
|--------|------|------|
| 共享容器权限范围 | 中 | 最小化共享数据范围 |
| 敏感数据明文存储 | 高 | 加密后再存储到共享容器 |
| Darwin 通知未验证来源 | 中 | 验证通知来源 |
| 共享 Keychain 组过大 | 中 | 使用细粒度 Keychain 组 |
| 共享文件无保护 | 中 | 使用 Data Protection |
| 并发访问冲突 | 低 | 使用文件锁或 NSFileCoordinator |

---

## 11. Pasteboard 剪贴板访问限制

### 11.1 Pasteboard 安全模型

iOS 剪贴板是应用间数据共享的便捷方式，但也带来隐私风险。

```
┌─────────────────────────────────────────────────────────┐
│              Pasteboard 安全模型                         │
│                                                         │
│  ┌─────────────┐                    ┌─────────────┐    │
│  │   App A     │                    │   App B     │    │
│  │  (复制数据) │                    │  (粘贴数据) │    │
│  └──────┬──────┘                    └──────┬──────┘    │
│         │                                   │          │
│         │  UIPasteboard.general             │          │
│         │  .setItems(...)                   │          │
│         │ ─────────────────────────────────→│          │
│         │                                   │          │
│  ┌──────┴───────────────────────────────────┴──────┐   │
│  │              Pasteboard 服务                     │   │
│  │                                                  │   │
│  │  安全策略:                                       │   │
│  │  - 首次读取时显示通知（iOS 14+）                 │   │
│  │  - 检测粘贴来源是否同应用                        │   │
│  │  - 支持 expirationDate 自动过期                  │   │
│  │  - 支持 localOnly 限制                           │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  iOS 14+ 隐私保护:                                      │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 当应用首次读取剪贴板时:                          │   │
│  │                                                  │   │
│  │  ┌─────────────────────────────────────────┐    │   │
│  │  │  "App" 粘贴自 "Other App"               │    │   │
│  │  │  [允许粘贴]  [拒绝]                      │    │   │
│  │  └─────────────────────────────────────────┘    │   │
│  │                                                  │   │
│  │  后续粘贴不再提示（同一会话内）                  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 11.2 安全剪贴板操作

```swift
import UIKit
import UniformTypeIdentifiers

class SecurePasteboard {
    
    static func copyToPasteboard(
        data: Any,
        expirationDate: Date? = nil,
        localOnly: Bool = true
    ) {
        let pasteboard = UIPasteboard.general
        
        var items: [[String: Any]] = []
        
        if let string = data as? String {
            items.append([UTType.utf8PlainText.identifier: string])
        } else if let url = data as? URL {
            items.append([UTType.url.identifier: url.absoluteString])
        } else if let image = data as? UIImage {
            items.append([UTType.png.identifier: image])
        }
        
        guard !items.isEmpty else { return }
        
        var options: [UIPasteboard.OptionsKey: Any] = [:]
        if let expirationDate = expirationDate {
            options[.expirationDate] = expirationDate
        }
        if localOnly {
            options[.localOnly] = true
        }
        
        pasteboard.setItems(items, options: options)
    }
    
    static func clearPasteboard() {
        UIPasteboard.general.items = []
    }
    
    // 监控剪贴板访问
    class PasteboardAccessMonitor {
        
        static func startMonitoring() {
            NotificationCenter.default.addObserver(
                forName: UIApplication.willResignActiveNotification,
                object: nil,
                queue: .main
            ) { _ in
                auditPasteboardOnBackground()
            }
        }
        
        private static func auditPasteboardOnBackground() {
            let pasteboard = UIPasteboard.general
            
            if let string = pasteboard.string {
                if containsSensitiveData(string) {
                    clearPasteboard()
                }
            }
        }
        
        private static func containsSensitiveData(_ string: String) -> Bool {
            let creditCardPattern = "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
            if let regex = try? NSRegularExpression(pattern: creditCardPattern),
               regex.firstMatch(in: string, range: NSRange(string.startIndex..., in: string)) != nil {
                return true
            }
            
            let idCardPattern = "\\b\\d{17}[\\dXx]\\b"
            if let regex = try? NSRegularExpression(pattern: idCardPattern),
               regex.firstMatch(in: string, range: NSRange(string.startIndex..., in: string)) != nil {
                return true
            }
            
            if string.contains("BEGIN PRIVATE KEY") || string.contains("BEGIN RSA PRIVATE KEY") {
                return true
            }
            
            return false
        }
    }
}
```

### 11.3 Pasteboard 安全最佳实践

| 实践 | 说明 | 优先级 |
|------|------|--------|
| 设置过期时间 | 敏感数据应设置短过期时间 | 高 |
| 使用 localOnly | 防止跨设备同步 | 高 |
| 避免存储密码 | 密码不应进入剪贴板 | 严重 |
| 后台前清除 | 应用进入后台前清除敏感内容 | 高 |
| 检测敏感模式 | 监控剪贴板中的敏感数据模式 | 中 |

---

## 12. 后台任务与交互限制

### 12.1 后台执行模型

iOS 对后台应用有严格的限制，以保护用户隐私和电池寿命。

```
┌─────────────────────────────────────────────────────────┐
│              iOS 后台执行模型                            │
│                                                         │
│  应用状态:                                              │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌────────┐│
│  │ Not     │-->│Inactive │-->│ Active  │-->│Back-   ││
│  │Running  │   │         │   │         │   │ground  ││
│  └─────────┘   └─────────┘   └─────────┘   └───┬────┘│
│                                                  │     │
│                                              ┌───┴────┐│
│                                              │Suspend-││
│                                              │ ed     ││
│                                              └────────┘│
│                                                         │
│  后台执行权限:                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 模式                    │ 时长限制    │ 需要声明 │   │
│  ├─────────────────────────┼─────────────┼─────────┤   │
│  │ Audio                   │ 无限制      │ 是      │   │
│  │ Location                │ 无限制      │ 是      │   │
│  │ VoIP                    │ 无限制      │ 是      │   │
│  │ External Accessory      │ 无限制      │ 是      │   │
│  │ Background Fetch        │ ~30秒/次    │ 是      │   │
│  │ Remote Notifications    │ ~30秒/次    │ 是      │   │
│  │ Background Processing   │ 分钟级      │ 是      │   │
│  │ Short-Lived Tasks       │ ~30秒       │ 否      │   │
│  │ Task Completion         │ ~30秒       │ 否      │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  后台数据访问限制:                                      │
│  ├── 网络: 受限（系统调度）                             │
│  ├── 位置: 需要 Always 授权                            │
│  ├── 传感器: 大部分暂停                                 │
│  ├── 文件: 可访问自身容器                              │
│  └── Keychain: 受 Data Protection 限制                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 12.2 后台任务安全实现

```swift
import UIKit
import BackgroundTasks

class SecureBackgroundTaskManager {
    
    static let shared = SecureBackgroundTaskManager()
    
    func registerBackgroundTasks() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "com.example.myapp.refresh",
            using: nil
        ) { task in
            self.handleBackgroundRefresh(task: task as! BGAppRefreshTask)
        }
        
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "com.example.myapp.processing",
            using: nil
        ) { task in
            self.handleBackgroundProcessing(task: task as! BGProcessingTask)
        }
    }
    
    func scheduleBackgroundRefresh() {
        let request = BGAppRefreshTaskRequest(
            identifier: "com.example.myapp.refresh"
        )
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            print("Failed to schedule: \(error)")
        }
    }
    
    func scheduleBackgroundProcessing(
        requiresNetworkConnectivity: Bool = true,
        requiresExternalPower: Bool = false
    ) {
        let request = BGProcessingTaskRequest(
            identifier: "com.example.myapp.processing"
        )
        request.earliestBeginDate = Date(timeIntervalSinceNow: 60 * 60)
        request.requiresNetworkConnectivity = requiresNetworkConnectivity
        request.requiresExternalPower = requiresExternalPower
        
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            print("Failed to schedule: \(error)")
        }
    }
    
    private func handleBackgroundRefresh(task: BGAppRefreshTask) {
        scheduleBackgroundRefresh()
        
        let operation = BackgroundRefreshOperation()
        
        task.expirationHandler = {
            operation.cancel()
        }
        
        operation.completionBlock = {
            task.setTaskCompleted(success: !operation.isCancelled)
        }
        
        OperationQueue.main.addOperation(operation)
    }
    
    private func handleBackgroundProcessing(task: BGProcessingTask) {
        let operation = BackgroundProcessingOperation()
        
        task.expirationHandler = {
            operation.cancel()
        }
        
        operation.completionBlock = {
            task.setTaskCompleted(success: !operation.isCancelled)
        }
        
        OperationQueue.main.addOperation(operation)
    }
}

class BackgroundRefreshOperation: Operation {
    override func main() {
        if isCancelled { return }
        
        // 检查 Data Protection 状态
        let isProtectedDataAvailable = UIApplication.shared
            .isProtectedDataAvailable
        
        guard isProtectedDataAvailable else {
            return
        }
    }
}

class BackgroundProcessingOperation: Operation {
    override func main() {
        if isCancelled { return }
    }
}
```

### 12.3 后台任务安全审计

| 检查项 | 风险 | 建议 |
|--------|------|------|
| 后台传输敏感数据 | 高 | 确保使用加密连接 |
| 后台访问锁定后不可用文件 | 中 | 检查 `isProtectedDataAvailable` |
| 未声明的后台模式 | 低 | 使用正确的 Background Mode |
| 后台位置追踪 | 高 | 明确告知用户，提供关闭选项 |
| 后台音频滥用 | 中 | 仅在确实需要时使用 |
| 未处理任务过期 | 低 | 实现 `expirationHandler` |

---

## 13. 通知与推送交互控制

### 13.1 推送通知安全架构

```
┌─────────────────────────────────────────────────────────┐
│              推送通知安全架构                            │
│                                                         │
│  ┌──────────┐         ┌──────────┐         ┌────────┐ │
│  │  Provider│         │  APNs    │         │  App   │ │
│  │  Server  │         │  (Apple) │         │        │ │
│  └────┬─────┘         └────┬─────┘         └───┬────┘ │
│       │                    │                    │      │
│       │  1. 建立连接       │                    │      │
│       │  (TLS + JWT/P12)   │                    │      │
│       │ ──────────────────→│                    │      │
│       │                    │                    │      │
│       │                    │    2. 注册设备      │      │
│       │                    │ ←──────────────────│      │
│       │                    │    (Device Token)   │      │
│       │                    │ ──────────────────→│      │
│       │                    │                    │      │
│       │  3. 发送推送       │                    │      │
│       │ ──────────────────→│                    │      │
│       │                    │                    │      │
│       │                    │  4. 验证并转发     │      │
│       │                    │ ──────────────────→│      │
│       │                    │                    │      │
│  安全机制:                                                │
│  ├── Provider 认证: JWT (p8) 或证书 (p12)               │
│  ├── 传输加密: TLS 1.2+                                  │
│  ├── Device Token: 与应用/设备绑定，不可导出             │
│  ├── 内容加密: 端到端（可选）                            │
│  └── 通知内容: 不应包含敏感信息（通知栏可见）            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 13.2 安全推送处理

```swift
import UIKit
import UserNotifications

class SecureNotificationHandler: NSObject, UNUserNotificationCenterDelegate {
    
    func registerForPushNotifications() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            guard granted else { return }
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }
    
    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        let token = deviceToken.map { String(format: "%02.2hhx", $0) }.joined()
        sendTokenToServer(token: token)
    }
    
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        guard isValidNotification(notification) else {
            completionHandler([])
            return
        }
        completionHandler([.banner, .sound])
    }
    
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        
        guard validatePayload(userInfo) else {
            completionHandler()
            return
        }
        
        handleAction(response: response)
        completionHandler()
    }
    
    private func isValidNotification(_ notification: UNNotification) -> Bool {
        return true
    }
    
    private func validatePayload(_ userInfo: [AnyHashable: Any]) -> Bool {
        if let url = userInfo["url"] as? String {
            guard let parsedURL = URL(string: url),
                  parsedURL.scheme == "https" else {
                return false
            }
        }
        
        if let deepLink = userInfo["deep_link"] as? String {
            guard !deepLink.contains("..") else {
                return false
            }
        }
        
        return true
    }
    
    private func sendTokenToServer(token: String) { }
    private func handleAction(response: UNNotificationResponse) { }
}
```

---

## 14. Accessibility API 交互限制

### 14.1 Accessibility 安全模型

Accessibility API 功能强大，可以读取和操作其他应用的 UI，因此受到严格限制。

```
┌─────────────────────────────────────────────────────────┐
│          Accessibility 安全模型                          │
│                                                         │
│  ┌─────────────┐                    ┌─────────────┐    │
│  │  App A      │                    │  App B      │    │
│  │  (辅助功能  │                    │  (目标应用) │    │
│  │   应用)     │                    │             │    │
│  └──────┬──────┘                    └──────┬──────┘    │
│         │                                   │          │
│         │  AXUIElement                      │          │
│         │  ─────────────────────────────────→│          │
│         │                                   │          │
│         │  可以:                            │          │
│         │  ├── 读取 UI 元素属性             │          │
│         │  ├── 模拟点击/输入                │          │
│         │  ├── 获取屏幕内容                 │          │
│         │  └── 操作其他应用                 │          │
│         │                                   │          │
│  ┌──────┴───────────────────────────────────┴──────┐   │
│  │              安全限制                            │   │
│  │                                                  │   │
│  │  1. 需要用户明确授权（设置 -> 辅助功能）         │   │
│  │  2. 状态栏显示蓝色指示器                        │   │
│  │  3. 不能访问密码字段                            │   │
│  │  4. 不能访问其他应用的沙箱数据                  │   │
│  │  5. 企业分发应用需要 MDM 配置                   │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  攻击风险:                                              │
│  ├── 恶意辅助功能应用窃取屏幕内容                      │
│  ├── 模拟用户操作进行欺诈                              │
│  ├── 读取敏感 UI 元素（银行卡号等）                    │
│  └── 与恶意服务器通信上传数据                          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 14.2 Accessibility 安全使用

```swift
import UIKit

class AccessibilitySecurityManager {
    
    static func isAccessibilityEnabled() -> Bool {
        return UIAccessibility.isVoiceOverRunning ||
               UIAccessibility.isSwitchControlRunning ||
               UIAccessibility.isSpeakScreenEnabled
    }
    
    static func configureAccessibilityLabels(
        view: UIView,
        label: String,
        isSensitive: Bool = false
    ) {
        view.isAccessibilityElement = true
        view.accessibilityLabel = label
        
        if isSensitive {
            view.accessibilityValue = "敏感信息，请谨慎操作"
        }
    }
    
    static func secureTextField(
        _ textField: UITextField,
        accessibilityLabel: String
    ) {
        textField.isSecureTextEntry = true
        textField.accessibilityLabel = accessibilityLabel
        textField.accessibilityValue = nil
        textField.textContentType = nil
    }
}

class AntiAccessibilityAbuse {
    
    static func detectAbnormalUIInteraction(
        touchLocation: CGPoint,
        timestamp: TimeInterval
    ) {
        if isSuspicious(touchLocation: touchLocation, timestamp: timestamp) {
            triggerVerification()
        }
    }
    
    private static func isSuspicious(
        touchLocation: CGPoint,
        timestamp: TimeInterval
    ) -> Bool {
        return false
    }
    
    private static func triggerVerification() { }
}
```

### 14.3 Accessibility 安全审计清单

| 检查项 | 风险 | 建议 |
|--------|------|------|
| 敏感数据作为 accessibilityLabel | 高 | 使用通用描述而非实际值 |
| 密码字段暴露 accessibilityValue | 严重 | 设为 nil |
| 未检测辅助功能状态 | 中 | 根据状态调整安全策略 |
| 未监控异常 UI 操作 | 中 | 实现自动化检测 |
| 敏感操作无二次验证 | 高 | 支付等操作需要生物识别 |

---

## 15. App Extension 安全架构

### 15.1 Extension 类型与安全模型

```
┌─────────────────────────────────────────────────────────┐
│            App Extension 安全架构                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Containing App                     │   │
│  │                                                  │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐   │   │
│  │  │ Extension │  │ Extension │  │ Extension │   │   │
│  │  │ (Today)   │  │ (Share)   │  │ (Action)  │   │   │
│  │  │           │  │           │  │           │   │   │
│  │  │ 独立沙箱  │  │ 独立沙箱  │  │ 独立沙箱  │   │   │
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘   │   │
│  │        │              │              │          │   │
│  │        └──────────────┼──────────────┘          │   │
│  │                       │                          │   │
│  │              ┌────────┴────────┐                 │   │
│  │              │  App Group      │                 │   │
│  │              │  共享数据       │                 │   │
│  │              └─────────────────┘                 │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Extension 限制:                                        │
│  ├── 内存限制: 通常 120MB（Today Widget 更低）          │
│  ├── 执行时间: 有限（系统可终止）                       │
│  ├── 后台执行: 受限                                     │
│  ├── 网络: 部分类型受限                                 │
│  ├── 硬件访问: 大部分禁止                               │
│  └── API 访问: 部分框架不可用                           │
│                                                         │
│  Extension 类型安全对比:                                │
│  ┌─────────────────┬──────────────┬────────────────┐  │
│  │ Extension 类型  │ 网络访问     │ 数据访问       │  │
│  ├─────────────────┼──────────────┼────────────────┤  │
│  │ Today           │ 允许         │ App Group      │  │
│  │ Share           │ 允许         │ 共享内容       │  │
│  │ Action          │ 允许         │ 共享内容       │  │
│  │ Photo Edit      │ 禁止         │ 照片           │  │
│  │ Keyboard        │ 禁止(默认)   │ 输入内容       │  │
│  │ Siri Intent     │ 允许         │ 有限           │  │
│  │ Notification    │ 允许         │ 通知内容       │  │
│  │ Content Blocker │ 禁止         │ 规则列表       │  │
│  │ Custom Keyboard │ 需 Full Access│ 输入内容      │  │
│  └─────────────────┴──────────────┴────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 15.2 Extension 安全开发

```swift
import UIKit

class SecureTodayWidget {
    
    func loadWidgetData() -> WidgetData? {
        guard let defaults = UserDefaults(suiteName: "group.com.example.myapp") else {
            return nil
        }
        
        guard let encryptedData = defaults.data(forKey: "widget_data") else {
            return nil
        }
        
        guard let decryptedData = decrypt(encryptedData) else {
            return nil
        }
        
        return try? JSONDecoder().decode(WidgetData.self, from: decryptedData)
    }
    
    func configureWidgetDisplay(data: WidgetData) -> WidgetView {
        let view = WidgetView()
        view.title = data.title
        
        if data.containsSensitiveInfo {
            view.balance = "****"
            view.accountNumber = "****\(data.accountSuffix)"
        } else {
            view.balance = data.formattedBalance
            view.accountNumber = data.accountNumber
        }
        
        return view
    }
    
    private func decrypt(_ data: Data) -> Data? { return data }
}

class SecureCustomKeyboard: UIInputViewController {
    
    var hasFullAccess: Bool { return self.hasFullAccess }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        if !hasFullAccess {
            // 不能使用网络、位置、剪贴板
        }
        
        setupSecureInputHandling()
    }
    
    private func setupSecureInputHandling() { }
    
    private func checkForSecureField() {
        if let traitCollection = self.textDocumentProxy as? UITextDocumentProxy {
            if traitCollection.keyboardType == .default {
                disableCloudFeatures()
            }
        }
    }
    
    func handleInput(_ text: String) {
        if isSensitiveInput(text) {
            // 不记录、不上传
        }
        self.textDocumentProxy.insertText(text)
    }
    
    private func isSensitiveInput(_ text: String) -> Bool { return false }
    private func disableCloudFeatures() { }
}
```

### 15.3 Extension 安全审计清单

| Extension 类型 | 关键风险 | 审计重点 |
|----------------|----------|----------|
| Today Widget | 信息泄露 | 不在 Widget 显示敏感数据 |
| Share Extension | 数据外泄 | 验证分享内容，不上传敏感内容 |
| Custom Keyboard | 键盘记录 | 无 Full Access 时限制功能 |
| Action Extension | 内容注入 | 验证处理的内容类型 |
| Photo Edit | 照片泄露 | 不将照片发送到外部 |
| Notification Service | 内容篡改 | 验证解密后的通知内容 |
| Siri Intent | 语音泄露 | 敏感操作需要确认 |

---

## 16. 第三方 SDK 访问控制审计

### 16.1 SDK 权限审计框架

```
┌─────────────────────────────────────────────────────────┐
│            第三方 SDK 权限审计框架                       │
│                                                         │
│  审计维度:                                              │
│  1. 声明权限审计                                         │
│     ├── Info.plist 权限声明                              │
│     ├── entitlements 权限声明                            │
│     └── 是否超出功能需要                                 │
│                                                          │
│  2. 运行时行为审计                                       │
│     ├── 网络请求目标                                     │
│     ├── 文件系统访问                                     │
│     ├── Keychain 访问                                    │
│     ├── 剪贴板访问                                       │
│     └── 系统 API 调用                                    │
│                                                          │
│  3. 数据收集审计                                         │
│     ├── 设备标识符收集                                   │
│     ├── 位置信息收集                                     │
│     ├── 用户行为追踪                                     │
│     └── 敏感信息收集                                     │
│                                                          │
│  4. 通信安全审计                                         │
│     ├── TLS 版本和配置                                   │
│     ├── 证书固定                                         │
│     ├── 数据加密                                         │
│     └── 服务器验证                                       │
│                                                          │
│  审计工具:                                              │
│  静态分析: otool, class-dump, strings, MachOView         │
│  动态分析: Frida, Objection, Charles/mitmproxy, dtrace   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 16.2 SDK 权限监控实现

```swift
import Foundation
import ObjectiveC.runtime

class SDKPermissionAuditor {
    
    static let shared = SDKPermissionAuditor()
    
    private var monitoredSDKs: [String: SDKMonitor] = [:]
    
    func registerSDK(name: String, expectedPermissions: Set<String>) {
        monitoredSDKs[name] = SDKMonitor(
            name: name,
            expectedPermissions: expectedPermissions,
            violations: []
        )
    }
    
    func startMonitoring() {
        hookFileManager()
        hookKeychain()
        hookNetwork()
        hookPasteboard()
        hookLocation()
        hookContacts()
        hookPhotos()
    }
    
    private func hookFileManager() { }
    private func hookKeychain() { }
    private func hookNetwork() { }
    private func hookPasteboard() { }
    private func hookLocation() { }
    private func hookContacts() { }
    private func hookPhotos() { }
    
    func reportAccess(sdk: String, permission: String, target: String) {
        guard let monitor = monitoredSDKs[sdk] else {
            logViolation(sdk: "unknown", permission: permission, target: target)
            return
        }
        
        if !monitor.expectedPermissions.contains(permission) {
            logViolation(sdk: sdk, permission: permission, target: target)
        }
    }
    
    private func logViolation(sdk: String, permission: String, target: String) {
        let violation = SDKViolation(
            sdk: sdk, permission: permission, target: target, timestamp: Date()
        )
        monitoredSDKs[sdk]?.violations.append(violation)
    }
    
    func generateAuditReport() -> AuditReport {
        var report = AuditReport()
        for (sdk, monitor) in monitoredSDKs {
            report.sdkReports[sdk] = SDKReport(
                name: sdk,
                expectedPermissions: monitor.expectedPermissions,
                violations: monitor.violations,
                riskLevel: calculateRiskLevel(violations: monitor.violations)
            )
        }
        return report
    }
    
    private func calculateRiskLevel(violations: [SDKViolation]) -> RiskLevel {
        if violations.isEmpty { return .low }
        let highRiskPermissions: Set<String> = [
            "keychain", "location", "contacts", "photos", "clipboard"
        ]
        let hasHighRisk = violations.contains { highRiskPermissions.contains($0.permission) }
        return hasHighRisk ? .high : .medium
    }
}

struct SDKMonitor {
    let name: String
    let expectedPermissions: Set<String>
    var violations: [SDKViolation]
}

struct SDKViolation {
    let sdk: String
    let permission: String
    let target: String
    let timestamp: Date
}

struct AuditReport {
    var sdkReports: [String: SDKReport] = [:]
}

struct SDKReport {
    let name: String
    let expectedPermissions: Set<String>
    let violations: [SDKViolation]
    let riskLevel: RiskLevel
}

enum RiskLevel {
    case low, medium, high, critical
}
```

### 16.3 常见 SDK 权限问题

| SDK 类型 | 常见过度权限 | 风险 | 建议 |
|----------|--------------|------|------|
| 广告 SDK | 位置、IDFA、剪贴板 | 高 | 限制为必要权限 |
| 分析 SDK | 设备信息、行为追踪 | 中 | 匿名化处理 |
| 社交 SDK | 通讯录、照片 | 高 | 用户明确授权 |
| 支付 SDK | Keychain、网络 | 中 | 验证证书固定 |
| 推送 SDK | 网络、设备信息 | 低 | 正常范围 |
| 崩溃报告 | 堆栈、设备信息 | 低 | 移除个人信息 |

---

## 17. IPC 攻击面与防御

### 17.1 iOS IPC 机制

```
┌─────────────────────────────────────────────────────────┐
│              iOS IPC 机制与安全                          │
│                                                         │
│  Mach Ports:                                            │
│  ├── 基于消息的进程间通信                               │
│  ├── 安全: 需要端口名称，受沙箱限制                     │
│  └── 风险: 端口名称猜测、消息注入                       │
│                                                         │
│  XPC Services:                                          │
│  ├── 高级 IPC 抽象                                      │
│  ├── 安全: entitlement 验证，沙箱限制                   │
│  └── 风险: entitlement 伪造                             │
│                                                         │
│  Darwin Notifications:                                  │
│  ├── 广播式通知                                         │
│  ├── 安全: 无认证，不应传递敏感数据                     │
│  └── 风险: 信息泄露                                     │
│                                                         │
│  URL Scheme / Universal Links:                          │
│  ├── 应用间通信的主要方式                               │
│  ├── 安全: 参数验证，来源验证                           │
│  └── 风险: Scheme 劫持、参数注入                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 17.2 IPC 安全实现

```swift
import Foundation

class SecureIPCManager {
    
    static func validateMessageSource(
        message: [String: Any],
        expectedSource: String? = nil
    ) -> Bool {
        guard let signature = message["signature"] as? String,
              let timestamp = message["timestamp"] as? TimeInterval,
              let payload = message["payload"] as? [String: Any] else {
            return false
        }
        
        let currentTime = Date().timeIntervalSince1970
        let maxAge: TimeInterval = 300
        guard abs(currentTime - timestamp) < maxAge else {
            return false
        }
        
        guard verifySignature(payload: payload, signature: signature) else {
            return false
        }
        
        if let expected = expectedSource,
           let source = message["source"] as? String,
           source != expected {
            return false
        }
        
        return true
    }
    
    private static func verifySignature(
        payload: [String: Any],
        signature: String
    ) -> Bool {
        return true
    }
    
    static func sendSecureMessage(
        to targetApp: String,
        payload: [String: Any],
        sharedSecret: Data
    ) -> Bool {
        var message = payload
        message["timestamp"] = Date().timeIntervalSince1970
        message["source"] = Bundle.main.bundleIdentifier
        
        let signature = generateSignature(payload: message, secret: sharedSecret)
        message["signature"] = signature
        
        guard let url = constructSecureURL(target: targetApp, message: message) else {
            return false
        }
        
        UIApplication.shared.open(url, options: [:]) { success in
            if !success {
                print("[IPC] Failed to send message to \(targetApp)")
            }
        }
        
        return true
    }
    
    private static func generateSignature(
        payload: [String: Any],
        secret: Data
    ) -> String {
        return "signature"
    }
    
    private static func constructSecureURL(
        target: String,
        message: [String: Any]
    ) -> URL? {
        return URL(string: "\(target)://ipc?data=\(message)")
    }
}
```

### 17.3 IPC 攻击面总结

| 攻击类型 | 描述 | 风险 | 防御 |
|----------|------|------|------|
| Mach 端口劫持 | 注册同名端口拦截消息 | 高 | 使用随机端口名 |
| XPC 权限绕过 | 伪造 entitlement | 严重 | 验证代码签名 |
| URL Scheme 注入 | 注入恶意参数 | 中 | 严格参数验证 |
| 重放攻击 | 重发合法消息 | 中 | 时间戳 + 一次性令牌 |
| 中间人攻击 | 拦截 IPC 通信 | 中 | 加密 + 签名 |

---

## 18. Apple 与 Android 访问控制对比

### 18.1 架构对比

| 特性 | iOS | Android |
|------|-----|---------|
| **沙箱机制** | MAC 框架强制沙箱 | SELinux + UID 隔离 |
| **权限模型** | 运行时授权 + Entitlement | 运行时权限 + Manifest |
| **应用签名** | 强制代码签名 | 强制代码签名（Android 6+） |
| **应用分发** | 仅 App Store（企业除外） | 多商店 + 侧载 |
| **IPC 机制** | URL Scheme, XPC, App Groups | Intent, ContentProvider, AIDL |
| **文件隔离** | 应用容器 | 应用私有目录 + Scoped Storage |
| **后台限制** | 严格限制 | 版本相关，逐渐收紧 |
| **侧载支持** | 不支持（企业证书除外） | 支持 |

### 18.2 安全模型对比

| 安全特性 | iOS | Android |
|----------|-----|---------|
| **默认拒绝** | 沙箱默认拒绝所有 | SELinux 默认拒绝 |
| **最小权限** | Entitlement 声明 | Manifest 声明 |
| **用户授权** | 运行时权限弹窗 | 运行时权限弹窗 |
| **权限撤销** | 设置中关闭 | 设置中关闭 |
| **权限分组** | 按功能分组 | 按危险等级分组 |
| **后台访问** | 严格限制 | Doze + App Standby |
| **剪贴板** | 首次访问提示 | Android 12+ 提示 |
| **应用间通信** | URL Scheme/Universal Links | Intent/ContentProvider |

### 18.3 安全优势对比

| 维度 | iOS 优势 | Android 优势 |
|------|----------|--------------|
| **生态控制** | 封闭生态，审核严格 | 开放生态，灵活 |
| **侧载风险** | 无侧载（企业除外） | 侧载带来恶意应用风险 |
| **碎片化** | 统一版本 | 版本碎片化严重 |
| **更新速度** | 快速推送 | 依赖厂商 |
| **企业控制** | MDM 深度集成 | MDM + Device Policy |
| **自定义能力** | 受限 | 高度可定制 |
| **安全研究** | 受限（闭源） | 开放（AOSP） |

---

## 19. 防御加固清单

### 19.1 访问控制加固

```
┌─────────────────────────────────────────────────────────┐
│              访问控制防御加固清单                        │
│                                                         │
│  [x] 沙箱安全                                           │
│      [x] 验证应用沙箱配置正确                           │
│      [x] 不在沙箱外存储敏感数据                         │
│      [x] 检测越狱环境                                   │
│      [x] 监控沙箱违规行为                               │
│                                                         │
│  [x] Entitlement 安全                                   │
│      [x] 最小化 entitlement 声明                        │
│      [x] 不使用私有 entitlement                         │
│      [x] 定期审计 entitlement 使用                      │
│      [x] 验证 entitlement 完整性                        │
│                                                         │
│  [x] Keychain 安全                                      │
│      [x] 使用最严格的 Accessibility                     │
│      [x] 敏感数据使用生物识别保护                       │
│      [x] 最小化 Keychain Access Group                   │
│      [x] 应用卸载时清理 Keychain                        │
│                                                         │
│  [x] 文件保护                                           │
│      [x] 所有敏感文件使用 Complete 保护                 │
│      [x] 定期审计文件保护级别                           │
│      [x] 使用加密备份                                   │
│      [x] 实现安全删除（覆写）                           │
│                                                         │
│  [x] IPC 安全                                           │
│      [x] URL Scheme 参数严格验证                        │
│      [x] 优先使用 Universal Links                       │
│      [x] IPC 消息签名验证                               │
│      [x] 防止重放攻击                                   │
│                                                         │
│  [x] 剪贴板安全                                         │
│      [x] 设置过期时间                                   │
│      [x] 使用 localOnly 选项                            │
│      [x] 不在剪贴板存储密码                             │
│      [x] 后台前清除敏感内容                             │
│                                                         │
│  [x] 后台任务安全                                       │
│      [x] 检查 isProtectedDataAvailable                  │
│      [x] 后台传输使用加密                               │
│      [x] 尊重用户低数据模式                             │
│      [x] 实现任务过期处理                               │
│                                                         │
│  [x] Extension 安全                                     │
│      [x] 不在 Widget 显示敏感数据                       │
│      [x] 验证分享内容类型                               │
│      [x] 键盘不记录敏感输入                             │
│      [x] Extension 内存使用优化                         │
│                                                         │
│  [x] 第三方 SDK 安全                                    │
│      [x] 审计 SDK 权限声明                              │
│      [x] 监控 SDK 运行时行为                            │
│      [x] 验证 SDK 网络通信                              │
│      [x] 定期更新 SDK                                   │
│                                                         │
│  [x] 辅助功能安全                                       │
│      [x] 敏感字段设置合适的 accessibilityLabel          │
│      [x] 密码字段不暴露 accessibilityValue              │
│      [x] 检测异常 UI 操作模式                           │
│      [x] 敏感操作二次验证                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 19.2 自动化审计脚本

```bash
#!/bin/bash
# iOS 访问控制自动化审计脚本

APP_PATH="$1"
REPORT_FILE="access_control_audit_$(date +%Y%m%d_%H%M%S).txt"

echo "iOS Access Control Audit" > "$REPORT_FILE"
echo "App: $APP_PATH" >> "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"

# 1. 检查 Entitlement
echo -e "\n[Entitlements]" >> "$REPORT_FILE"
codesign -d --entitlements :- "$APP_PATH" >> "$REPORT_FILE" 2>&1

# 2. 检查 Info.plist 权限声明
echo -e "\n[Info.plist Permissions]" >> "$REPORT_FILE"
plutil -p "$APP_PATH/Info.plist" | grep -i "usage" >> "$REPORT_FILE"

# 3. 检查 URL Scheme
echo -e "\n[URL Schemes]" >> "$REPORT_FILE"
plutil -p "$APP_PATH/Info.plist" | grep -A5 "CFBundleURLTypes" >> "$REPORT_FILE"

# 4. 检查 App Groups
echo -e "\n[App Groups]" >> "$REPORT_FILE"
plutil -p "$APP_PATH/Info.plist" | grep -i "group" >> "$REPORT_FILE"

# 5. 检查 Keychain Access Groups
echo -e "\n[Keychain Access Groups]" >> "$REPORT_FILE"
codesign -d --entitlements :- "$APP_PATH" | grep -A5 "keychain-access-groups" >> "$REPORT_FILE"

# 6. 检查后台模式
echo -e "\n[Background Modes]" >> "$REPORT_FILE"
plutil -p "$APP_PATH/Info.plist" | grep -A10 "UIBackgroundModes" >> "$REPORT_FILE"

# 7. 检查网络配置
echo -e "\n[ATS Configuration]" >> "$REPORT_FILE"
plutil -p "$APP_PATH/Info.plist" | grep -A10 "NSAppTransportSecurity" >> "$REPORT_FILE"

# 8. 检查 Associated Domains
echo -e "\n[Associated Domains]" >> "$REPORT_FILE"
codesign -d --entitlements :- "$APP_PATH" | grep -A5 "associated-domains" >> "$REPORT_FILE"

echo -e "\n========================================" >> "$REPORT_FILE"
echo "Audit complete. Report saved to: $REPORT_FILE"
```

---

## 20. 行业案例与教训

### 20.1 案例一：剪贴板隐私泄露

**事件**: 2020年，多个主流 iOS 应用被发现秘密读取剪贴板内容

**影响**:
- 社交应用读取用户复制的密码、地址
- 游戏应用读取剪贴板中的敏感信息
- 新闻应用读取用户复制的文章标题

**根因**:
- 应用使用剪贴板检测用户行为
- 缺乏剪贴板访问审计机制
- iOS 14 之前无访问提示

**教训**:
- iOS 14 引入剪贴板访问提示是正确的
- 应用应最小化剪贴板访问
- 用户应了解剪贴板隐私风险

### 20.2 案例二：URL Scheme 劫持

**事件**: 某支付应用的 URL Scheme 被恶意应用劫持

**影响**:
- 用户点击支付链接被重定向到恶意应用
- 支付凭证被窃取
- 资金损失

**根因**:
- URL Scheme 未验证来源
- 回调 URL 未白名单限制
- 缺乏参数签名验证

**教训**:
- 优先使用 Universal Links
- URL Scheme 必须验证来源
- 回调 URL 必须白名单
- 敏感参数必须签名

### 20.3 案例三：Keychain 跨应用泄露

**事件**: 某开发者的多个应用共享 Keychain 组配置错误

**影响**:
- 一个应用的 Keychain 数据被其他应用读取
- 用户认证令牌泄露
- 账户被未授权访问

**根因**:
- Keychain Access Group 配置过于宽泛
- 使用 `kSecAttrAccessibleAlways`（已弃用）
- 缺乏 Keychain 访问审计

**教训**:
- 最小化 Keychain Access Group
- 使用最严格的 Accessibility
- 定期审计 Keychain 访问

### 20.4 案例四：Extension 权限滥用

**事件**: 某键盘 Extension 在后台收集用户输入

**影响**:
- 用户密码被记录
- 敏感对话内容被上传
- 隐私严重泄露

**根因**:
- 键盘请求了 Full Access
- 未在隐私政策中披露数据收集
- 缺乏 Extension 行为审计

**教训**:
- 谨慎授予 Full Access
- Extension 数据收集必须披露
- 实现 Extension 行为监控

---

## 21. 未来趋势与演进方向

### 21.1 隐私保护增强

| 趋势 | 描述 | 影响 |
|------|------|------|
| **App Tracking Transparency 扩展** | 更严格的跨应用追踪限制 | 广告 SDK 需要重新设计 |
| **剪贴板访问控制** | 每次访问都需用户确认 | 应用需要重新设计粘贴流程 |
| **位置精度控制** | 用户可选择模糊位置 | 位置服务需要适配 |
| **照片选择器** | 应用只能访问用户选择的照片 | 照片访问模式改变 |
| **通讯录访问** | 更细粒度的通讯录权限 | 社交应用需要重新设计 |

### 21.2 沙箱强化

| 趋势 | 描述 | 影响 |
|------|------|------|
| **更严格的 Mach 端口控制** | 限制 Mach 端口名称空间 | 越狱工具需要适配 |
| **IOKit 设备隔离** | 更细粒度的设备访问控制 | 驱动开发需要适配 |
| **网络扩展限制** | 限制 VPN/代理扩展能力 | 安全应用需要重新设计 |
| **文件系统快照** | 防止文件系统元数据泄露 | 取证工具受影响 |

### 21.3 零信任架构

```
┌─────────────────────────────────────────────────────────┐
│              iOS 零信任访问控制                          │
│                                                         │
│  传统模型:                                              │
│  ┌─────────┐                                            │
│  │  应用   │ ──→ 一次授权，持续访问                     │
│  └─────────┘                                            │
│                                                         │
│  零信任模型:                                            │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────┐ │
│  │  应用   │──→│ 验证身份│──→│ 验证设备│──→│ 验证│ │
│  │  请求   │    │         │    │ 状态    │    │ 上下文│ │
│  └─────────┘    └─────────┘    └─────────┘    └──┬──┘ │
│                                                    │    │
│                                              ┌─────┴──┐│
│                                              │ 持续   ││
│                                              │ 监控   ││
│                                              └────────┘│
│                                                         │
│  关键原则:                                              │
│  ├── 永不信任，始终验证                                 │
│  ├── 最小权限访问                                       │
│  ├── 假设被入侵                                         │
│  └── 持续验证                                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 21.4 AI 驱动的访问控制

| 方向 | 描述 | 预期效果 |
|------|------|----------|
| **行为分析** | 基于用户行为模式调整权限 | 异常行为自动降级 |
| **上下文感知** | 根据时间、位置、设备状态调整 | 更智能的权限管理 |
| **威胁检测** | AI 识别潜在访问控制绕过 | 实时防护 |
| **自动响应** | 检测到威胁自动隔离 | 减少人工干预 |

---

## 22. 参考法规与合规要求

### 22.1 数据保护法规

| 法规 | 适用范围 | 访问控制要求 |
|------|----------|--------------|
| **GDPR** | 欧盟用户数据 | 数据最小化、目的限制、存储限制 |
| **CCPA** | 加州用户数据 | 消费者知情权、删除权、选择退出权 |
| **PIPL** | 中国用户数据 | 最小必要、知情同意、目的限制 |
| **HIPAA** | 医疗健康数据 | 访问控制、审计追踪、加密 |
| **PCI DSS** | 支付卡数据 | 访问控制、加密、审计 |

### 22.2 合规检查清单

```
┌─────────────────────────────────────────────────────────┐
│              访问控制合规检查清单                        │
│                                                         │
│  数据最小化:                                            │
│  [ ] 仅收集业务必需的数据                               │
│  [ ] 仅请求必需的系统权限                               │
│  [ ] 数据保留期限明确                                   │
│                                                         │
│  用户知情同意:                                          │
│  [ ] 隐私政策清晰说明数据收集                           │
│  [ ] 权限请求说明用途                                   │
│  [ ] 用户可撤回同意                                     │
│                                                         │
│  数据保护:                                              │
│  [ ] 敏感数据加密存储                                   │
│  [ ] 传输使用 TLS 1.2+                                  │
│  [ ] 密钥安全管理                                       │
│                                                         │
│  审计追踪:                                              │
│  [ ] 记录数据访问日志                                   │
│  [ ] 记录权限变更                                       │
│  [ ] 日志安全存储                                       │
│                                                         │
│  用户权利:                                              │
│  [ ] 支持数据导出                                       │
│  [ ] 支持数据删除                                       │
│  [ ] 支持账户注销                                       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 23. 附录：工具与资源

### 23.1 安全审计工具

| 工具 | 类型 | 用途 | 链接 |
|------|------|------|------|
| **Frida** | 动态 | 运行时 Hook、注入 | frida.re |
|
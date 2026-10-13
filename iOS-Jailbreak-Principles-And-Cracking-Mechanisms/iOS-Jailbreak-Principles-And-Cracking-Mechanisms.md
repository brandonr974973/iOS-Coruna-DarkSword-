# iOS越狱原理与破解机制

## iOS Jailbreak Principles and Cracking Mechanisms

---

**作者**: pengqinglei99-eng  
**日期**: 2026年10月14日  
**版本**: 1.0  
**联系**: telegram：@pengqing666

---

## 目录

1. [越狱概述](#1-越狱概述)
2. [iOS安全架构](#2-ios安全架构)
3. [越狱基本原理](#3-越狱基本原理)
4. [Boot ROM漏洞利用](#4-boot-rom漏洞利用)
5. [iBoot漏洞利用](#5-iboot漏洞利用)
6. [内核漏洞利用](#6-内核漏洞利用)
7. [代码签名绕过](#7-代码签名绕过)
8. [沙箱绕过](#8-沙箱绕过)
9. [文件系统挂载](#9-文件系统挂载)
10. [越狱工具分析](#10-越狱工具分析)
11. [越狱持久化](#11-越狱持久化)
12. [越狱检测与对抗](#12-越狱检测与对抗)
13. [越狱风险评估](#13-越狱风险评估)
14. [越狱法律与伦理](#14-越狱法律与伦理)
15. [未越狱设备的安全建议](#15-未越狱设备的安全建议)
16. [越狱技术发展趋势](#16-越狱技术发展趋势)

---

## 1. 越狱概述

### 1.1 什么是越狱

越狱（Jailbreak）是指绕过iOS系统的安全限制，获取系统最高权限的过程：

**越狱的本质**：
- 绕过代码签名验证
- 绕过沙箱限制
- 获取root权限
- 修改系统文件

**越狱的目的**：
- 安装未授权应用
- 修改系统设置
- 自定义界面
- 访问系统文件
- 进行安全研究

### 1.2 越狱的类型

**按持久性分类**：

**临时越狱（Tethered）**：
- 重启后失效
- 需要重新连接电脑
- 重新执行越狱

**半永久越狱（Semi-tethered）**：
- 重启后可以启动
- 但越狱功能失效
- 需要重新激活

**半不 tethered 越狱（Semi-untethered）**：
- 重启后可以启动
- 越狱功能失效
- 可以在设备上重新激活

**不 tethered 越狱（Untethered）**：
- 重启后保持越狱状态
- 完全持久化
- 最理想的越狱

**按漏洞类型分类**：

**硬件漏洞越狱**：
- 利用Boot ROM漏洞
- 无法通过软件更新修复
- 例如：checkm8

**软件漏洞越狱**：
- 利用系统软件漏洞
- 可以通过更新修复
- 例如：unc0ver, Taurine

### 1.3 越狱的历史

**早期越狱（2007-2010）**：

**iPhone OS 1.x-3.x**：
- 简单的漏洞利用
- 主要修改文件系统
- 安装Cydia

**关键工具**：
- iLiberty
- PwnageTool
- RedSn0w

**中期越狱（2010-2016）**：

**iOS 4.x-9.x**：
- 更复杂的漏洞利用
- 内核漏洞利用
- 完整的越狱生态

**关键工具**：
- Greenpois0n
- Absinthe
- evasi0n
- Pangu
- TaiG

**现代越狱（2016-至今）**：

**iOS 10.x-17.x**：
- 高度复杂的漏洞利用
- 多层防御绕过
- 安全研究导向

**关键工具**：
- Yalu（iOS 10）
- Electra（iOS 11）
- unc0ver（iOS 11-14）
- Taurine（iOS 14）
- palera1n（iOS 15-16）
- Dopamine（iOS 15-16）

### 1.4 越狱生态系统

**越狱应用商店**：

**Cydia**：
- 最古老的越狱商店
- 由Jay Freeman创建
- 丰富的插件资源

**Sileo**：
- 现代化的包管理器
- 支持Rootless越狱
- 更好的性能

**Zebra**：
- 轻量级包管理器
- 支持Rootless越狱
- 开源项目

**越狱插件**：

**系统定制**：
- WinterBoard：主题引擎
- Anemone：现代主题引擎
- SnowBoard：Rootless主题引擎

**功能增强**：
- Activator：手势控制
- PreferenceLoader：设置集成
- OpenSSH：远程访问

**开发工具**：
- class-dump：导出头文件
- Cycript：运行时修改
- Frida：动态插桩

---

## 2. iOS安全架构

### 2.1 安全启动链

**启动过程**：

```
Boot ROM（硬件固化）
  ↓
Low-Level Bootloader (LLB)
  ↓
iBoot
  ↓
XNU Kernel
  ↓
launchd
```

**每个阶段的验证**：

**Boot ROM**：
- 固化在硬件中
- 无法修改
- 验证LLB签名

**LLB**：
- 验证iBoot签名
- 初始化基本硬件
- 加载iBoot

**iBoot**：
- 验证内核签名
- 加载设备树
- 设置内核参数

**内核**：
- 验证系统卷
- 启动launchd
- 初始化系统服务

### 2.2 代码签名

**代码签名机制**：

**签名流程**：
```
源代码
  ↓
编译为二进制
  ↓
生成哈希（SHA-256）
  ↓
使用Apple证书签名
  ↓
嵌入签名到Mach-O
```

**签名验证时机**：
- 应用安装时
- 应用启动时
- 动态库加载时
- 代码页执行前

**签名结构**：
```
Mach-O Binary
├── __TEXT segment
│   └── __LINKEDIT
│       └── Code Signature
│           ├── CMS Signature
│           ├── Code Directory
│           ├── Requirements
│           └── Entitlements
```

### 2.3 沙箱机制

**沙箱架构**：

**强制访问控制（MAC）**：
- 基于策略的访问控制
- 独立于DAC
- 内核强制执行

**沙箱配置文件**：
```
(sandbox-definition
  (deny default)
  (allow file-read* (subpath "/usr/lib"))
  (allow network-outbound (conditional ...))
  (allow ipc-posix-shm ...)
)
```

**沙箱限制**：
- 文件访问限制
- 网络访问限制
- 进程间通信限制
- 设备访问限制

### 2.4 权限模型

**权限层次**：

**用户权限**：
- 普通用户（mobile）
- 受限权限
- 沙箱限制

**系统权限**：
- 系统用户（root）
- 扩展权限
- 系统服务

**Root权限**：
- 最高权限
- 完全控制
- 无限制

### 2.5 安全特性

**硬件安全**：

**Secure Enclave**：
- 独立安全处理器
- 密钥存储
- 生物识别

**Secure Boot**：
- 启动链验证
- 完整性检查
- 防篡改

**软件安全**：

**ASLR**：
- 地址空间布局随机化
- 增加利用难度
- 多层随机化

**DEP/NX**：
- 数据执行保护
- 代码段不可写
- 数据段不可执行

**PAC**：
- 指针认证码
- 完整性验证
- 防ROP

---

## 3. 越狱基本原理

### 3.1 越狱的核心目标

**获取Root权限**：

**原理**：
- 利用内核漏洞
- 修改进程凭证
- 获取root权限

**实现**：
```c
// 修改进程凭证
struct ucred cred;
cred.cr_uid = 0;  // root
cred.cr_ruid = 0;
cred.cr_svuid = 0;

// 应用到当前进程
proc_set_ucred(getpid(), &cred);
```

**绕过代码签名**：

**原理**：
- 禁用代码签名检查
- 修改签名验证逻辑
- 执行未签名代码

**实现**：
```c
// 禁用代码签名检查
// 修改内核中的代码签名标志
amfi->flags |= AMFI_FLAG_ALLOW_UNSIGNED;
```

**绕过沙箱**：

**原理**：
- 禁用沙箱策略
- 修改沙箱配置
- 直接访问资源

**实现**：
```c
// 禁用沙箱
sandbox_disable();

// 或修改沙箱策略
sandbox_set_profile("permissive");
```

### 3.2 越狱的基本流程

**典型越狱流程**：

```
1. 漏洞发现
   ↓
2. 漏洞利用
   ↓
3. 获取代码执行
   ↓
4. 权限提升
   ↓
5. 绕过代码签名
   ↓
6. 绕过沙箱
   ↓
7. 挂载文件系统
   ↓
8. 安装越狱环境
   ↓
9. 持久化（可选）
```

**详细步骤**：

**步骤1：漏洞发现**
- 研究iOS代码
- 寻找安全漏洞
- 验证漏洞可利用性

**步骤2：漏洞利用**
- 开发利用代码
- 构造利用输入
- 触发漏洞

**步骤3：获取代码执行**
- 控制执行流
- 执行shellcode
- 建立控制

**步骤4：权限提升**
- 利用内核漏洞
- 获取root权限
- 修改系统状态

**步骤5：绕过代码签名**
- 禁用签名检查
- 修改AMFI
- 允许未签名代码

**步骤6：绕过沙箱**
- 禁用沙箱
- 修改策略
- 访问受限资源

**步骤7：挂载文件系统**
- 重新挂载为读写
- 修改系统文件
- 安装越狱组件

**步骤8：安装越狱环境**
- 安装Cydia/Sileo
- 安装必要的包
- 配置环境

**步骤9：持久化**
- 修改启动流程
- 安装持久化组件
- 确保重启后保持

### 3.3 越狱的关键技术

**内核漏洞利用**：

**类型**：
- 内存损坏（UAF、溢出）
- 逻辑漏洞（权限绕过）
- 竞态条件

**目标**：
- 获取内核代码执行
- 修改内核数据结构
- 提升权限

**代码签名绕过**：

**AMFI（Apple Mobile File Integrity）**：
- 负责代码签名验证
- 内核扩展
- 可以禁用或修改

**Sandbox绕过**：

**沙箱策略**：
- 配置文件
- 内核强制执行
- 可以禁用或修改

**文件系统修改**：

**挂载点**：
- /（根文件系统）
- /System（系统文件）
- /usr（用户程序）

**修改方式**：
- 重新挂载为读写
- 修改系统文件
- 安装新组件

---

## 4. Boot ROM漏洞利用

### 4.1 Boot ROM概述

**什么是Boot ROM**：

**定义**：
- 固化在硬件中的代码
- 设备启动的第一阶段
- 无法通过软件更新修改

**特点**：
- 永久存在
- 无法修复
- 最高信任级别

**功能**：
- 初始化硬件
- 验证LLB
- 加载LLB

### 4.2 checkm8漏洞

**漏洞概述**：

**发现者**：axi0mX（2019年）

**影响范围**：
- iPhone 4S到iPhone X
- iPad mini到iPad Pro（2017）
- 所有使用A5-A11芯片的设备

**漏洞类型**：USB栈漏洞

**漏洞原理**：

**USB恢复模式处理**：
```
设备进入DFU模式
  ↓
Boot ROM处理USB请求
  ↓
处理大量USB请求
  ↓
触发堆溢出
  ↓
覆盖关键数据结构
  ↓
控制执行流
```

**详细分析**：

**USB请求处理**：
```c
// Boot ROM中的USB处理代码
void handle_usb_request(usb_request *req) {
    char buffer[1024];
    
    // 没有正确检查长度
    if (req->length > sizeof(buffer)) {
        // 漏洞：可以溢出buffer
        memcpy(buffer, req->data, req->length);
    }
}
```

**利用过程**：
1. 设备进入DFU模式
2. 发送特制的USB请求
3. 触发堆溢出
4. 覆盖返回地址
5. 执行shellcode

**利用特点**：

**优势**：
- 硬件漏洞，无法修复
- 永久可用
- 可以安装自定义iBoot

**局限性**：
- 需要物理连接
- 只支持特定设备
- 需要技术知识

### 4.3 checkm8利用工具

**checkra1n**：

**概述**：
- 基于checkm8的越狱工具
- 支持iOS 12-14
- semi-tethered越狱

**工作原理**：
```
1. 设备进入DFU模式
  ↓
2. checkra1n发送利用代码
  ↓
3. 触发checkm8漏洞
  ↓
4. 执行shellcode
  ↓
5. 加载自定义iBoot
  ↓
6. 启动越狱内核
  ↓
7. 安装越狱环境
```

**使用方法**：
```bash
# macOS
./checkra1n

# Linux
./checkra1n -l

# 命令行
checkra1n -c  # 命令行模式
```

**ipwndfu**：

**概述**：
- 开源的DFU利用工具
- 支持checkm8
- 可以安装自定义iBoot

**功能**：
- 进入DFU模式
- 执行checkm8利用
- 安装自定义iBoot
- 提取设备信息

**使用方法**：
```bash
# 进入DFU模式
./ipwndfu --dfu

# 执行利用
./ipwndfu -p

# 安装自定义iBoot
./ipwndfu -b custom_iboot
```

### 4.4 Boot ROM漏洞防御

**Apple的应对**：

**硬件修复**：
- A12及以后的芯片修复了漏洞
- 新的USB控制器
- 改进的错误处理

**软件缓解**：
- 限制DFU模式访问
- 增加验证步骤
- 监控异常行为

**用户防护**：
- 使用新设备
- 物理安全
- 警惕USB攻击

---

## 5. iBoot漏洞利用

### 5.1 iBoot概述

**什么是iBoot**：

**定义**：
- iOS的第二阶段引导加载器
- 负责加载内核
- 验证内核签名

**功能**：
- 初始化硬件
- 验证内核
- 加载内核
- 传递参数

**安全机制**：
- 代码签名验证
- 完整性检查
- 安全启动

### 5.2 iBoot漏洞类型

**代码执行漏洞**：

**类型**：
- 缓冲区溢出
- 整数溢出
- 解析漏洞

**影响**：
- 执行任意代码
- 绕过签名验证
- 加载未签名内核

**签名绕过漏洞**：

**类型**：
- 验证逻辑错误
- 证书处理错误
- 状态管理错误

**影响**：
- 绕过签名检查
- 加载未签名代码
- 破坏安全启动

### 5.3 iBoot漏洞案例

**iOS 11 iBoot漏洞**：

**发现**：
- 2018年源码泄露
- 多个漏洞被发现
- 影响iOS 11

**漏洞分析**：

**源码泄露**：
```c
// iBoot源码中的漏洞
void load_kernel(const char *path) {
    char buffer[4096];
    
    // 没有检查路径长度
    strcpy(buffer, path);  // 可能溢出
    
    // 加载内核
    load_image(buffer);
}
```

**利用**：
- 构造超长路径
- 触发缓冲区溢出
- 执行任意代码

**iOS 14 iBoot漏洞**：

**发现**：
- 安全研究者发现
- 影响iOS 14
- 用于越狱

**漏洞类型**：
- 内存损坏
- 签名绕过

**利用**：
- 触发漏洞
- 绕过签名
- 加载自定义内核

### 5.4 iBoot利用工具

**iBoot利用流程**：

```
1. 进入恢复模式
  ↓
2. 发送特制命令
  ↓
3. 触发iBoot漏洞
  ↓
4. 执行shellcode
  ↓
5. 修改启动参数
  ↓
6. 加载自定义内核
  ↓
7. 启动越狱系统
```

**工具**：

**irecovery**：
- 开源恢复模式工具
- 发送命令
- 加载镜像

**futurerestore**：
- 降级工具
- 利用iBoot漏洞
- 安装旧版本

### 5.5 iBoot漏洞防御

**Apple的修复**：

**代码修复**：
- 修复缓冲区溢出
- 改进输入验证
- 加强错误处理

**签名增强**：
- 更强的签名验证
- 多层验证
- 硬件验证

**安全启动**：
- 完整的启动链验证
- 每步验证
- 防篡改

---

## 6. 内核漏洞利用

### 6.1 XNU内核概述

**XNU架构**：

**组成**：
- Mach微内核
- BSD层
- IOKit

**功能**：
- 进程管理
- 内存管理
- 文件系统
- 网络栈
- 设备驱动

**安全机制**：
- 代码签名
- 沙箱
- 权限控制
- 内存保护

### 6.2 内核漏洞类型

**内存损坏漏洞**：

**UAF（Use-After-Free）**：
- 释放后使用
- 类型混淆
- 虚表劫持

**缓冲区溢出**：
- 栈溢出
- 堆溢出
- 全局溢出

**整数溢出**：
- 大小计算错误
- 索引错误
- 分配错误

**逻辑漏洞**：

**权限检查漏洞**：
- 缺少检查
- 检查错误
- 检查绕过

**竞态条件**：
- TOCTOU
- 并发访问
- 状态不一致

### 6.3 内核漏洞利用技术

**信息泄露**：

**目的**：
- 获取内核基址
- 绕过KASLR
- 获取敏感信息

**技术**：
- 未初始化内存泄露
- 越界读取
- 侧信道

**任意读写**：

**读原语**：
- 读取任意内核内存
- 获取敏感数据
- 绕过保护

**写原语**：
- 写入任意内核内存
- 修改关键数据
- 控制内核

**实现**：
- 利用内核漏洞
- 构造读写原语
- 稳定可靠

**代码执行**：

**直接执行**：
- 跳转到shellcode
- 执行内核代码
- 获取root权限

**ROP执行**：
- 复用内核代码
- 构造ROP链
- 实现功能

### 6.4 内核漏洞案例

**CVE-2021-1786**：

**漏洞类型**：IOKit UAF

**影响**：
- iOS 14.0-14.4
- 内核权限提升
- 用于越狱

**漏洞分析**：

**IOHIDFamily**：
```c
// IOHIDFamily中的UAF
void process_event(IOHIDEvent *event) {
    // 使用已释放的对象
    event->handler->process(event);  // UAF
}
```

**利用过程**：
```
1. 触发IOHIDFamily UAF
  ↓
2. 控制内核对象
  ↓
3. 虚表劫持
  ↓
4. 内核代码执行
  ↓
5. 获取root权限
```

**CVE-2021-30869**：

**漏洞类型**：内核UAF

**影响**：
- iOS 14.0-14.7
- 内核权限提升
- 用于越狱

**漏洞分析**：

**内核对象管理**：
```c
// 内核中的UAF
void process_object(kernel_object *obj) {
    // 对象已释放
    obj->method();  // UAF
}
```

**利用**：
- 触发内核UAF
- 控制内核对象
- 修改凭证
- 获取root权限

### 6.5 内核利用工具

**内核利用框架**：

**unc0ver**：
- 利用多个内核漏洞
- 支持iOS 11-14
- 半不tethered越狱

**Taurine**：
- 利用iOS 14漏洞
- 支持iOS 14.0-14.8.1
- Rootless越狱

**palera1n**：
- 利用checkm8 + 内核漏洞
- 支持iOS 15-16
- 完整越狱

**内核利用流程**：

```
1. 触发内核漏洞
  ↓
2. 获取内核代码执行
  ↓
3. 获取内核基址
  ↓
4. 构造读写原语
  ↓
5. 修改进程凭证
  ↓
6. 获取root权限
  ↓
7. 绕过代码签名
  ↓
8. 安装越狱环境
```

---

## 7. 代码签名绕过

### 7.1 代码签名机制

**AMFI（Apple Mobile File Integrity）**：

**功能**：
- 验证代码签名
- 防止未签名代码执行
- 内核扩展

**工作原理**：
```
加载代码
  ↓
计算哈希
  ↓
验证签名
  ↓
检查entitlements
  ↓
允许执行
```

**签名验证流程**：
```
Mach-O文件
  ↓
读取Code Directory
  ↓
计算页面哈希
  ↓
与签名比较
  ↓
验证CMS签名
  ↓
检查Apple证书链
  ↓
允许执行
```

### 7.2 代码签名绕过技术

**禁用AMFI**：

**原理**：
- 修改AMFI标志
- 禁用签名检查
- 允许未签名代码

**实现**：
```c
// 修改AMFI标志
amfi->flags |= AMFI_FLAG_ALLOW_UNSIGNED;

// 或禁用AMFI
amfi_disable();
```

**修改签名验证**：

**原理**：
- Hook签名验证函数
- 总是返回成功
- 绕过检查

**实现**：
```c
// Hook签名验证
int (*orig_cs_valid)(void *) = cs_valid;

int hooked_cs_valid(void *blob) {
    return 1;  // 总是有效
}

// 替换函数
patch(cs_valid, hooked_cs_valid);
```

**修改Entitlements**：

**原理**：
- 修改进程entitlements
- 获取额外权限
- 绕过限制

**实现**：
```c
// 添加entitlement
add_entitlement("com.apple.private.security.storage");

// 或修改现有entitlement
modify_entitlement("platform-application", true);
```

### 7.3 代码签名绕过案例

**unc0ver的签名绕过**：

**方法**：
- 利用内核漏洞
- 修改AMFI状态
- 禁用签名检查

**实现**：
```c
// unc0ver的签名绕过
void bypass_codesigning() {
    // 获取内核基址
    uint64_t kernel_base = get_kernel_base();
    
    // 找到AMFI结构
    uint64_t amfi = find_amfi(kernel_base);
    
    // 修改标志
    write_kernel(amfi + OFFSET_FLAGS, AMFI_FLAG_ALLOW_UNSIGNED);
}
```

**palera1n的签名绕过**：

**方法**：
- 使用自定义iBoot
- 修改内核加载
- 禁用签名检查

**实现**：
- 安装自定义iBoot
- 修改内核参数
- 禁用签名验证

### 7.4 代码签名绕过防御

**Apple的防护**：

**AMFI加固**：
- 更强的验证
- 多层检查
- 硬件验证

**Secure Enclave**：
- 独立验证
- 硬件保护
- 防篡改

**Kernel Integrity**：
- KTRR/CTRR
- 内核文本保护
- 防修改

---

## 8. 沙箱绕过

### 8.1 沙箱机制

**沙箱架构**：

**强制访问控制（MAC）**：
- 基于策略的访问控制
- 独立于DAC
- 内核强制执行

**沙箱配置文件**：
```
(sandbox-definition
  (deny default)
  (allow file-read* (subpath "/usr/lib"))
  (allow network-outbound (conditional ...))
  (allow ipc-posix-shm ...)
)
```

**沙箱限制**：
- 文件访问限制
- 网络访问限制
- 进程间通信限制
- 设备访问限制

### 8.2 沙箱绕过技术

**禁用沙箱**：

**原理**：
- 禁用沙箱强制执行
- 修改沙箱状态
- 允许所有访问

**实现**：
```c
// 禁用沙箱
sandbox_disable();

// 或修改沙箱策略
sandbox_set_profile("permissive");
```

**修改沙箱策略**：

**原理**：
- 修改沙箱配置文件
- 放宽限制
- 允许更多访问

**实现**：
```c
// 修改沙箱策略
char *new_profile = "(version 1)(deny default)(allow *)";
sandbox_set_profile(new_profile);
```

**利用内核漏洞**：

**原理**：
- 利用内核漏洞
- 获取root权限
- 绕过沙箱

**实现**：
```c
// 利用内核漏洞获取root
get_root();

// 修改进程凭证
setuid(0);
setgid(0);

// 现在可以绕过沙箱
```

### 8.3 沙箱绕过案例

**unc0ver的沙箱绕过**：

**方法**：
- 利用内核漏洞
- 获取root权限
- 禁用沙箱

**实现**：
```c
// unc0ver的沙箱绕过
void bypass_sandbox() {
    // 获取root权限
    get_root();
    
    // 禁用沙箱
    sandbox_disable();
    
    // 或修改沙箱策略
    sandbox_set_profile("permissive");
}
```

**Taurine的沙箱绕过**：

**方法**：
- Rootless越狱
- 不修改系统
- 使用用户空间技术

**实现**：
- 使用动态库注入
- Hook系统调用
- 绕过沙箱检查

### 8.4 沙箱绕过防御

**Apple的防护**：

**沙箱加固**：
- 更严格的策略
- 强制隔离
- 监控检测

**内核保护**：
- KTRR/CTRR
- PAC
- MTE

**监控检测**：
- 异常行为检测
- 沙箱违规检测
- 自动响应

---

## 9. 文件系统挂载

### 9.1 iOS文件系统

**文件系统结构**：

```
/
├── System/              ← 系统文件（只读）
│   ├── Library/
│   └── Applications/
├── User/                ← 用户数据
│   └── Containers/
│       ├── Data/        ← 应用数据
│       └── Bundle/      ← 应用包
├── private/
│   ├── var/             ← 可变数据
│   │   ├── mobile/
│   │   └── log/
│   └── etc/             ← 配置文件
└── usr/
    ├── lib/             ← 系统库
    └── bin/             ← 系统工具
```

**挂载点**：
- /（根文件系统）
- /System（系统文件）
- /usr（用户程序）
- /var（可变数据）

### 9.2 文件系统挂载技术

**重新挂载为读写**：

**原理**：
- 修改挂载标志
- 允许写入
- 修改系统文件

**实现**：
```c
// 重新挂载根文件系统为读写
mount("apfs", "/", MNT_UPDATE, &args);

// 或修改挂载标志
set_mount_flags("/", MNT_RDWR);
```

**修改系统文件**：

**原理**：
- 获取写入权限
- 修改系统文件
- 安装越狱组件

**实现**：
```bash
# 重新挂载为读写
mount -o rw,remount /

# 修改系统文件
cp jailbreak_files /usr/lib/

# 设置权限
chmod 755 /usr/lib/jailbreak_file
```

**安装越狱组件**：

**组件**：
- Cydia/Sileo
- 必要的包
- 配置文件

**安装过程**：
```bash
# 安装Cydia
dpkg -i cydia.deb

# 安装依赖
apt-get install -f

# 配置源
echo "deb https://repo.example.com/ ./" > /etc/apt/sources.list.d/example.list
```

### 9.3 文件系统挂载案例

**unc0ver的文件系统挂载**：

**方法**：
- 利用内核漏洞
- 重新挂载文件系统
- 安装越狱组件

**实现**：
```c
// unc0ver的文件系统挂载
void mount_filesystem() {
    // 获取root权限
    get_root();
    
    // 重新挂载为读写
    mount("apfs", "/", MNT_UPDATE, &args);
    
    // 安装越狱组件
    install_jailbreak_files();
}
```

**palera1n的文件系统挂载**：

**方法**：
- 使用自定义iBoot
- 修改内核参数
- 挂载自定义文件系统

**实现**：
- 安装自定义iBoot
- 修改启动参数
- 挂载越狱文件系统

### 9.4 文件系统挂载防御

**Apple的防护**：

**只读系统卷**：
- System Volume只读
- 无法修改
- 完整性保护

**SIP（System Integrity Protection）**：
- 系统完整性保护
- 防止修改
- 强制验证

**快照机制**：
- APFS快照
- 自动恢复
- 防篡改

---

## 10. 越狱工具分析

### 10.1 checkra1n

**概述**：

**开发者**：checkra1n团队

**支持版本**：
- iOS 12.0-14.8.1
- 基于checkm8漏洞
- semi-tethered越狱

**特点**：
- 硬件漏洞利用
- 永久可用
- 支持旧设备

**工作原理**：

```
1. 设备进入DFU模式
  ↓
2. checkra1n发送利用代码
  ↓
3. 触发checkm8漏洞
  ↓
4. 执行shellcode
  ↓
5. 加载自定义iBoot
  ↓
6. 启动越狱内核
  ↓
7. 安装越狱环境
```

**使用方法**：

**图形界面**：
```bash
# macOS
./checkra1n

# 点击"Start"
# 按照提示操作
```

**命令行**：
```bash
# 命令行模式
checkra1n -c

# 详细输出
checkra1n -v
```

**限制**：
- 只支持A5-A11设备
- 需要物理连接
- semi-tethered

### 10.2 unc0ver

**概述**：

**开发者**：Pwn20wnd

**支持版本**：
- iOS 11.0-14.8
- 软件漏洞利用
- semi-untethered越狱

**特点**：
- 功能完整
- 插件兼容
- 活跃开发

**工作原理**：

```
1. 启动unc0ver应用
  ↓
2. 点击"Jailbreak"
  ↓
3. 利用内核漏洞
  ↓
4. 获取root权限
  ↓
5. 绕过代码签名
  ↓
6. 绕过沙箱
  ↓
7. 挂载文件系统
  ↓
8. 安装越狱环境
```

**使用方法**：

**安装**：
- 通过AltStore安装
- 通过Sideloadly安装
- 通过企业证书安装

**越狱**：
```
1. 打开unc0ver
  ↓
2. 点击"Jailbreak"
  ↓
3. 等待完成
  ↓
4. 设备重启
  ↓
5. 重新打开unc0ver
  ↓
6. 再次点击"Jailbreak"
```

**限制**：
- 需要重新激活
- 软件漏洞可能被修复
- 需要定期更新

### 10.3 Taurine

**概述**：

**开发者**：Coolstar

**支持版本**：
- iOS 14.0-14.8.1
- 软件漏洞利用
- Rootless越狱

**特点**：
- Rootless设计
- 不修改系统
- 更安全

**工作原理**：

```
1. 启动Taurine应用
  ↓
2. 点击"Jailbreak"
  ↓
3. 利用内核漏洞
  ↓
4. 获取root权限
  ↓
5. 安装用户空间组件
  ↓
6. 配置Rootless环境
  ↓
7. 完成越狱
```

**Rootless特点**：

**不修改系统**：
- 不修改/System
- 不修改/usr
- 使用/var/jb

**用户空间**：
- 所有组件在用户空间
- 动态库注入
- Hook系统调用

**优势**：
- 更安全
- 更容易卸载
- 减少系统修改

### 10.4 palera1n

**概述**：

**开发者**：palera1n团队

**支持版本**：
- iOS 15.0-16.7
- 基于checkm8 + 内核漏洞
- 完整越狱

**特点**：
- 支持新设备
- 完整越狱
- 活跃开发

**工作原理**：

```
1. 设备进入DFU模式
  ↓
2. 触发checkm8漏洞
  ↓
3. 加载自定义iBoot
  ↓
4. 启动越狱内核
  ↓
5. 利用内核漏洞
  ↓
6. 获取root权限
  ↓
7. 安装越狱环境
  ↓
8. 完成越狱
```

**使用方法**：

**安装**：
```bash
# macOS
brew install palera1n

# 或从源码编译
git clone https://github.com/palera1n/palera1n
cd palera1n
make
```

**越狱**：
```bash
# 进入DFU模式
# 运行palera1n
palera1n

# 按照提示操作
```

**限制**：
- 需要A8-A11设备
- 需要物理连接
- 技术复杂

### 10.5 Dopamine

**概述**：

**开发者**：opa334

**支持版本**：
- iOS 15.0-16.6.1
- 软件漏洞利用
- Rootless越狱

**特点**：
- Rootless设计
- 现代化
- 开源

**工作原理**：

```
1. 启动Dopamine应用
  ↓
2. 点击"Jailbreak"
  ↓
3. 利用内核漏洞
  ↓
4. 获取root权限
  ↓
5. 安装用户空间组件
  ↓
6. 配置Rootless环境
  ↓
7. 完成越狱
```

**Rootless特点**：

**不修改系统**：
- 使用/var/jb
- 动态库注入
- Hook系统调用

**现代化设计**：
- 支持新特性
- 更好的兼容性
- 活跃的社区

---

## 11. 越狱持久化

### 11.1 持久化类型

**Tethered（有 tethered）**：

**特点**：
- 重启后无法启动
- 需要连接电脑
- 重新执行越狱

**使用场景**：
- 硬件漏洞利用
- 测试环境
- 开发用途

**Semi-tethered（半tethered）**：

**特点**：
- 重启后可以启动
- 但越狱功能失效
- 需要重新激活

**使用场景**：
- checkra1n
- 日常使用
- 需要时激活

**Semi-untethered（半不tethered）**：

**特点**：
- 重启后可以启动
- 越狱功能失效
- 可以在设备上重新激活

**使用场景**：
- unc0ver
- Taurine
- Dopamine

**Untethered（不tethered）**：

**特点**：
- 重启后保持越狱
- 完全持久化
- 最理想

**使用场景**：
- 旧版本iOS
- 硬件漏洞
- 完整越狱

### 11.2 持久化技术

**修改启动流程**：

**原理**：
- 修改启动脚本
- 自动执行越狱
- 保持越狱状态

**实现**：
```bash
# 修改启动脚本
echo "/usr/libexec/jailbreak" >> /etc/rc.local

# 或创建launchd plist
cat > /Library/LaunchDaemons/com.jailbreak.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.jailbreak</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/libexec/jailbreak</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF
```

**安装持久化组件**：

**组件**：
- 越狱脚本
- 动态库
- 配置文件

**安装**：
```bash
# 安装越狱脚本
cp jailbreak.sh /usr/libexec/
chmod 755 /usr/libexec/jailbreak.sh

# 安装动态库
cp substrate.dylib /usr/lib/
chmod 644 /usr/lib/substrate.dylib

# 安装配置
cp config.plist /etc/jailbreak/
```

**自动激活**：

**原理**：
- 检测越狱状态
- 自动重新激活
- 保持越狱

**实现**：
```bash
# 检测越狱状态
if [ ! -f /var/lib/jailbreak/active ]; then
    /usr/libexec/jailbreak.sh
fi
```

### 11.3 持久化案例

**checkra1n的持久化**：

**类型**：Semi-tethered

**机制**：
- 使用自定义iBoot
- 需要重新激活
- 每次重启后

**激活**：
```bash
# 连接电脑
# 运行checkra1n
checkra1n

# 或自动激活
# 需要用户操作
```

**unc0ver的持久化**：

**类型**：Semi-untethered

**机制**：
- 使用应用激活
- 不需要电脑
- 设备上操作

**激活**：
```
1. 打开unc0ver应用
  ↓
2. 点击"Jailbreak"
  ↓
3. 等待完成
```

**palera1n的持久化**：

**类型**：Semi-tethered/Untethered（取决于配置）

**机制**：
- 使用自定义iBoot
- 可以配置为untethered
- 需要技术知识

---

## 12. 越狱检测与对抗

### 12.1 越狱检测方法

**文件检测**：

**检查越狱文件**：
```swift
func isJailbroken() -> Bool {
    let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt/",
        "/usr/bin/ssh",
        "/private/var/lib/cydia",
        "/private/var/tmp/cydia.log"
    ]
    
    for path in jailbreakPaths {
        if FileManager.default.fileExists(atPath: path) {
            return true
        }
    }
    return false
}
```

**URL Scheme检测**：

**检查Cydia**：
```swift
func canOpenCydia() -> Bool {
    let cydiaURL = URL(string: "cydia://package/com.example.package")!
    return UIApplication.shared.canOpenURL(cydiaURL)
}
```

**文件系统写入检测**：

**尝试写入系统目录**：
```swift
func canWriteToSystem() -> Bool {
    let path = "/private/jailbreak_test"
    do {
        try "test".write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(atPath: path)
        return true
    } catch {
        return false
    }
}
```

**符号链接检测**：

**检查符号链接**：
```swift
func checkSymlinks() -> Bool {
    let paths = [
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/libexec/cydia",
        "/usr/bin/sshd"
    ]
    
    for path in paths {
        var statInfo = stat()
        if lstat(path, &statInfo) == 0 {
            if (statInfo.st_mode & S_IFMT) == S_IFLNK {
                return true
            }
        }
    }
    return false
}
```

**进程检测**：

**检查可疑进程**：
```swift
func checkProcesses() -> Bool {
    let suspiciousProcesses = [
        "cydia",
        "mobilesubstrate",
        "substrate",
        "substitute",
        "ellekit"
    ]
    
    // 使用sysctl获取进程列表
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
    var size: size_t = 0
    
    sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0)
    
    let count = size / MemoryLayout<kinfo_proc>.size
    var processes = [kinfo_proc](repeating: kinfo_proc(), count: count)
    
    sysctl(&mib, UInt32(mib.count), &processes, &size, nil, 0)
    
    for process in processes {
        let name = withUnsafePointer(to: &process.kp_proc.p_comm) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) {
                String(cString: $0)
            }
        }
        
        if suspiciousProcesses.contains(where: { name.lowercased().contains($0) }) {
            return true
        }
    }
    
    return false
}
```

**动态库检测**：

**检查注入的动态库**：
```swift
func checkDylibs() -> Bool {
    let suspiciousDylibs = [
        "MobileSubstrate",
        "Substrate",
        "substitute",
        "ellekit",
        "cydia"
    ]
    
    let imageCount = _dyld_image_count()
    for i in 0..<imageCount {
        if let name = _dyld_get_image_name(i) {
            let dylibName = String(cString: name)
            if suspiciousDylibs.contains(where: { dylibName.lowercased().contains($0.lowercased()) }) {
                return true
            }
        }
    }
    
    return false
}
```

### 12.2 越狱检测绕过

**Frida绕过**：

**绕过文件检测**：
```javascript
// Frida脚本
var FileManager = ObjC.classes.NSFileManager;
Interceptor.attach(FileManager['- fileExistsAtPath:'].implementation, {
    onLeave: function(retval) {
        // 如果返回true，改为返回false
        if (retval == 1) {
            retval.replace(0);
        }
    }
});
```

**绕过URL Scheme检测**：
```javascript
// Frida脚本
var UIApplication = ObjC.classes.UIApplication;
Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
    onLeave: function(retval) {
        // 总是返回false
        retval.replace(0);
    }
});
```

**绕过动态库检测**：
```javascript
// Frida脚本
var _dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');
Interceptor.attach(_dyld_get_image_name, {
    onLeave: function(retval) {
        if (!retval.isNull()) {
            var name = retval.readUtf8String();
            if (name.includes('Substrate') || name.includes('substitute')) {
                // 返回空字符串
                retval.replace(ptr(0));
            }
        }
    }
});
```

**Substrate绕过**：

**Hook检测函数**：
```javascript
// 使用Substrate
%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if ([path containsString:@"Cydia"] || [path containsString:@"MobileSubstrate"]) {
        return NO;
    }
    return %orig;
}

%end
```

### 12.3 越狱检测对抗策略

**多层检测**：

**综合检测**：
```swift
func comprehensiveJailbreakDetection() -> Bool {
    // 1. 文件路径检测
    if checkJailbreakFiles() { return true }
    
    // 2. URL Scheme检测
    if canOpenCydia() { return true }
    
    // 3. 文件系统写入检测
    if canWriteToSystem() { return true }
    
    // 4. 符号链接检测
    if checkSymlinks() { return true }
    
    // 5. 进程检测
    if checkProcesses() { return true }
    
    // 6. 动态库检测
    if checkDylibs() { return true }
    
    // 7. 环境变量检测
    if checkEnvironmentVariables() { return true }
    
    return false
}
```

**服务端验证**：

**设备验证**：
```swift
func verifyDevice() -> Bool {
    // 收集设备信息
    let deviceInfo = collectDeviceInfo()
    
    // 发送到服务端
    let verified = sendToServer(deviceInfo)
    
    return verified
}
```

**混淆检测**：

**隐藏检测逻辑**：
```swift
// 使用字符串加密
let path1 = String(data: Data(base64Encoded: "L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA=")!, encoding: .utf8)!
let path2 = String(data: Data(base64Encoded: "L3Vzci9saWIvTW9iaWxlU3Vic3RyYXRl")!, encoding: .utf8)!

// 分散检测逻辑
func check1() -> Bool { /* ... */ }
func check2() -> Bool { /* ... */ }
func check3() -> Bool { /* ... */ }

func isJailbroken() -> Bool {
    return check1() || check2() || check3()
}
```

---

## 13. 越狱风险评估

### 13.1 安全风险

**恶意软件风险**：

**未授权应用**：
- 可能包含恶意代码
- 窃取用户数据
- 破坏系统

**插件风险**：
- 插件可能有漏洞
- 插件可能冲突
- 插件可能不稳定

**系统稳定性**：

**系统崩溃**：
- 越狱可能导致崩溃
- 插件冲突
- 系统不稳定

**性能问题**：
- 越狱可能影响性能
- 电池消耗增加
- 内存使用增加

**数据安全风险**：

**数据泄露**：
- 越狱设备更容易被攻击
- 数据可能被窃取
- 隐私泄露

**备份风险**：
- 越狱备份可能包含敏感数据
- 恢复后可能引入风险
- 备份不完整

### 13.2 功能风险

**应用兼容性**：

**应用拒绝运行**：
- 银行应用检测越狱
- 游戏应用拒绝运行
- 企业应用限制

**功能限制**：
- 某些功能不可用
- Apple Pay可能失效
- 某些服务拒绝

**更新问题**：

**系统更新**：
- 更新可能破坏越狱
- 需要重新越狱
- 可能丢失数据

**应用更新**：
- 应用更新可能检测越狱
- 功能可能失效
- 需要重新配置

### 13.3 法律风险

**法律地位**：

**美国**：
- 越狱合法（DMCA豁免）
- 但可能违反保修条款
- 可能违反服务条款

**欧盟**：
- 越狱合法
- 但可能违反保修
- 各国法律不同

**中国**：
- 法律不明确
- 可能违反服务条款
- 风险自负

**保修问题**：

**Apple保修**：
- 越狱可能使保修失效
- Apple可能拒绝服务
- 需要恢复设备

**第三方保修**：
- 可能影响第三方保修
- 需要咨询提供商
- 可能拒绝服务

### 13.4 风险缓解

**安全实践**：

**只安装可信插件**：
- 从官方源安装
- 检查插件评价
- 避免未知来源

**定期更新**：
- 更新越狱工具
- 更新插件
- 更新系统（谨慎）

**备份数据**：
- 定期备份
- 加密备份
- 测试恢复

**功能保护**：

**使用兼容应用**：
- 检查应用兼容性
- 避免关键应用
- 准备替代方案

**谨慎更新**：
- 等待越狱更新
- 测试更新
- 备份后再更新

---

## 14. 越狱法律与伦理

### 14.1 法律地位

**美国法律**：

**DMCA豁免**：
- 2010年起，越狱合法
- 每三年更新一次
- 适用于智能手机

**限制**：
- 不适用于平板（有争议）
- 不适用于游戏机
- 可能违反服务条款

**欧盟法律**：

**合法性**：
- 大多数国家合法
- 但可能违反保修
- 各国法律不同

**限制**：
- 可能违反服务条款
- 可能影响保修
- 需要遵守当地法律

**中国法律**：

**法律地位**：
- 法律不明确
- 可能违反服务条款
- 风险自负

**限制**：
- 可能违反Apple服务条款
- 可能影响保修
- 需要谨慎

### 14.2 伦理考虑

**知识产权**：

**软件修改**：
- 修改Apple软件
- 可能违反许可协议
- 需要尊重知识产权

**插件开发**：
- 尊重原作者
- 遵守开源许可
- 不侵犯版权

**用户权利**：

**设备所有权**：
- 用户拥有设备
- 有权修改设备
- 但可能违反条款

**自由选择**：
- 用户有权选择
- 了解风险和后果
- 自主决定

**安全研究**：

**研究目的**：
- 促进安全
- 发现漏洞
- 改进产品

**责任披露**：
- 负责任的披露
- 给厂商修复时间
- 不恶意利用

### 14.3 越狱的道德边界

**合法用途**：

**个人使用**：
- 自定义设备
- 安装合法插件
- 个人偏好

**安全研究**：
- 研究安全机制
- 发现漏洞
- 改进安全

**教育目的**：
- 学习iOS安全
- 理解系统架构
- 培养技能

**不当用途**：

**盗版软件**：
- 安装盗版应用
- 侵犯版权
- 违法行为

**恶意攻击**：
- 利用越狱攻击他人
- 传播恶意软件
- 窃取数据

**商业滥用**：
- 未经授权的商业使用
- 违反服务条款
- 可能违法

---

## 15. 未越狱设备的安全建议

### 15.1 保持系统更新

**及时更新**：

**系统更新**：
- 安装最新iOS版本
- 修复安全漏洞
- 获得新功能

**应用更新**：
- 更新所有应用
- 修复应用漏洞
- 获得新功能

**自动更新**：
```
设置 > 通用 > 软件更新 > 自动更新
  ↓
启用"下载iOS更新"
  ↓
启用"安装iOS更新"
```

### 15.2 应用安全

**只安装官方应用**：

**App Store**：
- 只从App Store安装
- 避免第三方商店
- 检查应用评价

**应用审核**：
- Apple审核应用
- 检查恶意代码
- 确保安全性

**权限管理**：

**审查权限**：
```
设置 > 隐私与安全性
  ↓
查看应用权限
  ↓
限制不必要的权限
```

**最小权限**：
- 只授予必要权限
- 定期审查权限
- 撤销不需要的权限

### 15.3 数据安全

**启用加密**：

**数据保护**：
```
设置 > Face ID与密码（或Touch ID与密码）
  ↓
启用"数据保护"
```

**iCloud备份**：
- 启用iCloud备份
- 加密备份
- 定期备份

**密码管理**：

**强密码**：
- 使用复杂密码
- 避免重复使用
- 定期更换

**双因素认证**：
```
设置 > Apple ID > 密码与安全性
  ↓
启用"双因素认证"
```

### 15.4 网络安全

**安全Wi-Fi**：

**避免公共Wi-Fi**：
- 避免不安全的Wi-Fi
- 使用VPN
- 谨慎连接

**VPN使用**：
- 使用可信VPN
- 加密网络流量
- 保护隐私

**安全浏览**：

**Safari安全**：
- 启用欺诈网站警告
- 阻止弹出窗口
- 使用隐私浏览

**避免钓鱼**：
- 警惕可疑链接
- 验证网站真实性
- 不点击可疑链接

### 15.5 物理安全

**设备锁定**：

**自动锁定**：
```
设置 > 显示与亮度 > 自动锁定
  ↓
设置短时间（30秒或1分钟）
```

**强密码**：
- 使用复杂密码
- 避免简单密码
- 启用Face ID/Touch ID

**查找我的iPhone**：

**启用查找**：
```
设置 > Apple ID > 查找
  ↓
启用"查找我的iPhone"
```

**功能**：
- 定位设备
- 远程锁定
- 远程擦除

---

## 16. 越狱技术发展趋势

### 16.1 硬件漏洞趋势

**checkm8的影响**：

**永久漏洞**：
- 影响A5-A11芯片
- 无法通过软件修复
- 永久可用

**后续影响**：
- 推动了Rootless越狱
- 促进了安全研究
- 影响了Apple安全策略

**新硬件漏洞**：

**可能性**：
- 新芯片可能有新漏洞
- 需要持续研究
- 可能被发现

**挑战**：
- Apple加强硬件安全
- 更复杂的设计
- 更难发现漏洞

### 16.2 软件漏洞趋势

**漏洞难度增加**：

**安全加固**：
- Apple持续加固
- 更多缓解措施
- 更难发现漏洞

**研究成本**：
- 需要更多时间
- 需要更多资源
- 需要更深入理解

**Rootless趋势**：

**Rootless越狱**：
- 不修改系统
- 用户空间技术
- 更安全

**优势**：
- 减少系统修改
- 更容易卸载
- 更好的兼容性

**挑战**：
- 技术复杂
- 兼容性挑战
- 需要新技术

### 16.3 越狱工具趋势

**工具演进**：

**从简单到复杂**：
- 早期：简单工具
- 现代：复杂框架
- 未来：更智能

**从tethered到untethered**：
- 早期：tethered
- 现代：semi-untethered
- 未来：untethered

**社区发展**：

**开源社区**：
- 更多开源工具
- 社区协作
- 知识共享

**商业化**：
- 商业越狱工具
- 付费服务
- 专业支持

### 16.4 未来展望

**技术挑战**：

**Apple安全**：
- 持续加强
- 新技术
- 新挑战

**研究者**：
- 需要创新
- 需要深入
- 需要坚持

**生态变化**：

**越狱生态**：
- 可能萎缩
- 转向安全研究
- 新的用途

**安全研究**：
- 更多关注
- 更多资源
- 更多价值

---

## 附录

### A. 越狱工具对比

| 工具 | 支持版本 | 类型 | 持久性 | 特点 |
|------|---------|------|--------|------|
| checkra1n | iOS 12-14 | 硬件 | Semi-tethered | checkm8漏洞 |
| unc0ver | iOS 11-14 | 软件 | Semi-untethered | 功能完整 |
| Taurine | iOS 14 | 软件 | Semi-untethered | Rootless |
| palera1n | iOS 15-16 | 硬件+软件 | Semi-tethered | 新设备支持 |
| Dopamine | iOS 15-16 | 软件 | Semi-untethered | Rootless |

### B. 越狱术语表

**Tethered**：需要电脑才能启动  
**Semi-tethered**：可以启动但越狱失效  
**Semi-untethered**：可以在设备上重新激活  
**Untethered**：完全持久化  
**Rootless**：不修改系统文件  
**DFU**：Device Firmware Update模式  
**iBoot**：iOS引导加载器  
**AMFI**：Apple Mobile File Integrity  

### C. 参考资料

**Apple官方**：
- iOS Security Guide
- Code Signing
- App Sandbox

**越狱社区**：
- checkra1n
- unc0ver
- palera1n

**安全研究**：
- Google Project Zero
- Citizen Lab
- iDevice Research

---

**咨询ios系统请咨询 telegram：@pengqing666**

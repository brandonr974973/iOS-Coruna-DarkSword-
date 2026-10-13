# iOS防御检测与逆向工程

## iOS Defense Detection and Reverse Engineering

---

**作者**: pengqinglei99-eng  
**日期**: 2026年10月14日  
**版本**: 1.0  
**联系**: telegram：@pengqing666

---

## 目录

1. [防御检测概述](#1-防御检测概述)
2. [越狱检测技术](#2-越狱检测技术)
3. [调试器检测](#3-调试器检测)
4. [代码注入检测](#4-代码注入检测)
5. [运行时完整性检查](#5-运行时完整性检查)
6. [反逆向工程技术](#6-反逆向工程技术)
7. [代码混淆技术](#7-代码混淆技术)
8. [二进制保护机制](#8-二进制保护机制)
9. [运行时保护机制](#9-运行时保护机制)
10. [网络通信保护](#10-网络通信保护)
11. [数据存储保护](#11-数据存储保护)
12. [逆向工程工具与方法](#12-逆向工程工具与方法)
13. [静态分析技术](#13-静态分析技术)
14. [动态分析技术](#14-动态分析技术)
15. [防御绕过与对抗](#15-防御绕过与对抗)
16. [防御策略最佳实践](#16-防御策略最佳实践)

---

## 1. 防御检测概述

### 1.1 防御检测的目的

防御检测是指应用或系统检测自身是否处于受攻击环境的技术：

**核心目标**：

**环境检测**：
- 检测设备是否越狱
- 检测是否被调试
- 检测是否被注入

**完整性验证**：
- 验证代码完整性
- 验证数据完整性
- 验证配置完整性

**行为监控**：
- 监控异常行为
- 检测攻击尝试
- 记录安全事件

### 1.2 防御检测的层次

**应用层防御**：

**越狱检测**：
- 检查越狱文件
- 检查Cydia
- 检查权限

**调试器检测**：
- 检测调试器附加
- 检测断点
- 检测分析环境

**代码注入检测**：
- 检测dylib注入
- 检测hook
- 检测修改

**系统层防御**：

**代码签名验证**：
- 强制代码签名
- 完整性检查
- 防篡改

**沙箱隔离**：
- 应用隔离
- 权限限制
- 资源控制

**内存保护**：
- ASLR
- DEP/NX
- PAC

### 1.3 防御检测的重要性

**保护知识产权**：
- 防止代码被盗
- 防止算法被复制
- 保护商业机密

**保护用户数据**：
- 防止数据泄露
- 防止中间人攻击
- 保护隐私

**防止欺诈**：
- 防止游戏作弊
- 防止金融欺诈
- 防止功能滥用

**合规要求**：
- 满足法规要求
- 通过安全审计
- 建立信任

---

## 2. 越狱检测技术

### 2.1 文件路径检测

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

**检测原理**：
- 越狱工具会安装特定文件
- 检查这些文件是否存在
- 存在则表示设备已越狱

**局限性**：
- 路径可能被隐藏
- 文件系统可能被修改
- 需要结合其他检测

### 2.2 URL Scheme检测

**检查Cydia**：

```swift
func canOpenCydia() -> Bool {
    let cydiaURL = URL(string: "cydia://package/com.example.package")!
    return UIApplication.shared.canOpenURL(cydiaURL)
}
```

**检测原理**：
- Cydia注册了自定义URL scheme
- 检查是否可以打开Cydia
- 可以打开则表示已越狱

**局限性**：
- iOS 9+需要声明LSApplicationQueriesSchemes
- 可能被绕过
- 不是所有越狱都安装Cydia

### 2.3 文件系统写入检测

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

**检测原理**：
- 非越狱设备无法写入系统目录
- 尝试写入并检查是否成功
- 成功则表示已越狱

**局限性**：
- 可能被沙箱阻止
- 需要清理测试文件
- 可能触发安全警告

### 2.4 符号链接检测

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

**检测原理**：
- 越狱工具会创建符号链接
- 检查特定路径是否为符号链接
- 是符号链接则表示已越狱

**局限性**：
- 符号链接可能被删除
- 需要root权限检查某些路径
- 可能被绕过

### 2.5 进程检测

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

**检测原理**：
- 越狱工具会运行特定进程
- 检查进程列表中是否存在这些进程
- 存在则表示已越狱

**局限性**：
- 进程名可能被修改
- 需要特殊权限
- 可能被隐藏

### 2.6 动态库检测

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

**检测原理**：
- 越狱工具会注入动态库
- 检查已加载的动态库列表
- 存在可疑库则表示已越狱

**局限性**：
- 库名可能被修改
- 可能被隐藏
- 需要深入分析

### 2.7 综合越狱检测

**多层检测**：

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

**优势**：
- 多层检测提高准确性
- 单一检测失败不影响整体
- 增加绕过难度

**最佳实践**：
- 使用多种检测方法
- 定期更新检测逻辑
- 结合服务端验证

---

## 3. 调试器检测

### 3.1 sysctl检测

**检查P_TRACED标志**：

```swift
func isDebuggerAttached() -> Bool {
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    
    if sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 {
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    return false
}
```

**检测原理**：
- 调试器附加时会设置P_TRACED标志
- 使用sysctl检查进程标志
- 标志存在则表示被调试

**优势**：
- 简单可靠
- 难以绕过
- 系统级检测

**局限性**：
- 只能在调试器附加后检测
- 可能被hook绕过
- 需要root权限修改

### 3.2 ptrace检测

**使用PT_DENY_ATTACH**：

```swift
func denyDebuggerAttach() {
    // 导入ptrace
    typealias ptraceFunc = @convention(c) (CInt, CInt, CInt, CInt) -> CInt
    let ptrace = unsafeBitCast(dlsym(dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOW), "ptrace"), to: ptraceFunc.self)
    
    // 拒绝调试器附加
    ptrace(PT_DENY_ATTACH, 0, 0, 0)
}
```

**检测原理**：
- PT_DENY_ATTACH阻止调试器附加
- 调用后调试器无法附加
- 防止动态分析

**优势**：
- 主动防御
- 阻止调试
- 难以绕过

**局限性**：
- 影响正常调试
- 可能被绕过
- 需要正确处理

### 3.3 断点检测

**检测软件断点**：

```swift
func checkBreakpoints() -> Bool {
    // ARM64断点指令：0xD4200000
    let breakpointInstruction: UInt32 = 0xD4200000
    
    // 检查关键函数的第一条指令
    let functions = [
        unsafeBitCast(isDebuggerAttached, to: UnsafeRawPointer.self),
        // 添加其他关键函数
    ]
    
    for function in functions {
        let instruction = function.load(as: UInt32.self)
        if instruction == breakpointInstruction {
            return true
        }
    }
    
    return false
}
```

**检测原理**：
- 软件断点通过修改指令实现
- 检查关键函数的指令是否被修改
- 被修改则表示有断点

**优势**：
- 检测断点
- 防止调试
- 保护关键代码

**局限性**：
- 只能检测软件断点
- 硬件断点无法检测
- 可能被绕过

### 3.4 时间检测

**检测执行时间异常**：

```swift
func checkTiming() -> Bool {
    let start = mach_absolute_time()
    
    // 执行一段代码
    var sum = 0
    for i in 0..<1000000 {
        sum += i
    }
    
    let end = mach_absolute_time()
    let elapsed = end - start
    
    // 如果执行时间异常长，可能被单步调试
    let threshold: UInt64 = 1000000 // 根据测试调整
    return elapsed > threshold
}
```

**检测原理**：
- 调试器单步执行会显著增加执行时间
- 测量代码执行时间
- 时间异常则表示被调试

**优势**：
- 检测单步调试
- 难以绕过
- 主动防御

**局限性**：
- 可能误报（系统负载）
- 需要调整阈值
- 影响性能

### 3.5 异常处理检测

**检测调试器异常处理**：

```swift
func checkExceptionHandler() -> Bool {
    // 设置异常处理器
    let handler = NSGetUncaughtExceptionHandler()
    
    // 检查是否被修改
    // 如果异常处理器被修改，可能被调试
    return handler != expectedHandler
}
```

**检测原理**：
- 调试器可能会修改异常处理器
- 检查异常处理器是否被修改
- 被修改则表示被调试

**优势**：
- 检测调试器
- 保护异常处理
- 难以绕过

**局限性**：
- 可能误报
- 需要正确设置
- 可能被绕过

---

## 4. 代码注入检测

### 4.1 动态库注入检测

**检查已加载的动态库**：

```swift
func checkInjectedLibraries() -> Bool {
    let suspiciousLibraries = [
        "MobileSubstrate",
        "Substrate",
        "substitute",
        "ellekit",
        "cycript",
        "frida"
    ]
    
    let imageCount = _dyld_image_count()
    for i in 0..<imageCount {
        if let name = _dyld_get_image_name(i) {
            let dylibName = String(cString: name).lowercased()
            if suspiciousLibraries.contains(where: { dylibName.contains($0.lowercased()) }) {
                return true
            }
        }
    }
    
    return false
}
```

**检测原理**：
- 代码注入通常通过动态库实现
- 检查已加载的动态库列表
- 存在可疑库则表示被注入

**优势**：
- 检测常见注入工具
- 简单有效
- 难以隐藏

**局限性**：
- 库名可能被修改
- 可能被隐藏
- 需要更新列表

### 4.2 函数Hook检测

**检测函数是否被Hook**：

```swift
func checkFunctionHook(function: UnsafeRawPointer) -> Bool {
    // ARM64跳转指令：0x14000000 (B instruction)
    let jumpInstruction: UInt32 = 0x14000000
    
    let instruction = function.load(as: UInt32.self)
    
    // 检查是否是跳转指令
    if (instruction & 0xFC000000) == jumpInstruction {
        return true
    }
    
    return false
}
```

**检测原理**：
- 函数Hook通常通过修改函数入口实现
- 检查函数入口是否被修改为跳转指令
- 被修改则表示被Hook

**优势**：
- 检测函数Hook
- 保护关键函数
- 主动防御

**局限性**：
- 只能检测inline hook
- GOT/PLT hook无法检测
- 可能被绕过

### 4.3 Objective-C方法Swizzle检测

**检测方法是否被Swizzle**：

```swift
func checkMethodSwizzle(cls: AnyClass, selector: Selector) -> Bool {
    guard let method = class_getInstanceMethod(cls, selector) else {
        return false
    }
    
    let implementation = method_getImplementation(method)
    
    // 检查实现是否在预期的类中
    // 如果被swizzle，实现可能指向其他位置
    
    // 获取方法的原始实现
    let originalIMP = class_getMethodImplementation(cls, selector)
    
    // 检查实现是否一致
    return implementation != originalIMP
}
```

**检测原理**：
- 方法swizzle会修改方法实现
- 检查方法实现是否被修改
- 被修改则表示被swizzle

**优势**：
- 检测Objective-C hook
- 保护关键方法
- 难以绕过

**局限性**：
- 只能检测Objective-C方法
- Swift方法无法检测
- 可能被绕过

### 4.4 Frida检测

**检测Frida注入**：

```swift
func detectFrida() -> Bool {
    // 1. 检查Frida端口
    let fridaPorts = [27042, 27043]
    
    for port in fridaPorts {
        let socket_fd = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = UInt32(0x7F000001).bigEndian // 127.0.0.1
        
        if connect(socket_fd, UnsafeMutablePointer<sockaddr>(OpaquePointer(&addr)), socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 {
            close(socket_fd)
            return true
        }
        close(socket_fd)
    }
    
    // 2. 检查Frida字符串
    let imageCount = _dyld_image_count()
    for i in 0..<imageCount {
        if let name = _dyld_get_image_name(i) {
            let dylibName = String(cString: name).lowercased()
            if dylibName.contains("frida") {
                return true
            }
        }
    }
    
    return false
}
```

**检测原理**：
- Frida使用特定端口通信
- 检查Frida端口是否开放
- 检查Frida动态库是否加载

**优势**：
- 检测Frida
- 多层检测
- 难以绕过

**局限性**：
- 端口可能被修改
- 可能被隐藏
- 需要更新检测

---

## 5. 运行时完整性检查

### 5.1 代码段完整性

**检查代码段是否被修改**：

```swift
func checkCodeIntegrity() -> Bool {
    // 获取代码段地址和大小
    guard let codeStart = UnsafeRawPointer(#dsohandle) else {
        return false
    }
    
    // 计算代码段哈希
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CC_SHA256(codeStart, codeSize, &hash)
    
    // 与预期哈希比较
    let expectedHash = "..." // 预计算的哈希值
    
    return hash.map { String(format: "%02x", $0) }.joined() == expectedHash
}
```

**检测原理**：
- 代码段在运行时不应该被修改
- 计算代码段哈希
- 与预期哈希比较

**优势**：
- 检测代码修改
- 保护关键代码
- 难以绕过

**局限性**：
- 需要预计算哈希
- 更新后需要重新计算
- 可能被绕过

### 5.2 字符串完整性

**检查关键字符串是否被修改**：

```swift
func checkStringIntegrity() -> Bool {
    let criticalStrings = [
        "isJailbroken",
        "isDebuggerAttached",
        "checkInjection"
    ]
    
    for str in criticalStrings {
        // 检查字符串是否存在于二进制中
        // 如果被修改或移除，可能表示被攻击
        if !binaryContains(str) {
            return false
        }
    }
    
    return true
}
```

**检测原理**：
- 关键字符串不应该被修改
- 检查字符串是否存在
- 不存在则表示被修改

**优势**：
- 简单有效
- 检测修改
- 难以绕过

**局限性**：
- 字符串可能被加密
- 可能被替换
- 需要更新列表

### 5.3 资源文件完整性

**检查资源文件是否被修改**：

```swift
func checkResourceIntegrity() -> Bool {
    let resources = [
        "main.storyboard",
        "Assets.car",
        "Info.plist"
    ]
    
    for resource in resources {
        guard let path = Bundle.main.path(forResource: resource, ofType: nil) else {
            return false
        }
        
        // 计算文件哈希
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return false
        }
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        
        // 与预期哈希比较
        // ...
    }
    
    return true
}
```

**检测原理**：
- 资源文件不应该被修改
- 计算文件哈希
- 与预期哈希比较

**优势**：
- 检测资源修改
- 保护关键资源
- 难以绕过

**局限性**：
- 需要预计算哈希
- 更新后需要重新计算
- 可能被绕过

---

## 6. 反逆向工程技术

### 6.1 字符串加密

**加密敏感字符串**：

```swift
class StringEncryptor {
    static func encrypt(_ string: String, key: String) -> String {
        var result = ""
        for (i, char) in string.enumerated() {
            let keyChar = key[key.index(key.startIndex, offsetBy: i % key.count)]
            let encrypted = Character(UnicodeScalar(Int(char.asciiValue!) ^ Int(keyChar.asciiValue!))!)
            result.append(encrypted)
        }
        return result
    }
    
    static func decrypt(_ encrypted: String, key: String) -> String {
        return encrypt(encrypted, key: key) // XOR是对称的
    }
}

// 使用
let encrypted = StringEncryptor.encrypt("sensitive_string", key: "secret_key")
// 运行时解密
let decrypted = StringEncryptor.decrypt(encrypted, key: "secret_key")
```

**优势**：
- 防止字符串被直接读取
- 增加逆向难度
- 保护敏感信息

**局限性**：
- 密钥可能被提取
- 运行时仍然可见
- 可能被动态分析

### 6.2 控制流混淆

**扁平化控制流**：

```swift
// 原始代码
func original() {
    if condition1 {
        doSomething1()
    } else if condition2 {
        doSomething2()
    } else {
        doSomething3()
    }
}

// 混淆后
func obfuscated() {
    var state = 0
    while true {
        switch state {
        case 0:
            if condition1 { state = 1 }
            else if condition2 { state = 2 }
            else { state = 3 }
        case 1:
            doSomething1()
            state = 4
        case 2:
            doSomething2()
            state = 4
        case 3:
            doSomething3()
            state = 4
        case 4:
            return
        default:
            break
        }
    }
}
```

**优势**：
- 增加分析难度
- 隐藏真实逻辑
- 防止静态分析

**局限性**：
- 影响性能
- 可能被去混淆
- 增加代码大小

### 6.3 代码虚拟化

**使用自定义虚拟机**：

```swift
// 定义虚拟机指令
enum VMOpcode: UInt8 {
    case add = 0x01
    case sub = 0x02
    case mul = 0x03
    case div = 0x04
    case load = 0x05
    case store = 0x06
    case jump = 0x07
    case call = 0x08
    case ret = 0x09
}

// 虚拟机执行器
class VMExecutor {
    var registers: [Int] = [0, 0, 0, 0]
    var stack: [Int] = []
    
    func execute(bytecode: [UInt8]) {
        var pc = 0
        while pc < bytecode.count {
            let opcode = VMOpcode(rawValue: bytecode[pc])!
            pc += 1
            
            switch opcode {
            case .add:
                registers[0] = registers[1] + registers[2]
            case .sub:
                registers[0] = registers[1] - registers[2]
            // ... 其他指令
            case .ret:
                return
            default:
                break
            }
        }
    }
}
```

**优势**：
- 极大增加逆向难度
- 隐藏真实逻辑
- 防止静态分析

**局限性**：
- 性能开销大
- 实现复杂
- 可能被动态分析

### 6.4 反调试技术

**检测调试器**：

```swift
func antiDebug() {
    // 1. sysctl检测
    if isDebuggerAttached() {
        exit(0)
    }
    
    // 2. ptrace检测
    denyDebuggerAttach()
    
    // 3. 时间检测
    if checkTiming() {
        exit(0)
    }
    
    // 4. 断点检测
    if checkBreakpoints() {
        exit(0)
    }
}
```

**优势**：
- 阻止调试
- 保护代码
- 增加分析难度

**局限性**：
- 可能被绕过
- 影响正常调试
- 需要多种技术组合

---

## 7. 代码混淆技术

### 7.1 符号混淆

**重命名符号**：

```swift
// 原始
class UserManager {
    func getUserPassword(userId: String) -> String {
        // ...
    }
}

// 混淆后
class a {
    func b(c: String) -> String {
        // ...
    }
}
```

**工具**：
- Swift编译器优化
- 第三方混淆工具
- 自定义脚本

**优势**：
- 隐藏代码结构
- 增加理解难度
- 保护知识产权

**局限性**：
- 不影响功能分析
- 可能被去混淆
- 需要维护映射

### 7.2 数据流混淆

**混淆数据流**：

```swift
// 原始
func calculate(x: Int, y: Int) -> Int {
    return x * 2 + y * 3
}

// 混淆
func calculate(x: Int, y: Int) -> Int {
    var a = x
    var b = y
    var c = 0
    
    for _ in 0..<2 {
        c += a
    }
    
    for _ in 0..<3 {
        c += b
    }
    
    return c
}
```

**优势**：
- 隐藏真实逻辑
- 增加分析难度
- 防止自动化分析

**局限性**：
- 影响性能
- 可能被优化
- 增加代码大小

### 7.3 死代码插入

**插入无用代码**：

```swift
func realFunction() -> Int {
    // 真实逻辑
    return 42
}

func obfuscatedFunction() -> Int {
    // 死代码
    var x = 0
    for i in 0..<100 {
        x += i
    }
    
    // 真实逻辑
    let result = realFunction()
    
    // 更多死代码
    var y = 0
    for i in 0..<100 {
        y += i
    }
    
    return result
}
```

**优势**：
- 增加分析难度
- 隐藏真实逻辑
- 防止自动化分析

**局限性**：
- 增加代码大小
- 影响性能
- 可能被识别

### 7.4 不透明谓词

**使用不透明谓词**：

```swift
func checkCondition() -> Bool {
    // 不透明谓词：总是返回true，但难以分析
    let x = 42
    let y = x * 2
    let z = y - x
    return z == x // 总是true
}

func protectedFunction() {
    if checkCondition() {
        // 真实逻辑
    } else {
        // 永远不会执行
    }
}
```

**优势**：
- 隐藏控制流
- 增加分析难度
- 防止静态分析

**局限性**：
- 可能被动态分析
- 影响性能
- 可能被识别

---

## 8. 二进制保护机制

### 8.1 ASLR（地址空间布局随机化）

**ASLR原理**：

- 随机化代码段地址
- 随机化数据段地址
- 随机化堆栈地址
- 随机化库地址

**iOS ASLR**：
- 32位：有限的随机化
- 64位：强大的随机化
- 每次启动不同

**优势**：
- 增加利用难度
- 防止固定地址攻击
- 需要信息泄露

**局限性**：
- 可能被信息泄露绕过
- 32位随机化有限
- 需要结合其他保护

### 8.2 DEP/NX（数据执行保护）

**DEP原理**：

- 数据段不可执行
- 代码段不可写入
- W^X策略

**iOS DEP**：
- 强制执行
- 硬件支持
- 内核强制执行

**优势**：
- 防止代码注入
- 防止shellcode执行
- 强制分离

**局限性**：
- 可能被ROP绕过
- JIT需要特殊处理
- 需要结合其他保护

### 8.3 Stack Canary（栈金丝雀）

**Stack Canary原理**：

- 在栈帧中插入随机值
- 函数返回前检查
- 检测栈溢出

**iOS Stack Canary**：
- 编译器自动插入
- 随机生成
- 强制执行

**优势**：
- 检测栈溢出
- 防止返回地址覆盖
- 自动保护

**局限性**：
- 可能被信息泄露绕过
- 不影响堆溢出
- 需要结合其他保护

### 8.4 PIE（位置无关可执行文件）

**PIE原理**：

- 可执行文件可以加载到任意地址
- 配合ASLR使用
- 增加利用难度

**iOS PIE**：
- 默认启用
- 强制要求
- App Store要求

**优势**：
- 配合ASLR
- 增加利用难度
- 防止固定地址攻击

**局限性**：
- 轻微性能影响
- 需要结合ASLR
- 可能被绕过

### 8.5 ARC（自动引用计数）

**ARC原理**：

- 自动管理内存
- 插入retain/release
- 防止内存泄漏

**iOS ARC**：
- 编译器自动插入
- 强制执行
- 减少UAF

**优势**：
- 减少内存漏洞
- 自动管理
- 提高安全性

**局限性**：
- 不能完全防止UAF
- 循环引用问题
- 性能开销

---

## 9. 运行时保护机制

### 9.1 沙箱（Sandbox）

**沙箱原理**：

- 限制应用权限
- 隔离应用资源
- 强制访问控制

**iOS沙箱**：
- 强制实施
- 细粒度控制
- 内核强制执行

**优势**：
- 限制应用权限
- 防止横向移动
- 保护系统资源

**局限性**：
- 可能被沙箱逃逸绕过
- 需要正确配置
- 影响功能

### 9.2 代码签名（Code Signing）

**代码签名原理**：

- 验证代码来源
- 确保代码完整性
- 防止篡改

**iOS代码签名**：
- 强制要求
- Apple签名
- 硬件验证

**优势**：
- 验证代码来源
- 确保完整性
- 防止篡改

**局限性**：
- 可能被绕过（越狱）
- 需要正确实现
- 不影响逻辑漏洞

### 9.3 Entitlements（权限声明）

**Entitlements原理**：

- 声明应用权限
- 系统验证
- 运行时检查

**iOS Entitlements**：
- 编译时声明
- Apple审核
- 运行时验证

**优势**：
- 明确权限
- 系统验证
- 用户控制

**局限性**：
- 可能被滥用
- 需要正确配置
- 不影响逻辑漏洞

### 9.4 Keychain（钥匙串）

**Keychain原理**：

- 安全存储凭据
- 加密保护
- 访问控制

**iOS Keychain**：
- 硬件加密
- 访问控制
- 跨设备同步

**优势**：
- 安全存储
- 加密保护
- 访问控制

**局限性**：
- 可能被提取（越狱）
- 需要正确使用
- 性能开销

---

## 10. 网络通信保护

### 10.1 TLS/SSL

**TLS原理**：

- 加密通信
- 身份验证
- 完整性保护

**iOS TLS**：
- ATS强制
- 现代协议
- 强密码套件

**优势**：
- 加密通信
- 防止窃听
- 身份验证

**局限性**：
- 可能被中间人攻击
- 需要正确配置
- 性能开销

### 10.2 证书固定（Certificate Pinning）

**证书固定原理**：

- 固定服务器证书
- 防止中间人攻击
- 验证证书

**iOS证书固定**：

```swift
class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        if let serverTrust = challenge.protectionSpace.serverTrust {
            // 获取服务器证书
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)!
            
            // 获取证书数据
            let serverCertificateData = SecCertificateCopyData(certificate) as Data
            
            // 与固定证书比较
            let pinnedCertificate = "..." // 固定的证书数据
            
            if serverCertificateData == pinnedCertificate {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

**优势**：
- 防止中间人攻击
- 验证服务器身份
- 增强安全性

**局限性**：
- 证书更新困难
- 可能被绕过
- 需要正确实现

### 10.3 请求签名

**请求签名原理**：

- 签名请求参数
- 防止篡改
- 验证来源

**iOS请求签名**：

```swift
func signRequest(params: [String: Any], secret: String) -> String {
    // 排序参数
    let sortedKeys = params.keys.sorted()
    var queryString = ""
    
    for key in sortedKeys {
        queryString += "\(key)=\(params[key]!)&"
    }
    
    // 添加密钥
    queryString += secret
    
    // 计算哈希
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    queryString.withCString {
        _ = CC_SHA256($0, CC_LONG(strlen($0)), &hash)
    }
    
    return hash.map { String(format: "%02x", $0) }.joined()
}
```

**优势**：
- 防止参数篡改
- 验证请求来源
- 增强安全性

**局限性**：
- 密钥可能被提取
- 可能被重放
- 需要正确实现

### 10.4 数据加密

**数据加密原理**：

- 加密敏感数据
- 防止窃听
- 保护隐私

**iOS数据加密**：

```swift
import CryptoKit

func encryptData(data: Data, key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.seal(data, using: key)
    return sealedBox.combined!
}

func decryptData(data: Data, key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.SealedBox(combined: data)
    return try AES.GCM.open(sealedBox, using: key)
}
```

**优势**：
- 保护敏感数据
- 防止窃听
- 符合合规要求

**局限性**：
- 密钥管理困难
- 性能开销
- 需要正确实现

---

## 11. 数据存储保护

### 11.1 Keychain存储

**Keychain原理**：

- 安全存储凭据
- 加密保护
- 访问控制

**iOS Keychain使用**：

```swift
import Security

func saveToKeychain(key: String, data: Data) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    
    return status == errSecSuccess
}

func loadFromKeychain(key: String) -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    if status == errSecSuccess {
        return result as? Data
    }
    
    return nil
}
```

**优势**：
- 安全存储
- 加密保护
- 访问控制

**局限性**：
- 可能被提取（越狱）
- 需要正确使用
- 性能开销

### 11.2 文件加密

**文件加密原理**：

- 加密文件内容
- 保护敏感数据
- 防止未授权访问

**iOS文件加密**：

```swift
func encryptFile(at path: String, key: Data) throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    
    // 使用AES加密
    let encrypted = try AES.encrypt(data, key: key)
    
    // 写入加密文件
    try encrypted.write(to: URL(fileURLWithPath: path + ".encrypted"))
    
    // 删除原文件
    try FileManager.default.removeItem(atPath: path)
}
```

**优势**：
- 保护文件内容
- 防止未授权访问
- 符合合规要求

**局限性**：
- 密钥管理困难
- 性能开销
- 需要正确实现

### 11.3 数据库加密

**数据库加密原理**：

- 加密数据库内容
- 保护敏感数据
- 防止未授权访问

**iOS数据库加密**：

**使用SQLCipher**：

```swift
import SQLCipher

func openEncryptedDatabase(path: String, key: String) -> OpaquePointer? {
    var db: OpaquePointer?
    
    if sqlite3_open(path, &db) == SQLITE_OK {
        // 设置加密密钥
        sqlite3_key(db, key, Int32(key.utf8.count))
        
        // 测试密钥
        if sqlite3_exec(db, "SELECT count(*) FROM sqlite_master", nil, nil, nil) != SQLITE_OK {
            sqlite3_close(db)
            return nil
        }
        
        return db
    }
    
    return nil
}
```

**优势**：
- 保护数据库内容
- 透明加密
- 符合合规要求

**局限性**：
- 密钥管理困难
- 性能开销
- 需要正确实现

### 11.4 敏感数据保护

**保护敏感数据**：

```swift
// 不要存储敏感数据
// 使用后立即清除
var password = "sensitive_password"
// 使用密码
// ...

// 清除内存
memset(&password, 0, MemoryLayout.size(ofValue: password))

// 使用安全的字符串
class SecureString {
    private var data: UnsafeMutableBufferPointer<UInt8>
    
    init(_ string: String) {
        data = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: string.utf8.count)
        for (i, byte) in string.utf8.enumerated() {
            data[i] = byte
        }
    }
    
    deinit {
        // 清除内存
        data.update(repeating: 0)
        data.deallocate()
    }
}
```

**优势**：
- 保护敏感数据
- 防止内存泄露
- 符合合规要求

**局限性**：
- 需要手动管理
- 可能遗漏
- 性能开销

---

## 12. 逆向工程工具与方法

### 12.1 反汇编器

**IDA Pro**：

**功能**：
- 反汇编
- 反编译
- 图形化界面
- 插件支持

**使用**：
```
加载二进制文件
  ↓
自动分析
  ↓
查看反汇编代码
  ↓
查看反编译代码（Hex-Rays）
  ↓
分析逻辑
```

**优势**：
- 功能强大
- 支持多种架构
- 插件丰富

**局限性**：
- 价格昂贵
- 学习曲线陡峭
- 可能被检测

**Ghidra**：

**功能**：
- 反汇编
- 反编译
- 开源免费
- 脚本支持

**使用**：
```
创建项目
  ↓
导入二进制文件
  ↓
自动分析
  ↓
查看反汇编代码
  ↓
查看反编译代码
  ↓
分析逻辑
```

**优势**：
- 开源免费
- 功能强大
- 脚本支持

**局限性**：
- 性能较差
- 界面不够友好
- 可能被检测

**Hopper**：

**功能**：
- 反汇编
- 反编译
- macOS原生
- 轻量级

**优势**：
- macOS原生
- 轻量级
- 价格适中

**局限性**：
- 功能不如IDA
- 只支持macOS
- 插件较少

### 12.2 调试器

**LLDB**：

**功能**：
- 调试iOS应用
- 断点
- 内存检查
- 寄存器查看

**常用命令**：
```
(lldb) breakpoint set --name main
(lldb) process launch
(lldb) thread backtrace
(lldb) frame variable
(lldb) memory read --size 4 `0x12345678`
```

**优势**：
- iOS默认调试器
- 功能强大
- 与Xcode集成

**局限性**：
- 需要越狱设备
- 可能被检测
- 学习曲线

**Frida**：

**功能**：
- 动态插桩
- 运行时修改
- JavaScript API
- 跨平台

**使用**：
```javascript
// Frida脚本
Java.perform(function() {
    var MainActivity = Java.use("com.example.MainActivity");
    MainActivity.onCreate.overload().implementation = function() {
        console.log("onCreate called");
        this.onCreate();
    };
});
```

**优势**：
- 功能强大
- 灵活
- 跨平台

**局限性**：
- 需要安装Frida
- 可能被检测
- 学习曲线

**Cycript**：

**功能**：
- 运行时修改
- Objective-C操作
- 交互式控制台

**使用**：
```
# 附加到进程
cycript -p SpringBoard

# 修改Objective-C对象
[#UIApplication sharedApplication].keyWindow.backgroundColor = [UIColor redColor]
```

**优势**：
- 交互式
- 实时修改
- 功能强大

**局限性**：
- 需要越狱
- 可能被检测
- 已不维护

### 12.3 类_dump工具

**class-dump**：

**功能**：
- 导出Objective-C头文件
- 分析类结构
- 查看方法签名

**使用**：
```bash
class-dump -H -o headers MyApp.app/MyApp
```

**优势**：
- 简单快速
- 开源免费
- 功能实用

**局限性**：
- 只支持Objective-C
- 不支持Swift
- 可能被加壳阻止

**class-dump-z**：

**功能**：
- 导出Objective-C头文件
- 更快的速度
- 更好的输出

**优势**：
- 速度快
- 输出好
- 开源免费

**局限性**：
- 只支持Objective-C
- 不支持Swift
- 可能被加壳阻止

### 12.4 二进制分析工具

**otool**：

**功能**：
- 查看Mach-O信息
- 反汇编
- 查看段和节

**使用**：
```bash
# 查看Mach-O头
otool -h MyApp

# 查看段和节
otool -l MyApp

# 反汇编
otool -tV MyApp

# 查看符号表
otool -tv MyApp
```

**优势**：
- macOS自带
- 简单快速
- 功能实用

**局限性**：
- 功能有限
- 命令行界面
- 不支持反编译

**jtool**：

**功能**：
- 查看Mach-O信息
- 反汇编
- 更强大的功能

**优势**：
- 功能强大
- 比otool更灵活
- 开源免费

**局限性**：
- 命令行界面
- 学习曲线
- 文档不全

---

## 13. 静态分析技术

### 13.1 反汇编分析

**分析反汇编代码**：

```
加载二进制文件
  ↓
反汇编
  ↓
识别函数
  ↓
分析控制流
  ↓
理解逻辑
```

**技术**：
- 识别函数边界
- 分析调用关系
- 理解控制流
- 识别数据流

**优势**：
- 深入理解
- 发现隐藏逻辑
- 全面覆盖

**局限性**：
- 耗时耗力
- 需要经验
- 容易遗漏

### 13.2 反编译分析

**分析反编译代码**：

```
加载二进制文件
  ↓
反编译
  ↓
查看伪代码
  ↓
理解逻辑
```

**技术**：
- 理解伪代码
- 识别模式
- 重构逻辑

**优势**：
- 更易理解
- 快速分析
- 发现逻辑

**局限性**：
- 可能不准确
- 丢失信息
- 需要验证

### 13.3 字符串分析

**分析字符串**：

```
提取字符串
  ↓
分类字符串
  ↓
分析敏感字符串
  ↓
发现线索
```

**技术**：
- 提取所有字符串
- 识别敏感字符串
- 分析URL、API密钥等
- 发现隐藏功能

**优势**：
- 快速发现线索
- 简单有效
- 全面覆盖

**局限性**：
- 可能被加密
- 可能误导
- 需要验证

### 13.4 数据流分析

**分析数据流**：

```
识别输入
  ↓
追踪数据流
  ↓
分析转换
  ↓
识别输出
```

**技术**：
- 识别输入点
- 追踪数据转换
- 分析处理逻辑
- 识别输出点

**优势**：
- 深入理解
- 发现漏洞
- 全面覆盖

**局限性**：
- 复杂
- 耗时
- 需要经验

---

## 14. 动态分析技术

### 14.1 调试分析

**使用调试器分析**：

```
附加调试器
  ↓
设置断点
  ↓
单步执行
  ↓
观察状态
```

**技术**：
- 设置断点
- 单步执行
- 观察寄存器和内存
- 分析逻辑

**优势**：
- 真实环境
- 深入分析
- 发现运行时问题

**局限性**：
- 可能被检测
- 影响执行
- 需要经验

### 14.2 插桩分析

**使用插桩框架分析**：

```
编写插桩脚本
  ↓
附加到目标
  ↓
Hook函数
  ↓
观察行为
```

**技术**：
- Hook关键函数
- 记录调用
- 修改参数
- 观察行为

**优势**：
- 灵活
- 实时修改
- 深入分析

**局限性**：
- 可能被检测
- 影响性能
- 需要经验

### 14.3 模糊测试

**使用模糊测试发现漏洞**：

```
选择目标
  ↓
生成测试用例
  ↓
执行测试
  ↓
分析崩溃
```

**技术**：
- 生成变异输入
- 执行目标
- 监控崩溃
- 分析漏洞

**优势**：
- 自动化
- 发现未知漏洞
- 全面覆盖

**局限性**：
- 耗时
- 误报率高
- 需要分析

### 14.4 网络分析

**使用网络分析工具**：

```
配置代理
  ↓
捕获流量
  ↓
分析请求
  ↓
发现敏感信息
```

**技术**：
- 使用代理（Charles, Burp Suite）
- 捕获HTTPS流量
- 分析请求和响应
- 发现敏感信息

**优势**：
- 发现通信漏洞
- 分析API
- 发现敏感信息

**局限性**：
- 需要绕过证书固定
- 可能被检测
- 需要经验

---

## 15. 防御绕过与对抗

### 15.1 越狱检测绕过

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
var dyld = Module.findExportByName(null, '_dyld_image_count');
Interceptor.attach(dyld, {
    onLeave: function(retval) {
        // 减少返回的数量，隐藏注入的库
        retval.sub(1);
    }
});
```

### 15.2 调试器检测绕过

**绕过sysctl检测**：

```javascript
// Frida脚本
var sysctl = Module.findExportByName(null, 'sysctl');
Interceptor.attach(sysctl, {
    onEnter: function(args) {
        this.mib = args[0];
    },
    onLeave: function(retval) {
        // 检查是否是进程信息请求
        var mib = this.mib;
        if (mib.readS32() === 1) { // CTL_KERN
            // 清除P_TRACED标志
            var info = args[2];
            var flagOffset = 32; // kinfo_proc中p_flag的偏移
            var flags = info.add(flagOffset).readS32();
            flags &= ~0x800; // 清除P_TRACED
            info.add(flagOffset).writeS32(flags);
        }
    }
});
```

**绕过ptrace检测**：

```javascript
// Frida脚本
var ptrace = Module.findExportByName(null, 'ptrace');
Interceptor.attach(ptrace, {
    onEnter: function(args) {
        var request = args[0];
        if (request == 31) { // PT_DENY_ATTACH
            // 改为无操作
            args[0] = 0;
        }
    }
});
```

### 15.3 代码注入检测绕过

**绕过动态库检测**：

```javascript
// Frida脚本
var _dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');
Interceptor.attach(_dyld_get_image_name, {
    onLeave: function(retval) {
        if (!retval.isNull()) {
            var name = retval.readUtf8String();
            if (name.includes('Frida') || name.includes('Substrate')) {
                // 返回空字符串
                retval.replace(ptr(0));
            }
        }
    }
});
```

**绕过函数Hook检测**：

```javascript
// Frida脚本
// 恢复原始函数
var originalFunction = Module.findBaseAddress('MyApp').add(0x1234);
// 恢复原始指令
Memory.patchCode(originalFunction, 4, function(code) {
    code.writeByteArray([0x00, 0x00, 0x00, 0x00]); // 原始指令
});
```

### 15.4 反逆向技术绕过

**绕过字符串加密**：

```javascript
// Frida脚本
// Hook解密函数
var decryptFunction = Module.findExportByName(null, 'decryptString');
Interceptor.attach(decryptFunction, {
    onLeave: function(retval) {
        // 记录解密后的字符串
        console.log('Decrypted: ' + retval.readUtf8String());
    }
});
```

**绕过代码混淆**：

```javascript
// Frida脚本
// Hook关键函数，记录调用
var targetFunction = Module.findExportByName(null, 'targetFunction');
Interceptor.attach(targetFunction, {
    onEnter: function(args) {
        console.log('Function called with args: ' + args[0] + ', ' + args[1]);
    },
    onLeave: function(retval) {
        console.log('Function returned: ' + retval);
    }
});
```

### 15.5 综合绕过策略

**多层绕过**：

```javascript
// 综合Frida脚本
// 1. 绕过越狱检测
bypassJailbreakDetection();

// 2. 绕过调试器检测
bypassDebuggerDetection();

// 3. 绕过注入检测
bypassInjectionDetection();

// 4. 绕过反逆向
bypassAntiReverse();

function bypassJailbreakDetection() {
    // 实现绕过逻辑
}

function bypassDebuggerDetection() {
    // 实现绕过逻辑
}

function bypassInjectionDetection() {
    // 实现绕过逻辑
}

function bypassAntiReverse() {
    // 实现绕过逻辑
}
```

**最佳实践**：
- 分析所有检测点
- 逐一绕过
- 测试验证
- 持续更新

---

## 16. 防御策略最佳实践

### 16.1 多层防御

**纵深防御**：

```
第一层：越狱检测
  ↓
第二层：调试器检测
  ↓
第三层：注入检测
  ↓
第四层：完整性检查
  ↓
第五层：运行时保护
```

**优势**：
- 多层保护
- 增加绕过难度
- 提高安全性

**实现**：
- 使用多种检测技术
- 定期更新检测逻辑
- 结合服务端验证

### 16.2 持续更新

**定期更新**：

**检测逻辑更新**：
- 添加新的检测方法
- 更新检测规则
- 修复已知绕过

**混淆更新**：
- 更新混淆策略
- 更换混淆算法
- 增加混淆强度

**优势**：
- 保持防御有效性
- 应对新攻击
- 持续保护

**实现**：
- 定期发布更新
- 监控绕过技术
- 快速响应

### 16.3 服务端验证

**服务端验证**：

**设备验证**：
- 验证设备状态
- 检查越狱状态
- 验证应用完整性

**请求验证**：
- 验证请求签名
- 检查请求合法性
- 防止重放攻击

**优势**：
- 不依赖客户端
- 更难绕过
- 集中控制

**实现**：
- 实现服务端验证逻辑
- 验证客户端状态
- 拒绝非法请求

### 16.4 用户教育

**用户教育**：

**安全意识**：
- 教育用户安全风险
- 提醒不要越狱
- 提醒不要安装未授权应用

**最佳实践**：
- 使用强密码
- 启用双因素认证
- 定期更新系统

**优势**：
- 减少安全风险
- 提高整体安全
- 建立信任

**实现**：
- 提供安全指南
- 应用内提醒
- 定期沟通

### 16.5 合规与审计

**合规要求**：

**行业标准**：
- PCI DSS（支付卡行业）
- HIPAA（医疗健康）
- GDPR（欧盟数据保护）

**审计要求**：
- 定期安全审计
- 渗透测试
- 代码审查

**优势**：
- 满足法规要求
- 建立信任
- 降低风险

**实现**：
- 了解适用法规
- 实施合规措施
- 定期审计

---

## 附录

### A. 常用工具列表

**逆向工程**：
- IDA Pro
- Ghidra
- Hopper
- Binary Ninja

**调试**：
- LLDB
- Frida
- Cycript
- Xcode Debugger

**模糊测试**：
- AFL
- libFuzzer
- Honggfuzz

**网络分析**：
- Charles Proxy
- Burp Suite
- Wireshark

### B. 参考资料

**Apple官方**：
- iOS Security Guide
- Code Signing
- App Sandbox

**安全研究**：
- OWASP Mobile Security
- SANS Mobile Security
- NIST Mobile Security

**社区资源**：
- Reverse Engineering
- iOS App Reverse Engineering
- Hacking and Security

### C. 术语表

**ASLR**：Address Space Layout Randomization，地址空间布局随机化  
**DEP**：Data Execution Prevention，数据执行保护  
**PIE**：Position Independent Executable，位置无关可执行文件  
**ARC**：Automatic Reference Counting，自动引用计数  
**UAF**：Use-After-Free，释放后使用  
**ROP**：Return-Oriented Programming，返回导向编程  
**JIT**：Just-In-Time，即时编译  
**Hook**：钩子，拦截函数调用  

---

**咨询ios系统请咨询 telegram：@pengqing666**

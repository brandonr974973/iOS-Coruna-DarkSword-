# iOS应用权限滥用与隐私泄露 (iOS App Permission Abuse and Privacy Leakage)

> 作者：pengqinglei99-eng  
> 日期：2026-10-19  
> 版本：v1.0  
> 声明：本报告仅用于安全研究与防御目的，不鼓励任何非法利用行为。

---

## 目录

- [1. 概述与背景](#1-概述与背景)
- [2. iOS权限系统架构分析](#2-ios权限系统架构分析)
- [3. 位置权限滥用分析](#3-位置权限滥用分析)
- [4. 相机与相册权限安全缺陷](#4-相机与相册权限安全缺陷)
- [5. 通讯录与日历权限泄露](#5-通讯录与日历权限泄露)
- [6. 麦克风与语音权限风险](#6-麦克风与语音权限风险)
- [7. 通知权限与推送隐私](#7-通知权限与推送隐私)
- [8. 后台权限与数据收集](#8-后台权限与数据收集)
- [9. 剪贴板与键盘输入监控](#9-剪贴板与键盘输入监控)
- [10. 广告追踪与隐私泄露](#10-广告追踪与隐私泄露)
- [11. 第三方SDK权限滥用](#11-第三方sdk权限滥用)
- [12. 权限降级与绕过技术](#12-权限降级与绕过技术)
- [13. 隐私保护防御机制](#13-隐私保护防御机制)
- [14. 隐私合规审计工具](#14-隐私合规审计工具)
- [15. 总结与展望](#15-总结与展望)

---

## 1. 概述与背景

### 1.1 iOS权限模型的演进

iOS平台的权限管理系统经历了多次重大演进，从早期粗粒度的权限控制到现代精细化的隐私保护框架：

| iOS版本 | 权限特性 | 隐私增强 |
|---------|---------|---------|
| iOS 6 | 通讯录/日历权限提示 | 首次引入权限弹窗 |
| iOS 8 | HealthKit/HomeKit | 健康数据加密存储 |
| iOS 10 | 相机/麦克风/照片权限 | Info.plist使用说明强制 |
| iOS 13 | 位置"仅一次"选项 | 蓝牙/WiFi权限分离 |
| iOS 14 | ATT框架 | 精确位置开关、粘贴板提示 |
| iOS 15 | 邮件/网络隐私报告 | App Privacy Report |
| iOS 16 | 安全粘贴板 | 照片部分访问 |
| iOS 17 | Data Access API | 敏感数据访问日志 |
| iOS 18 | 增强ATT | Ringer/Silent状态保护 |

### 1.2 隐私威胁态势

2025-2026年间，iOS应用隐私泄露的主要威胁包括：

1. **过度权限请求**: 应用请求超出功能所需的权限
2. **隐蔽数据收集**: 在用户不知情时收集敏感信息
3. **SDK数据共享**: 第三方SDK将收集的数据回传广告平台
4. **权限链式泄露**: 通过一个权限间接获取其他敏感信息
5. **后台持续监控**: 利用后台权限持续收集用户数据

### 1.3 研究方法论

本文采用以下方法分析iOS权限安全问题：

- **静态分析**: 审查Info.plist权限声明和代码中的权限使用
- **动态分析**: 运行时监控权限调用和数据传输
- **网络分析**: 捕获和分析权限数据的外传行为
- **合规审计**: 对照隐私法规检查权限使用合规性

---

## 2. iOS权限系统架构分析

### 2.1 权限管理核心组件

```c
/*
 * iOS权限系统核心架构
 * 基于TCC (Transparency, Consent, and Control) 框架
 */

// TCC 服务类型定义
typedef enum {
    TCC_SERVICE_CAMERA = 0,
    TCC_SERVICE_MICROPHONE = 1,
    TCC_SERVICE_LOCATION = 2,
    TCC_SERVICE_CONTACTS = 3,
    TCC_SERVICE_CALENDAR = 4,
    TCC_SERVICE_PHOTOS = 5,
    TCC_SERVICE_ADDRESSBOOK = 6,
    TCC_SERVICE_REMINDERS = 7,
    TCC_SERVICE_BLUETOOTH = 8,
    TCC_SERVICE_MEDIA_LIBRARY = 9,
    TCC_SERVICE_MOTION = 10,
    TCC_SERVICE_HEALTH = 11,
    TCC_SERVICE_HOMEKIT = 12,
    TCC_SERVICE_NETWORK = 13,
    TCC_SERVICE_ACCOUNT = 14,
    TCC_SERVICE_USER_TRACKING = 15,
    TCC_SERVICE_CLIPBOARD = 16,
    TCC_SERVICE_LOCAL_NETWORK = 17,
    TCC_SERVICE_NEARBY_INTERACTION = 18,
} tcc_service_type_t;

// TCC 授权状态
typedef enum {
    TCC_AUTHORIZATION_DENIED = 0,
    TCC_AUTHORIZATION_UNKNOWN = 1,
    TCC_AUTHORIZATION_AUTHORIZED = 2,
    TCC_AUTHORIZATION_LIMITED = 3,      // iOS 14+ 有限访问
    TCC_AUTHORIZATION_PROVISIONAL = 4,  // 临时授权
    TCC_AUTHORIZATION_RESTRICTED = 5,   // 受限（家长控制等）
} tcc_authorization_status_t;

// TCC 数据库记录结构
typedef struct tcc_db_record {
    uint32_t record_id;                  // 记录ID
    char *service_name;                  // 服务名称
    char *client_bundle_id;             // 应用Bundle ID
    uint32_t auth_value;                // 授权值
    uint64_t auth_reason;               // 授权原因
    uint64_t last_modified;             // 最后修改时间
    char *auth_class;                   // 授权类别
    uint32_t service_count;             // 服务计数
} tcc_db_record_t;

// 权限请求上下文
typedef struct permission_request_ctx {
    tcc_service_type_t service;          // 请求的服务类型
    char *bundle_id;                     // 请求应用ID
    char *usage_description;             // 使用说明字符串
    uint32_t request_flags;              // 请求标志
    Boolean is_background_request;       // 是否后台请求
    Boolean is_system_app;              // 是否系统应用
} permission_request_ctx_t;
```

### 2.2 权限数据库分析

```objectivec
/*
 * TCC权限数据库安全分析
 * 漏洞类型: 权限状态操纵 + 数据库访问
 */

// TCC数据库路径分析
@interface TCCDatabaseAnalyzer : NSObject

+ (NSString *)tccDatabasePath;
+ (void)analyzeTCCRecords;
+ (BOOL)checkPermissionStatus:(NSString *)service
                   forBundleID:(NSString *)bundleID;

@end

@implementation TCCDatabaseAnalyzer

+ (NSString *)tccDatabasePath {
    // TCC数据库位置（需要越狱访问）
    return @"/var/mobile/Library/TCC/TCC.db";
}

+ (void)analyzeTCCRecords {
    // 分析TCC数据库中的权限记录
    // 注意：此操作需要特殊权限（越狱或企业MDM）
    
    NSLog(@"[+] TCC Database Analysis");
    NSLog(@"[+] Database path: %@", [self tccDatabasePath]);
    
    // 权限记录分析
    NSArray *services = @[
        @"kTCCServiceCamera",
        @"kTCCServiceMicrophone",
        @"kTCCServiceLocation",
        @"kTCCServiceAddressBook",
        @"kTCCServiceCalendar",
        @"kTCCServicePhotos",
        @"kTCCServiceBluetoothAlways",
        @"kTCCServiceMediaLibrary",
        @"kTCCServiceMotion",
        @"kTCCServiceHealth",
        @"kTCCServiceHomeKit",
        @"kTCCServiceUserTracking",
        @"kTCCServiceLiverpool",  // iCloud
        @"kTCCServiceShareKit",
    ];
    
    for (NSString *service in services) {
        NSLog(@"[+] Service: %@", service);
        // 查询该服务的所有权限记录
    }
}

+ (BOOL)checkPermissionStatus:(NSString *)service
                   forBundleID:(NSString *)bundleID {
    // 通过公开API检查权限状态
    if ([service isEqualToString:@"kTCCServiceCamera"]) {
        AVAuthorizationStatus status =
            [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];
        return status == AVAuthorizationStatusAuthorized;
    }
    
    if ([service isEqualToString:@"kTCCServiceMicrophone"]) {
        AVAuthorizationStatus status =
            [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
        return status == AVAuthorizationStatusAuthorized;
    }
    
    if ([service isEqualToString:@"kTCCServiceLocation"]) {
        CLAuthorizationStatus status =
            [CLLocationManager authorizationStatus];
        return status == kCLAuthorizationStatusAuthorizedWhenInUse ||
               status == kCLAuthorizationStatusAuthorizedAlways;
    }
    
    return NO;
}

@end
```

### 2.3 Info.plist权限声明审计

```objectivec
/*
 * Info.plist 权限声明安全审计
 * 检测过度权限请求和误导性描述
 */

@interface InfoPlistPermissionAuditor : NSObject

+ (void)auditPermissionsInBundle:(NSBundle *)bundle;
+ (void)checkMisleadingDescriptions:(NSDictionary *)plist;

@end

@implementation InfoPlistPermissionAuditor

// 所有iOS权限键及其说明
static NSDictionary *permissionKeys(void) {
    return @{
        // 位置权限
        @"NSLocationWhenInUseUsageDescription": @{
            @"service": @"Location (When In Use)",
            @"sensitivity": @"HIGH",
            @"risk": @"Location tracking"
        },
        @"NSLocationAlwaysAndWhenInUseUsageDescription": @{
            @"service": @"Location (Always)",
            @"sensitivity": @"CRITICAL",
            @"risk": @"Continuous location tracking"
        },
        @"NSLocationAlwaysUsageDescription": @{
            @"service": @"Location (Always) - Legacy",
            @"sensitivity": @"CRITICAL",
            @"risk": @"Continuous background location"
        },
        
        // 媒体权限
        @"NSCameraUsageDescription": @{
            @"service": @"Camera",
            @"sensitivity": @"HIGH",
            @"risk": @"Visual surveillance"
        },
        @"NSMicrophoneUsageDescription": @{
            @"service": @"Microphone",
            @"sensitivity": @"CRITICAL",
            @"risk": @"Audio surveillance"
        },
        @"NSPhotoLibraryUsageDescription": @{
            @"service": @"Photo Library (Read)",
            @"sensitivity": @"HIGH",
            @"risk": @"Photo data access"
        },
        @"NSPhotoLibraryAddUsageDescription": @{
            @"service": @"Photo Library (Write)",
            @"sensitivity": @"MEDIUM",
            @"risk": @"Photo library modification"
        },
        
        // 个人数据权限
        @"NSContactsUsageDescription": @{
            @"service": @"Contacts",
            @"sensitivity": @"CRITICAL",
            @"risk": @"Contact data harvesting"
        },
        @"NSCalendarsUsageDescription": @{
            @"service": @"Calendars",
            @"sensitivity": @"HIGH",
            @"risk": @"Schedule/privacy data access"
        },
        @"NSRemindersUsageDescription": @{
            @"service": @"Reminders",
            @"sensitivity": @"MEDIUM",
            @"risk": @"Personal reminder access"
        },
        
        // 健康与运动
        @"NSHealthShareUsageDescription": @{
            @"service": @"Health (Read)",
            @"sensitivity": @"CRITICAL",
            @"risk": @"Health data access"
        },
        @"NSHealthUpdateUsageDescription": @{
            @"service": @"Health (Write)",
            @"sensitivity": @"HIGH",
            @"risk": @"Health data modification"
        },
        @"NSMotionUsageDescription": @{
            @"service": @"Motion",
            @"sensitivity": @"MEDIUM",
            @"risk": @"Activity tracking"
        },
        
        // 其他权限
        @"NSBluetoothAlwaysUsageDescription": @{
            @"service": @"Bluetooth",
            @"sensitivity": @"MEDIUM",
            @"risk": @"Device discovery/tracking"
        },
        @"NSUserTrackingUsageDescription": @{
            @"service": @"App Tracking",
            @"sensitivity": @"HIGH",
            @"risk": @"Cross-app tracking"
        },
        @"NSFaceIDUsageDescription": @{
            @"service": @"Face ID",
            @"sensitivity": @"MEDIUM",
            @"risk": @"Biometric access"
        },
        @"NSSiriUsageDescription": @{
            @"service": @"Siri",
            @"sensitivity": @"HIGH",
            @"risk": @"Voice assistant access"
        },
    };
}

+ (void)auditPermissionsInBundle:(NSBundle *)bundle {
    NSDictionary *plist = bundle.infoDictionary;
    if (!plist) return;
    
    NSDictionary *keys = permissionKeys();
    NSMutableArray *requestedPermissions = [NSMutableArray array];
    NSMutableArray *highRiskPermissions = [NSMutableArray array];
    
    NSLog(@"\n========================================");
    NSLog(@"  Info.plist Permission Audit");
    NSLog(@"  Bundle: %@", bundle.bundleIdentifier);
    NSLog(@"========================================\n");
    
    for (NSString *key in keys) {
        NSString *description = plist[key];
        if (description) {
            NSDictionary *info = keys[key];
            [requestedPermissions addObject:@{
                @"key": key,
                @"service": info[@"service"],
                @"sensitivity": info[@"sensitivity"],
                @"description": description,
            }];
            
            if ([info[@"sensitivity"] isEqualToString:@"CRITICAL"]) {
                [highRiskPermissions addObject:info[@"service"]];
            }
            
            NSLog(@"[+] Requested: %@ (%@)", info[@"service"], info[@"sensitivity"]);
            NSLog(@"    Description: %@", description);
            
            // 检查描述是否过于模糊
            if (description.length < 10) {
                NSLog(@"[!] WARNING: Description too vague (< 10 chars)");
            }
        }
    }
    
    NSLog(@"\n--- Summary ---");
    NSLog(@"Total permissions: %lu", (unsigned long)requestedPermissions.count);
    NSLog(@"Critical risk: %lu", (unsigned long)highRiskPermissions.count);
    
    if (highRiskPermissions.count > 0) {
        NSLog(@"\n[!] CRITICAL permissions requested:");
        for (NSString *perm in highRiskPermissions) {
            NSLog(@"    - %@", perm);
        }
    }
}

+ (void)checkMisleadingDescriptions:(NSDictionary *)plist {
    // 检测误导性权限描述
    NSArray *suspiciousPatterns = @[
        @"please allow",      // 诱导性语言
        @"we need",           // 模糊需求
        @"required",          // 虚假必需
        @"to continue",       // 恐吓性语言
        @"don't deny",        // 阻止拒绝
    ];
    
    NSDictionary *keys = permissionKeys();
    
    for (NSString *key in keys) {
        NSString *desc = plist[key];
        if (!desc) continue;
        
        NSString *lowerDesc = desc.lowercaseString;
        for (NSString *pattern in suspiciousPatterns) {
            if ([lowerDesc containsString:pattern]) {
                NSLog(@"[!] MISLEADING: %@ contains suspicious pattern: '%@'",
                      key, pattern);
            }
        }
    }
}

@end
```

---

## 3. 位置权限滥用分析

### 3.1 位置数据收集技术分析

```objectivec
/*
 * iOS位置权限滥用深度分析
 * 漏洞类型: 过度位置收集 + 后台追踪 + 精度滥用
 */

// 位置管理器安全分析
@interface LocationPrivacyAnalyzer : NSObject <CLLocationManagerDelegate>

@property (nonatomic, strong) CLLocationManager *locationManager;
@property (nonatomic, strong) NSMutableArray<CLLocation *> *locationHistory;
@property (nonatomic, assign) BOOL isBackgroundTracking;
@property (nonatomic, strong) NSMutableSet<NSString *> *locationRecipients;

- (void)analyzeLocationCollection;
- (void)detectExcessiveTracking;

@end

@implementation LocationPrivacyAnalyzer

- (void)analyzeLocationCollection {
    self.locationManager = [[CLLocationManager alloc] init];
    self.locationManager.delegate = self;
    self.locationHistory = [NSMutableArray array];
    self.locationRecipients = [NSMutableSet set];
    
    // 分析位置精度请求
    CLLocationAccuracy requestedAccuracy = self.locationManager.desiredAccuracy;
    
    NSLog(@"[+] Location Collection Analysis");
    NSLog(@"    Requested accuracy: %.2f meters", requestedAccuracy);
    
    // 精度滥用检测
    if (requestedAccuracy == kCLLocationAccuracyBest ||
        requestedAccuracy == kCLLocationAccuracyBestForNavigation) {
        NSLog(@"[!] WARNING: Maximum accuracy requested");
        NSLog(@"    GPS-level accuracy may not be necessary for app function");
        
        // 合理的精度选择
        // kCLLocationAccuracyKilometer - 城市级应用
        // kCLLocationAccuracyHundredMeters - 区域级应用
        // kCLLocationAccuracyNearestTenMeters - 街道级应用
        // kCLLocationAccuracyBest - 导航应用
    }
    
    // 检查位置过滤配置
    CLLocationDistance filter = self.locationManager.distanceFilter;
    if (filter < 10) {
        NSLog(@"[!] WARNING: Very low distance filter (%.1fm)", filter);
        NSLog(@"    This generates excessive location updates");
    }
    
    // 检查后台位置更新
    if (self.locationManager.allowsBackgroundLocationUpdates) {
        NSLog(@"[!] CRITICAL: Background location updates enabled");
        self.isBackgroundTracking = YES;
    }
    
    // 检查显著位置变化监控
    // 此功能即使应用被杀死也能唤醒应用
    NSLog(@"[+] Significant location change monitoring: available");
    
    // 检查区域监控
    NSLog(@"[+] Region monitoring: max %lu regions",
          (unsigned long)[CLLocationManager maximumRegionMonitoringDistance]);
    
    // 检查信标监控
    NSLog(@"[+] Beacon ranging: available (can determine precise distance)");
}

- (void)detectExcessiveTracking {
    // 分析位置更新频率
    if (self.locationHistory.count < 2) return;
    
    NSDate *firstUpdate = self.locationHistory.firstObject.timestamp;
    NSDate *lastUpdate = self.locationHistory.lastObject.timestamp;
    
    NSTimeInterval duration = [lastUpdate timeIntervalSinceDate:firstUpdate];
    double updatesPerMinute = self.locationHistory.count / (duration / 60.0);
    
    NSLog(@"[+] Tracking frequency analysis:");
    NSLog(@"    Duration: %.1f minutes", duration / 60.0);
    NSLog(@"    Updates: %lu", (unsigned long)self.locationHistory.count);
    NSLog(@"    Frequency: %.1f updates/minute", updatesPerMinute);
    
    if (updatesPerMinute > 10) {
        NSLog(@"[!] EXCESSIVE: More than 10 updates per minute");
    }
    
    // 分析位置数据是否被发送到外部服务器
    NSLog(@"[+] Location data recipients:");
    for (NSString *recipient in self.locationRecipients) {
        NSLog(@"    - %@", recipient);
    }
}

#pragma mark - CLLocationManagerDelegate

- (void)locationManager:(CLLocationManager *)manager
     didUpdateLocations:(NSArray<CLLocation *> *)locations {
    
    for (CLLocation *location in locations) {
        [self.locationHistory addObject:location];
        
        // 记录位置详细信息
        NSLog(@"[LOC] %.6f, %.6f (±%.1fm) @ %@",
              location.coordinate.latitude,
              location.coordinate.longitude,
              location.horizontalAccuracy,
              location.timestamp);
        
        // 检查是否有速度/航向数据
        if (location.speed >= 0) {
            NSLog(@"[LOC] Speed: %.1f m/s", location.speed);
        }
        if (location.course >= 0) {
            NSLog(@"[LOC] Course: %.1f°", location.course);
        }
        if (location.altitude != 0) {
            NSLog(@"[LOC] Altitude: %.1fm (±%.1fm)",
                  location.altitude, location.verticalAccuracy);
        }
    }
}

@end

// 位置数据模糊化处理器
@interface LocationPrivacyGuard : NSObject

+ (CLLocation *)fuzzLocation:(CLLocation *)original
                  precision:(CLLocationDegrees)precision;
+ (BOOL)shouldAllowLocationRequest:(NSString *)bundleID
                        forPurpose:(NSString *)purpose;

@end

@implementation LocationPrivacyGuard

// 位置模糊化处理
+ (CLLocation *)fuzzLocation:(CLLocation *)original
                  precision:(CLLocationDegrees)precision {
    
    // 将经纬度截断到指定精度
    double factor = 1.0 / precision;
    
    double fuzzedLat = round(original.coordinate.latitude * factor) / factor;
    double fuzzedLon = round(original.coordinate.longitude * factor) / factor;
    
    CLLocationCoordinate2D fuzzedCoord = CLLocationCoordinate2DMake(fuzzedLat, fuzzedLon);
    
    return [[CLLocation alloc]
        initWithCoordinate:fuzzedCoord
                  altitude:original.altitude
        horizontalAccuracy:precision * 111000  // 约略转换为米
          verticalAccuracy:original.verticalAccuracy
                 timestamp:original.timestamp];
}

+ (BOOL)shouldAllowLocationRequest:(NSString *)bundleID
                        forPurpose:(NSString *)purpose {
    
    // 基于应用类型判断位置请求合理性
    NSDictionary *legitimatePurposes = @{
        @"maps": @[@"navigation", @"search_nearby", @"show_location"],
        @"weather": @[@"current_location_weather"],
        @"ride_sharing": @[@"pickup_location", @"tracking_ride"],
        @"fitness": @[@"route_tracking", @"distance_calculation"],
        @"social": @[@"share_location", @"find_friends"],
    };
    
    // 检查请求目的是否合理
    // 此方法需要与应用类别数据库配合使用
    
    return YES; // 简化
}

@end
```

### 3.2 位置数据间接获取

```objectivec
/*
 * 位置数据间接获取技术分析
 * 无需位置权限推断用户位置的方法
 */

@interface IndirectLocationInference : NSObject

+ (NSString *)inferLocationFromTimeZone;
+ (NSString *)inferLocationFromLocale;
+ (NSString *)inferLocationFromIPAddress;
+ (NSString *)inferLocationFromWiFiNetwork;
+ (NSDictionary *)collectAllIndirectLocationSignals;

@end

@implementation IndirectLocationInference

// 从时区推断位置
+ (NSString *)inferLocationFromTimeZone {
    NSTimeZone *tz = [NSTimeZone localTimeZone];
    NSString *tzName = tz.name;
    
    // 时区可以推断大致地理区域
    // 例如: Asia/Shanghai -> 中国东部
    //       America/New_York -> 美国东海岸
    
    NSLog(@"[+] Timezone: %@ (offset: %+ld seconds)",
          tzName, (long)tz.secondsFromGMT);
    
    // 时区 + GMT偏移可以缩小到国家/地区级别
    return tzName;
}

// 从区域设置推断位置
+ (NSString *)inferLocationFromLocale {
    NSLocale *locale = [NSLocale currentLocale];
    NSString *countryCode = locale.country;
    NSString *languageCode = locale.languageCode;
    
    NSLog(@"[+] Locale: country=%@, language=%@",
          countryCode, languageCode);
    
    // 国家代码直接暴露用户所在国家
    return countryCode;
}

// 从IP地址推断位置
+ (NSString *)inferLocationFromIPAddress {
    // 应用可以通过HTTP请求获取自己的公网IP
    // 然后通过GeoIP数据库查询位置
    
    // 常见GeoIP精度：
    // - 国家级: 99%准确率
    // - 州/省级: 90%准确率
    // - 城市级: 50-75%准确率
    
    NSLog(@"[+] IP geolocation: available via network request");
    return @"City-level accuracy possible";
}

// 从WiFi网络信息推断位置
+ (NSString *)inferLocationFromWiFiNetwork {
    // NEHotspotNetwork可以获取当前WiFi的SSID
    // SSID名称可能包含位置信息（如 "Starbucks_Downtown_5G"）
    
    // 即使没有WiFi权限，WiFi的BSSID（MAC地址）
    // 在某些场景下可能通过其他API泄露
    
    NSLog(@"[+] WiFi SSID can reveal location context");
    return @"SSID-based location inference";
}

// 收集所有间接位置信号
+ (NSDictionary *)collectAllIndirectLocationSignals {
    NSMutableDictionary *signals = [NSMutableDictionary dictionary];
    
    signals[@"timezone"] = [self inferLocationFromTimeZone];
    signals[@"locale_country"] = [self inferLocationFromLocale];
    signals[@"ip_geolocation"] = [self inferLocationFromIPAddress];
    signals[@"wifi_context"] = [self inferLocationFromWiFiNetwork];
    
    // 设备语言设置
    NSString *preferredLang = [NSLocale preferredLanguages].firstObject;
    signals[@"preferred_language"] = preferredLang ?: @"unknown";
    
    // 货币设置
    NSLocale *locale = [NSLocale currentLocale];
    NSString *currencyCode = [locale objectForKey:NSLocaleCurrencyCode];
    signals[@"currency"] = currencyCode ?: @"unknown";
    
    // 测量系统
    NSString *measurementSystem =
        [locale objectForKey:NSLocaleUsesMetricSystem];
    signals[@"metric_system"] = measurementSystem ?: @"unknown";
    
    // 温度单位（从locale推断）
    signals[@"temperature_unit"] = @"locale-dependent";
    
    NSLog(@"[+] Indirect location signals collected: %lu",
          (unsigned long)signals.count);
    
    return signals;
}

@end
```

---

## 4. 相机与相册权限安全缺陷

### 4.1 相机权限滥用分析

```objectivec
/*
 * 相机权限滥用技术分析
 * 漏洞类型: 隐蔽拍摄 + 元数据泄露 + 实时视频流
 */

// 相机权限安全监控
@interface CameraPrivacyMonitor : NSObject

@property (nonatomic, strong) NSMutableArray<NSDictionary *> *cameraUsageLog;
@property (nonatomic, assign) BOOL isMonitoring;

- (void)startMonitoring;
- (void)analyzeCameraUsage:(AVCaptureSession *)session;

@end

@implementation CameraPrivacyMonitor

- (void)startMonitoring {
    self.isMonitoring = YES;
    self.cameraUsageLog = [NSMutableArray array];
    
    // 注册相机使用通知
    // iOS 14+ 提供相机使用指示器（绿点）
    // 但应用内部可以监控自己的相机使用
    
    NSLog(@"[+] Camera privacy monitoring started");
}

- (void)analyzeCameraUsage:(AVCaptureSession *)session {
    NSDictionary *usage = [NSMutableDictionary dictionary];
    
    // 分析输入设备
    for (AVCaptureDeviceInput *input in session.inputs) {
        AVCaptureDevice *device = input.device;
        
        usage[@"deviceType"] = device.deviceType;
        usage[@"position"] = (device.position == AVCaptureDevicePositionFront)
            ? @"front" : @"back";
        usage[@"modelID"] = device.localizedName;
        
        // 检查是否启用了视频稳定
        if ([device isVideoStabilizationModeSupported:
             AVCaptureVideoStabilizationModeAuto]) {
            usage[@"stabilization"] = @"enabled";
        }
        
        // 检查分辨率设置
        AVCaptureInputPort *port = input.ports.firstObject;
        if (port) {
            CMFormatDescriptionRef formatDesc = port.formatDescription;
            if (formatDesc) {
                CMVideoDimensions dims = CMVideoFormatDescriptionGetDimensions(formatDesc);
                usage[@"resolution"] = [NSString stringWithFormat:@"%dx%d",
                    dims.width, dims.height];
            }
        }
        
        NSLog(@"[CAM] Device: %@ (%@) at %@ resolution",
              usage[@"deviceType"], usage[@"position"],
              usage[@"resolution"] ?: @"unknown");
    }
    
    // 分析输出配置
    for (AVCaptureOutput *output in session.outputs) {
        if ([output isKindOfClass:[AVCapturePhotoOutput class]]) {
            usage[@"photo_capture"] = @YES;
            AVCapturePhotoOutput *photoOutput = (AVCapturePhotoOutput *)output;
            usage[@"max_photo_quality"] = @(photoOutput.maxPhotoQualityPrioritization);
        }
        
        if ([output isKindOfClass:[AVCaptureVideoDataOutput class]]) {
            // 视频数据输出 - 可用于实时分析
            usage[@"video_stream"] = @YES;
            NSLog(@"[!] WARNING: Video data output active (real-time frame access)");
        }
        
        if ([output isKindOfClass:[AVCaptureMovieFileOutput class]]) {
            usage[@"video_recording"] = @YES;
            NSLog(@"[!] WARNING: Video recording active");
        }
    }
    
    // 检查元数据处理
    // 照片EXIF数据包含GPS、设备信息、时间戳等
    usage[@"metadata_handling"] = @"check_delegate";
    
    [self.cameraUsageLog addObject:usage];
}

@end

// 照片EXIF元数据隐私分析
@interface PhotoMetadataAnalyzer : NSObject

+ (void)analyzeEXIFData:(NSData *)imageData;
+ (NSDictionary *)extractSensitiveMetadata:(NSDictionary *)exifDict;

@end

@implementation PhotoMetadataAnalyzer

+ (void)analyzeEXIFData:(NSData *)imageData {
    CGImageSourceRef source = CGImageSourceCreateWithData(
        (__bridge CFDataRef)imageData, NULL);
    
    if (!source) return;
    
    NSDictionary *metadata = (__bridge_transfer NSDictionary *)
        CGImageSourceCopyPropertiesAtIndex(source, 0, NULL);
    CFRelease(source);
    
    if (!metadata) return;
    
    NSLog(@"[+] Photo Metadata Analysis:");
    
    // 检查GPS数据
    NSDictionary *gpsDict = metadata[(__bridge NSString *)kCGImagePropertyGPSDictionary];
    if (gpsDict) {
        NSNumber *latitude = gpsDict[(__bridge NSString *)kCGImagePropertyGPSLatitude];
        NSNumber *longitude = gpsDict[(__bridge NSString *)kCGImagePropertyGPSLongitude];
        NSNumber *altitude = gpsDict[(__bridge NSString *)kCGImagePropertyGPSAltitude];
        
        NSLog(@"[!] CRITICAL: GPS data in photo:");
        NSLog(@"    Latitude: %@°", latitude);
        NSLog(@"    Longitude: %@°", longitude);
        if (altitude) {
            NSLog(@"    Altitude: %@m", altitude);
        }
    }
    
    // 检查设备信息
    NSDictionary *tiffDict = metadata[(__bridge NSString *)kCGImagePropertyTIFFDictionary];
    if (tiffDict) {
        NSString *make = tiffDict[(__bridge NSString *)kCGImagePropertyTIFFMake];
        NSString *model = tiffDict[(__bridge NSString *)kCGImagePropertyTIFFModel];
        NSString *software = tiffDict[(__bridge NSString *)kCGImagePropertyTIFFSoftware];
        
        NSLog(@"[+] Device: %@ %@", make ?: @"", model ?: @"");
        if (software) {
            NSLog(@"[+] Software: %@ (may reveal OS version)", software);
        }
    }
    
    // 检查拍摄时间
    NSDictionary *exifDict = metadata[(__bridge NSString *)kCGImagePropertyExifDictionary];
    if (exifDict) {
        NSString *dateTime = exifDict[(__bridge NSString *)kCGImagePropertyExifDateTimeOriginal];
        NSString *dateTimeDigitized = exifDict[(__bridge NSString *)kCGImagePropertyExifDateTimeDigitized];
        
        NSLog(@"[+] Taken: %@ (original: %@)",
              dateTimeDigitized ?: @"N/A", dateTime ?: @"N/A");
    }
    
    // 检查缩略图（可能包含额外的场景信息）
    NSDictionary *jpegDict = metadata[(__bridge NSString *)kCGImagePropertyJPEGDictionary];
    if (jpegDict) {
        NSLog(@"[+] JPEG metadata present (may contain thumbnail)");
    }
}

+ (NSDictionary *)extractSensitiveMetadata:(NSDictionary *)exifDict {
    NSMutableDictionary *sensitive = [NSMutableDictionary dictionary];
    
    // 提取所有可能泄露隐私的字段
    NSArray *sensitiveKeys = @[
        (__bridge NSString *)kCGImagePropertyGPSDictionary,
        (__bridge NSString *)kCGImagePropertyTIFFDictionary,
        (__bridge NSString *)kCGImagePropertyExifDictionary,
    ];
    
    for (NSString *key in sensitiveKeys) {
        NSDictionary *subDict = exifDict[key];
        if (subDict) {
            sensitive[key] = subDict;
        }
    }
    
    return sensitive;
}

@end

// 照片元数据清理器
@implementation PhotoMetadataCleaner

+ (NSData *)stripSensitiveMetadata:(NSData *)imageData {
    CGImageSourceRef source = CGImageSourceCreateWithData(
        (__bridge CFDataRef)imageData, NULL);
    
    if (!source) return imageData;
    
    // 获取原始图像
    CGImageRef image = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    CFRelease(source);
    
    if (!image) return imageData;
    
    // 创建新的数据，不包含元数据
    NSMutableData *cleanData = [NSMutableData data];
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        (__bridge CFMutableDataRef)cleanData,
        kUTTypeJPEG, 1, NULL);
    
    if (!dest) {
        CGImageRelease(image);
        return imageData;
    }
    
    // 写入图像，不写入元数据
    CGImageDestinationAddImage(dest, image, nil);
    CGImageDestinationFinalize(dest);
    
    CGImageRelease(image);
    CFRelease(dest);
    
    NSLog(@"[+] Photo metadata stripped");
    return cleanData;
}

@end
```

### 4.2 相册权限精细化分析

```objectivec
/*
 * 相册权限精细化安全分析
 * iOS 14+ 有限照片访问模式的安全评估
 */

@interface PhotoLibraryPrivacyAnalyzer : NSObject

+ (void)analyzePhotoAccessPattern;
+ (void)checkLimitedLibraryAccess;

@end

@implementation PhotoLibraryPrivacyAnalyzer

+ (void)analyzePhotoAccessPattern {
    PHAuthorizationStatus status;
    
    if (@available(iOS 14, *)) {
        status = [PHPhotoLibrary authorizationStatusForAccessLevel:
            PHAccessLevelReadWrite];
        
        switch (status) {
            case PHAuthorizationStatusAuthorized:
                NSLog(@"[!] Full photo library access granted");
                NSLog(@"    App can access ALL photos and videos");
                break;
                
            case PHAuthorizationStatusLimited:
                NSLog(@"[+] Limited photo library access");
                NSLog(@"    App can only access user-selected photos");
                break;
                
            case PHAuthorizationStatusDenied:
                NSLog(@"[+] Photo library access denied");
                break;
                
            case PHAuthorizationStatusNotDetermined:
                NSLog(@"[ ] Photo library permission not yet requested");
                break;
                
            default:
                break;
        }
    }
    
    // 分析相册访问模式
    PHFetchOptions *options = [[PHFetchOptions alloc] init];
    options.sortDescriptors = @[[NSSortDescriptor sortDescriptorWithKey:
        @"creationDate", ascending:NO]];
    
    // 漏洞：即使有限访问，应用仍可获取照片的元数据
    // 包括创建日期、修改日期、位置信息（如果用户选择了含GPS的照片）
    
    PHFetchResult *assets = [PHAsset fetchAssetsWithOptions:options];
    
    NSLog(@"[+] Accessible photos: %lu", (unsigned long)assets.count);
    
    // 分析可获取的元数据
    [assets enumerateObjectsUsingBlock:^(PHAsset *asset, NSUInteger idx, BOOL *stop) {
        if (idx >= 5) { *stop = YES; return; }
        
        NSLog(@"[PHOTO] %@ - %@ - %@ - loc:%@",
              asset.creationDate ?: @"N/A",
              asset.mediaType == PHAssetMediaTypeImage ? @"Image" : @"Video",
              [NSString stringWithFormat:@"%lux%lu",
               (unsigned long)asset.pixelWidth,
               (unsigned long)asset.pixelHeight],
              asset.location ? @"YES" : @"NO");
        
        // 漏洞：位置信息在有限访问模式下仍然可用
        if (asset.location) {
            NSLog(@"[!] GPS available even in Limited mode: %.4f, %.4f",
                  asset.location.coordinate.latitude,
                  asset.location.coordinate.longitude);
        }
    }];
}

+ (void)checkLimitedLibraryAccess {
    // 检查应用是否正确处理有限访问模式
    
    if (@available(iOS 14, *)) {
        PHAuthorizationStatus status = [PHPhotoLibrary
            authorizationStatusForAccessLevel:PHAccessLevelReadWrite];
        
        if (status == PHAuthorizationStatusLimited) {
            // 应用应该显示提示，引导用户授予更多权限
            // 但某些应用可能利用此模式来减少权限请求
            
            NSLog(@"[+] App is operating in Limited Photo Access mode");
            NSLog(@"    This is the most privacy-friendly photo access level");
            
            // 检查应用是否尝试绕过限制
            // 某些应用可能通过其他方式（如UIDocumentPickerViewController）
            // 间接获取更多照片信息
        }
    }
}

@end
```

---

## 5. 通讯录与日历权限泄露

### 5.1 通讯录数据挖掘

```objectivec
/*
 * 通讯录权限滥用分析
 * 漏洞类型: 联系人数据大规模采集 + 社交图谱构建
 */

@interface ContactsPrivacyAnalyzer : NSObject

+ (void)analyzeContactsAccess;
+ (NSDictionary *)extractContactFingerprint:(CNContact *)contact;

@end

@implementation ContactsPrivacyAnalyzer

+ (void)analyzeContactsAccess {
    CNAuthorizationStatus status = [CNContactStore authorizationStatusForEntityType:CNEntityTypeContacts];
    
    if (status != CNAuthorizationStatusAuthorized) {
        NSLog(@"[+] Contacts access not authorized");
        return;
    }
    
    CNContactStore *store = [[CNContactStore alloc] init];
    
    // 分析可获取的联系人字段
    NSArray *keysToFetch = @[
        CNContactGivenNameKey,           // 名
        CNContactFamilyNameKey,          // 姓
        CNContactPhoneNumbersKey,        // 电话号码
        CNContactEmailAddressesKey,      // 邮箱地址
        CNContactPostalAddressesKey,     // 邮寄地址
        CNContactBirthdayKey,            // 生日
        CNContactOrganizationNameKey,    // 组织/公司
        CNContactJobTitleKey,            // 职位
        CNContactSocialProfilesKey,      // 社交账号
        CNContactInstantMessageAddressesKey, // 即时通讯
        CNContactUrlAddressesKey,        // URL
        CNContactNoteKey,               // 备注
        CNContactRelationsKey,          // 关系
    ];
    
    NSLog(@"[!] CRITICAL: Full contacts access allows:");
    NSLog(@"    - Name, phone, email extraction");
    NSLog(@"    - Physical address harvesting");
    NSLog(@"    - Birthday/social info collection");
    NSLog(@"    - Organization/employment data");
    NSLog(@"    - Social media account discovery");
    NSLog(@"    - Personal notes and relationships");
    
    CNFetchRequest *request = [CNContactFetchRequest alloc]
        initWithKeysToFetch:keysToFetch;
    
    __block NSUInteger contactCount = 0;
    __block NSUInteger withPhoneCount = 0;
    __block NSUInteger withEmailCount = 0;
    __block NSUInteger withAddressCount = 0;
    
    NSError *error = nil;
    [store enumerateContactsWithFetchRequest:request error:&error
        usingBlock:^(CNContact *contact, BOOL *stop) {
            contactCount++;
            if (contact.phoneNumbers.count > 0) withPhoneCount++;
            if (contact.emailAddresses.count > 0) withEmailCount++;
            if (contact.postalAddresses.count > 0) withAddressCount++;
        }];
    
    NSLog(@"\n[+] Contacts Statistics:");
    NSLog(@"    Total contacts: %lu", (unsigned long)contactCount);
    NSLog(@"    With phone: %lu", (unsigned long)withPhoneCount);
    NSLog(@"    With email: %lu", (unsigned long)withEmailCount);
    NSLog(@"    With address: %lu", (unsigned long)withAddressCount);
    
    if (contactCount > 0) {
        NSLog(@"\n[!] Privacy Impact:");
        NSLog(@"    - %lu phone numbers exposed to app developer",
              (unsigned long)withPhoneCount);
        NSLog(@"    - %lu email addresses exposed",
              (unsigned long)withEmailCount);
        NSLog(@"    - %lu physical addresses exposed",
              (unsigned long)withAddressCount);
        NSLog(@"    - Social graph can be reconstructed");
    }
}

+ (NSDictionary *)extractContactFingerprint:(CNContact *)contact {
    // 即使不获取完整信息，组合字段也可创建唯一标识
    NSMutableDictionary *fingerprint = [NSMutableDictionary dictionary];
    
    // 姓名哈希
    NSString *fullName = [NSString stringWithFormat:@"%@%@",
        contact.givenName, contact.familyName];
    if (fullName.length > 0) {
        fingerprint[@"name_hash"] = [self sha256:fullName];
    }
    
    // 电话号码哈希
    if (contact.phoneNumbers.count > 0) {
        NSString *phone = contact.phoneNumbers.firstObject.value.stringValue;
        fingerprint[@"phone_hash"] = [self sha256:phone];
        fingerprint[@"phone_count"] = @(contact.phoneNumbers.count);
    }
    
    // 邮箱哈希
    if (contact.emailAddresses.count > 0) {
        NSString *email = contact.emailAddresses.firstObject.value;
        fingerprint[@"email_hash"] = [self sha256:email];
    }
    
    // 即使哈希后，这些数据仍可用于交叉匹配
    // 与已泄露数据库比对可还原真实信息
    
    return fingerprint;
}

+ (NSString *)sha256:(NSString *)input {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, (CC_LONG)strlen(cStr), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}

@end
```

### 5.2 日历数据隐私分析

```objectivec
/*
 * 日历权限隐私分析
 * 漏洞类型: 日程泄露 + 行为模式分析
 */

@interface CalendarPrivacyAnalyzer : NSObject

+ (void)analyzeCalendarAccess;
+ (NSDictionary *)extractBehaviorPattern:(EKEventStore *)store;

@end

@implementation CalendarPrivacyAnalyzer

+ (void)analyzeCalendarAccess {
    EKAuthorizationStatus status =
        [EKEventStore authorizationStatusForEntityType:EKEntityTypeEvent];
    
    if (status != EKAuthorizationStatusAuthorized) {
        NSLog(@"[+] Calendar access not authorized");
        return;
    }
    
    EKEventStore *store = [[EKEventStore alloc] init];
    
    NSLog(@"[!] Calendar access reveals:");
    NSLog(@"    - Meeting schedules and attendees");
    NSLog(@"    - Travel plans (from location events)");
    NSLog(@"    - Medical appointments");
    NSLog(@"    - Personal activities");
    NSLog(@"    - Work patterns and schedule");
    NSLog(@"    - Contact information (event attendees)");
    
    // 获取未来30天的事件
    NSDate *startDate = [NSDate date];
    NSDate *endDate = [NSDate dateWithTimeIntervalSinceNow:30 * 24 * 3600];
    
    NSPredicate *predicate = [store predicateForEventsWithStartDate:startDate
        endDate:endDate calendars:nil];
    
    NSArray<EKEvent *> *events = [store eventsMatchingPredicate:predicate];
    
    NSLog(@"\n[+] Events in next 30 days: %lu", (unsigned long)events.count);
    
    // 分析事件类型分布
    NSMutableDictionary *categories = [NSMutableDictionary dictionary];
    
    for (EKEvent *event in events) {
        NSString *calendarTitle = event.calendar.title;
        categories[calendarTitle] = @(categories[calendarTitle].intValue + 1);
        
        // 检查敏感事件
        NSString *lowerTitle = event.title.lowercaseString ?: @"";
        NSArray *sensitiveKeywords = @[
            @"doctor", @"hospital", @"medical", @"therapy", @"counsel",
            @"interview", @"court", @"lawyer", @"bank", @"loan",
        ];
        
        for (NSString *keyword in sensitiveKeywords) {
            if ([lowerTitle containsString:keyword]) {
                NSLog(@"[!] Sensitive event: %@ (calendar: %@)",
                      event.title, calendarTitle);
                break;
            }
        }
    }
    
    NSLog(@"\n[+] Calendar categories:");
    for (NSString *title in categories) {
        NSLog(@"    %@: %d events", title, categories[title].intValue);
    }
}

+ (NSDictionary *)extractBehaviorPattern:(EKEventStore *)store {
    // 从日历事件中提取行为模式
    NSMutableDictionary *patterns = [NSMutableDictionary dictionary];
    
    NSDate *startDate = [NSDate dateWithTimeIntervalSinceNow:-90 * 24 * 3600];
    NSDate *endDate = [NSDate date];
    
    NSPredicate *predicate = [store predicateForEventsWithStartDate:startDate
        endDate:endDate calendars:nil];
    NSArray<EKEvent *> *events = [store eventsMatchingPredicate:predicate];
    
    // 分析工作时间模式
    NSMutableDictionary *hourlyDistribution = [NSMutableDictionary dictionary];
    for (EKEvent *event in events) {
        NSCalendar *cal = [NSCalendar currentCalendar];
        NSDateComponents *components = [cal components:NSCalendarUnitHour
            fromDate:event.startDate];
        NSString *hour = @(components.hour).stringValue;
        hourlyDistribution[hour] = @(hourlyDistribution[hour].intValue + 1);
    }
    patterns[@"hourly_activity"] = hourlyDistribution;
    
    // 分析每周模式
    NSMutableDictionary *weeklyDistribution = [NSMutableDictionary dictionary];
    for (EKEvent *event in events) {
        NSCalendar *cal = [NSCalendar currentCalendar];
        NSDateComponents *components = [cal components:NSCalendarUnitWeekday
            fromDate:event.startDate];
        NSString *day = @(components.weekday).stringValue;
        weeklyDistribution[day] = @(weeklyDistribution[day].intValue + 1);
    }
    patterns[@"weekly_activity"] = weeklyDistribution;
    
    // 分析地点模式
    NSMutableArray *locations = [NSMutableArray array];
    for (EKEvent *event in events) {
        if (event.location) {
            [locations addObject:event.location];
        }
    }
    patterns[@"frequent_locations"] = locations;
    
    NSLog(@"[+] Behavior pattern extracted from %lu events",
          (unsigned long)events.count);
    
    return patterns;
}

@end
```

---

## 6. 麦克风与语音权限风险

### 6.1 麦克风权限监控

```objectivec
/*
 * 麦克风权限安全风险分析
 * 漏洞类型: 隐蔽录音 + 语音指纹 + 环境分析
 */

@interface MicrophonePrivacyMonitor : NSObject

@property (nonatomic, strong) AVAudioEngine *audioEngine;
@property (nonatomic, assign) BOOL isRecording;
@property (nonatomic, strong) NSMutableArray *audioLevelHistory;

- (void)monitorMicrophoneAccess;
- (void)detectCovertRecording;

@end

@implementation MicrophonePrivacyMonitor

- (void)monitorMicrophoneAccess {
    // 检查麦克风权限状态
    AVAudioSessionRecordPermission permission =
        [[AVAudioSession sharedInstance] recordPermission];
    
    switch (permission) {
        case AVAudioSessionRecordPermissionGranted:
            NSLog(@"[!] Microphone access GRANTED");
            NSLog(@"    App can record audio at any time");
            break;
        case AVAudioSessionRecordPermissionDenied:
            NSLog(@"[+] Microphone access DENIED");
            break;
        case AVAudioSessionRecordPermissionUndetermined:
            NSLog(@"[ ] Microphone permission not yet requested");
            break;
    }
    
    // 监控音频输入路由变化
    [[NSNotificationCenter defaultCenter] addObserver:self
        selector:@selector(audioRouteChanged:)
        name:AVAudioSessionRouteChangeNotification
        object:[AVAudioSession sharedInstance]];
}

- (void)detectCovertRecording {
    // 检测隐蔽录音行为
    
    // 方法1：检查音频会话是否活跃
    AVAudioSession *session = [AVAudioSession sharedInstance];
    
    if (session.isOtherAudioPlaying) {
        // 其他应用正在播放音频时，当前应用不应需要录音
        if (session.currentRoute.inputs.count > 0) {
            NSLog(@"[!] WARNING: Audio input active while other audio playing");
        }
    }
    
    // 方法2：监控音频电平（不实际录音）
    // 通过AVAudioEngine的inputNode可以获取音频电平
    // 而不保存实际音频数据
    
    self.audioEngine = [[AVAudioEngine alloc] init];
    AVAudioInputNode *inputNode = self.audioEngine.inputNode;
    
    [inputNode installTapOnBus:0 bufferSize:1024
        format:inputNode.outputFormatForBus(0)
        block:^(AVAudioPCMBuffer *buffer, AVAudioTime *when) {
            
            // 计算音频电平（RMS）
            float *samples = buffer.floatChannelData[0];
            float sum = 0;
            for (int i = 0; i < buffer.frameLength; i++) {
                sum += samples[i] * samples[i];
            }
            float rms = sqrt(sum / buffer.frameLength);
            
            // 记录电平历史
            if (!self.audioLevelHistory) {
                self.audioLevelHistory = [NSMutableArray array];
            }
            [self.audioLevelHistory addObject:@(rms)];
            
            // 检测异常音频模式
            if (rms > 0.1) {
                // 高音量可能表示语音活动
                NSLog(@"[MIC] Audio level: %.4f (potential voice activity)", rms);
            }
        }];
    
    NSError *error;
    [self.audioEngine startAndReturnError:&error];
    if (error) {
        NSLog(@"[!] Audio engine start failed: %@", error);
    }
}

- (void)audioRouteChanged:(NSNotification *)notification {
    NSDictionary *info = notification.userInfo;
    AVAudioSessionRouteDescription *route = info[AVAudioSessionRouteDescriptionKey];
    NSInteger reason = [info[AVAudioSessionRouteChangeReasonKey] integerValue];
    
    NSLog(@"[MIC] Audio route changed: reason=%ld, inputs=%lu",
          (long)reason, (unsigned long)route.inputs.count);
    
    // 检查是否有新的输入设备被激活
    for (AVAudioSessionPortDescription *port in route.inputs) {
        NSLog(@"[MIC] Input port: %@ (%@)", port.portName, port.portType);
    }
}

@end

// 语音指纹分析
@interface VoiceFingerprintAnalyzer : NSObject

+ (NSDictionary *)extractVoiceFeatures:(AVAudioPCMBuffer *)buffer;
+ (NSString *)generateVoiceHash:(AVAudioPCMBuffer *)buffer;

@end

@implementation VoiceFingerprintAnalyzer

+ (NSDictionary *)extractVoiceFeatures:(AVAudioPCMBuffer *)buffer {
    // 从音频缓冲区提取语音特征
    // 这些特征可以用于说话人识别
    
    NSMutableDictionary *features = [NSMutableDictionary dictionary];
    
    float *samples = buffer.floatChannelData[0];
    int frameLength = buffer.frameLength;
    
    // 计算基本音频特征
    float energy = 0;
    float maxAmplitude = 0;
    int zeroCrossings = 0;
    
    for (int i = 0; i < frameLength; i++) {
        float sample = samples[i];
        energy += sample * sample;
        maxAmplitude = MAX(maxAmplitude, fabs(sample));
        
        if (i > 0 && ((samples[i] >= 0 && samples[i-1] < 0) ||
                       (samples[i] < 0 && samples[i-1] >= 0))) {
            zeroCrossings++;
        }
    }
    
    features[@"energy"] = @(energy / frameLength);
    features[@"max_amplitude"] = @(maxAmplitude);
    features[@"zero_crossing_rate"] = @((float)zeroCrossings / frameLength);
    
    // 过零率和能量可以区分语音/静音/噪声
    // 更高级的特征（MFCC等）可以识别说话人
    
    return features;
}

+ (NSString *)generateVoiceHash:(AVAudioPCMBuffer *)buffer {
    // 生成音频片段的哈希（用于去重和匹配）
    NSData *audioData = [NSData dataWithBytes:buffer.floatChannelData[0]
        length:buffer.frameLength * sizeof(float)];
    
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(audioData.bytes, (CC_LONG)audioData.length, hash);
    
    NSMutableString *hashStr = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashStr appendFormat:@"%02x", hash[i]];
    }
    
    return hashStr;
}

@end
```

---

## 7. 通知权限与推送隐私

### 7.1 推送通知隐私分析

```objectivec
/*
 * 推送通知隐私安全分析
 * 漏洞类型: 设备令牌泄露 + 通知内容拦截 + 推送元数据收集
 */

@interface PushNotificationPrivacyAnalyzer : NSObject

+ (void)analyzePushNotificationPrivacy;
+ (void)checkDeviceTokenHandling;

@end

@implementation PushNotificationPrivacyAnalyzer

+ (void)analyzePushNotificationPrivacy {
    NSLog(@"[+] Push Notification Privacy Analysis");
    
    // 1. 设备令牌安全
    // APNs设备令牌唯一标识设备
    // 泄露后可被用于向设备发送恶意推送
    
    NSLog(@"[!] Device token considerations:");
    NSLog(@"    - Token uniquely identifies device+app combination");
    NSLog(@"    - Token can change (OS update, restore, etc.)");
    NSLog(@"    - Token sent to developer's push server");
    NSLog(@"    - If server compromised, token can be misused");
    
    // 2. 推送内容隐私
    // 默认情况下，推送内容经过APNs服务器
    // Apple服务器可以看到推送内容（除非端到端加密）
    
    NSLog(@"\n[!] Push content privacy:");
    NSLog(@"    - Push payload passes through Apple servers");
    NSLog(@"    - Content visible to Apple (not E2E encrypted)");
    NSLog(@"    - Sensitive data should not be in push payload");
    NSLog(@"    - Use content-available for silent triggers");
    
    // 3. 通知元数据
    // 推送可以包含丰富的元数据
    
    NSLog(@"\n[!] Metadata exposure:");
    NSLog(@"    - Badge count reveals unread message count");
    NSLog(@"    - Category reveals notification type");
    NSLog(@"    - Thread ID reveals conversation grouping");
    NSLog(@"    - Sound reveals notification priority");
    
    // 4. 通知交互追踪
    // 应用可以追踪用户是否查看/交互了通知
    
    NSLog(@"\n[!] Interaction tracking:");
    NSLog(@"    - App knows when notification was delivered");
    NSLog(@"    - App knows when user tapped notification");
    NSLog(@"    - App knows which action user selected");
    NSLog(@"    - Timing data reveals user activity patterns");
}

+ (void)checkDeviceTokenHandling {
    // 检查设备令牌的存储和传输安全性
    
    // 安全做法：
    // 1. 令牌应存储在Keychain中
    // 2. 传输应使用TLS
    // 3. 令牌变更时应及时更新
    
    NSLog(@"[+] Checking device token handling best practices:");
    NSLog(@"    - Token stored in Keychain (not UserDefaults)");
    NSLog(@"    - Token transmitted over TLS only");
    NSLog(@"    - Token refreshed on didRegisterForRemoteNotifications");
    NSLog(@"    - Token invalidated on app uninstall");
}

@end
```

---

## 8. 后台权限与数据收集

### 8.1 后台模式安全分析

```objectivec
/*
 * 后台权限与数据收集安全分析
 * 漏洞类型: 后台持续监控 + 隐蔽数据上传
 */

// 后台模式权限审计
@interface BackgroundModeAuditor : NSObject

+ (void)auditBackgroundModes:(NSArray *)backgroundModes;
+ (void)analyzeBackgroundDataCollection;

@end

@implementation BackgroundModeAuditor

+ (void)auditBackgroundModes:(NSArray *)backgroundModes {
    NSLog(@"[+] Background Modes Audit");
    NSLog(@"    Configured modes: %@", backgroundModes);
    
    // 高风险后台模式
    NSDictionary *riskAssessment = @{
        @"location": @{
            @"risk": @"CRITICAL",
            @"description": @"Continuous location tracking in background",
            @"data_volume": @"High - continuous GPS data"
        },
        @"audio": @{
            @"risk": @"HIGH",
            @"description": @"Background audio recording/streaming",
            @"data_volume": @"Very high - continuous audio stream"
        },
        @"voip": @{
            @"risk": @"MEDIUM",
            @"description": @"Voice over IP - keeps connection alive",
            @"data_volume": @"Medium - signaling data"
        },
        @"fetch": @{
            @"risk": @"MEDIUM",
            @"description": @"Background content refresh",
            @"data_volume": @"Variable - depends on implementation"
        },
        @"remote-notification": @{
            @"risk": @"LOW",
            @"description": @"Silent push notification processing",
            @"data_volume": @"Low - event-driven"
        },
        @"newsstand-content": @{
            @"risk": @"LOW",
            @"description": @"Newsstand content download",
            @"data_volume": @"Medium - periodic downloads"
        },
        @"external-accessory": @{
            @"risk": @"MEDIUM",
            @"description": @"External accessory communication",
            @"data_volume": @"Variable"
        },
        @"bluetooth-central": @{
            @"risk": @"MEDIUM",
            @"description": @"Bluetooth peripheral scanning",
            @"data_volume": @"Medium - device discovery data"
        },
        @"bluetooth-peripheral": @{
            @"risk": @"HIGH",
            @"description": @"Acting as Bluetooth peripheral",
            @"data_volume": @"Variable - can broadcast data"
        },
        @"background-processing": @{
            @"risk": @"MEDIUM",
            @"description": @"General background processing",
            @"data_volume": @"Variable"
        },
    };
    
    for (NSString *mode in backgroundModes) {
        NSDictionary *assessment = riskAssessment[mode];
        if (assessment) {
            NSLog(@"\n[%@] %@: %@", assessment[@"risk"], mode, assessment[@"description"]);
            NSLog(@"    Data volume: %@", assessment[@"data_volume"]);
        }
    }
}

+ (void)analyzeBackgroundDataCollection {
    // 分析后台数据收集行为
    
    NSLog(@"\n[+] Background Data Collection Analysis");
    
    // 1. 后台位置收集
    // 即使应用不在前台，仍可每几秒获取位置
    
    // 2. 后台网络活动
    // 应用可以在后台发送数据到服务器
    // iOS对后台网络活动有一定限制，但仍有大量数据可传输
    
    // 3. 后台蓝牙扫描
    // 可以发现附近的BLE设备
    // 用于设备追踪和室内定位
    
    // 4. 后台音频处理
    // 可以持续录音并进行语音分析
    // Siri等语音助手使用此能力
    
    // 5. 后台运动数据
    // CoreMotion可以在后台收集步数、姿态等数据
    
    // 估算后台数据收集量
    NSLog(@"\n[+] Estimated background data collection per day:");
    NSLog(@"    Location (GPS): ~50-200 KB/day");
    NSLog(@"    Location (WiFi): ~5-20 KB/day");
    NSLog(@"    Bluetooth scan: ~10-50 KB/day");
    NSLog(@"    Background fetch: ~100 KB-1 MB/day");
    NSLog(@"    Motion data: ~1-5 KB/day");
    NSLog(@"    Audio (if active): ~50-500 MB/day");
}

@end

// 后台任务安全监控
@interface BackgroundTaskMonitor : NSObject

@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDate *> *activeTasks;

- (void)registerBackgroundTask:(NSString *)taskName;
- (void)endBackgroundTask:(NSString *)taskName;
- (void)auditBackgroundTasks;

@end

@implementation BackgroundTaskMonitor

- (instancetype)init {
    self = [super init];
    if (self) {
        _activeTasks = [NSMutableDictionary dictionary];
    }
    return self;
}

- (void)registerBackgroundTask:(NSString *)taskName {
    self.activeTasks[taskName] = [NSDate date];
    NSLog(@"[BG] Task started: %@ at %@", taskName, [NSDate date]);
}

- (void)endBackgroundTask:(NSString *)taskName {
    NSDate *startTime = self.activeTasks[taskName];
    if (startTime) {
        NSTimeInterval duration = [[NSDate date] timeIntervalSinceDate:startTime];
        NSLog(@"[BG] Task ended: %@ (duration: %.1fs)", taskName, duration);
        [self.activeTasks removeObjectForKey:taskName];
    }
}

- (void)auditBackgroundTasks {
    NSLog(@"\n[+] Active Background Tasks Audit:");
    
    for (NSString *taskName in self.activeTasks) {
        NSDate *startTime = self.activeTasks[taskName];
        NSTimeInterval duration = [[NSDate date] timeIntervalSinceDate:startTime];
        
        NSLog(@"    %@: running for %.1f seconds", taskName, duration);
        
        if (duration > 180) { // 超过3分钟
            NSLog(@"[!] WARNING: Long-running background task: %@", taskName);
        }
    }
    
    NSLog(@"    Total active tasks: %lu", (unsigned long)self.activeTasks.count);
}

@end
```

---

## 9. 剪贴板与键盘输入监控

### 9.1 剪贴板隐私分析

```objectivec
/*
 * 剪贴板隐私安全分析
 * 漏洞类型: 剪贴板嗅探 + 敏感数据窃取
 * iOS 14+ 已添加剪贴板访问通知
 */

@interface ClipboardPrivacyAnalyzer : NSObject

+ (void)analyzeClipboardAccess;
+ (void)detectSensitiveDataInClipboard;
+ (void)monitorClipboardChanges;

@end

@implementation ClipboardPrivacyAnalyzer

+ (void)analyzeClipboardAccess {
    UIPasteboard *generalPasteboard = [UIPasteboard generalPasteboard];
    
    NSLog(@"[+] Clipboard Privacy Analysis");
    
    // 检查剪贴板内容类型
    NSArray *pasteboardTypes = generalPasteboard.types;
    NSLog(@"    Content types: %@", pasteboardTypes);
    
    // 检查文本内容
    NSString *text = generalPasteboard.string;
    if (text) {
        NSLog(@"    Text content: %lu characters", (unsigned long)text.length);
        
        // 检测敏感内容模式
        [self detectSensitivePatterns:text];
    }
    
    // 检查URL内容
    NSURL *url = generalPasteboard.URL;
    if (url) {
        NSLog(@"    URL: %@", url.absoluteString);
        // URL可能包含敏感参数（token、session ID等）
    }
    
    // 检查图片内容
    UIImage *image = generalPasteboard.image;
    if (image) {
        NSLog(@"    Image: %.0fx%.0f pixels",
              image.size.width, image.size.height);
    }
    
    // 检查剪贴板变更历史
    // iOS 14+ 提供 changeCount 属性
    NSInteger changeCount = generalPasteboard.changeCount;
    NSLog(@"    Change count: %ld", (long)changeCount);
    
    // 检查是否有多个项目
    NSInteger numberOfItems = generalPasteboard.numberOfItems;
    NSLog(@"    Items count: %ld", (long)numberOfItems);
    
    // 检查过期设置
    // iOS 14+ 支持设置剪贴板过期时间
    NSLog(@"    Expiration date: %@",
          generalPasteboard.expirationDate ?: @"none");
    
    // 检查本地Only标志
    NSLog(@"    Local only: %@",
          generalPasteboard.isLocalOnly ? @"YES" : @"NO");
}

+ (void)detectSensitiveDataInClipboard {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    NSString *text = pb.string;
    
    if (!text) return;
    
    [self detectSensitivePatterns:text];
}

+ (void)detectSensitivePatterns:(NSString *)text {
    // 检测剪贴板中的敏感数据模式
    
    // 1. 信用卡号（Luhn算法验证）
    NSString *ccPattern = @"\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b";
    if ([self matchesPattern:ccPattern inString:text]) {
        NSLog(@"[!] CRITICAL: Credit card number pattern detected in clipboard");
    }
    
    // 2. 社会安全号（SSN格式）
    NSString *ssnPattern = @"\\b\\d{3}-\\d{2}-\\d{4}\\b";
    if ([self matchesPattern:ssnPattern inString:text]) {
        NSLog(@"[!] CRITICAL: SSN pattern detected in clipboard");
    }
    
    // 3. 密码/令牌
    NSArray *passwordPatterns = @[
        @"password\\s*[:=]\\s*\\S+",
        @"token\\s*[:=]\\s*\\S+",
        @"secret\\s*[:=]\\s*\\S+",
        @"api[_-]?key\\s*[:=]\\s*\\S+",
    ];
    
    for (NSString *pattern in passwordPatterns) {
        if ([self matchesPattern:pattern inString:text]) {
            NSLog(@"[!] CRITICAL: Password/token pattern detected in clipboard");
            break;
        }
    }
    
    // 4. 加密货币地址
    NSString *btcPattern = @"\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b";
    if ([self matchesPattern:btcPattern inString:text]) {
        NSLog(@"[!] WARNING: Bitcoin address pattern detected");
    }
    
    // 5. 电话号码
    NSString *phonePattern = @"\\b\\+?\\d{1,3}[-.\\s]?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b";
    if ([self matchesPattern:phonePattern inString:text]) {
        NSLog(@"[!] WARNING: Phone number pattern in clipboard");
    }
    
    // 6. 邮箱地址
    NSString *emailPattern = @"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b";
    if ([self matchesPattern:emailPattern inString:text]) {
        NSLog(@"[!] INFO: Email address pattern in clipboard");
    }
}

+ (BOOL)matchesPattern:(NSString *)pattern inString:(NSString *)string {
    NSError *error = nil;
    NSRegularExpression *regex = [NSRegularExpression
        regularExpressionWithPattern:pattern
        options:NSRegularExpressionCaseInsensitive
        error:&error];
    
    if (error) return NO;
    
    NSRange range = NSMakeRange(0, string.length);
    return [regex numberOfMatchesInString:string options:0 range:range] > 0;
}

+ (void)monitorClipboardChanges {
    // 监控剪贴板变化
    [[NSNotificationCenter defaultCenter] addObserverForName:UIPasteboardChangedNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *notification) {
            
            NSDictionary *userInfo = notification.userInfo;
            NSArray *changedTypes = userInfo[UIPasteboardChangedTypesAddedKey];
            
            NSLog(@"[CLIP] Clipboard changed: new types = %@", changedTypes);
            
            // 检查是否有应用正在频繁读取剪贴板
            // iOS 14+ 会在应用读取剪贴板时显示横幅
        }];
}

@end
```

### 9.2 自定义键盘隐私分析

```objectivec
/*
 * 自定义键盘扩展隐私安全分析
 * 漏洞类型: 键盘记录 + 输入数据收集
 */

@interface KeyboardExtensionPrivacyAnalyzer : NSObject

+ (void)analyzeKeyboardExtensionPrivacy;
+ (void)checkOpenAccessImplications;

@end

@implementation KeyboardExtensionPrivacyAnalyzer

+ (void)analyzeKeyboardExtensionPrivacy {
    NSLog(@"[+] Keyboard Extension Privacy Analysis");
    
    // 自定义键盘扩展有两种权限级别：
    // 1. 默认模式：有限的API访问
    // 2. Open Access：完全访问能力
    
    NSLog(@"\n[!] Default Mode (Restricted):");
    NSLog(@"    - Can read user input (keystrokes)");
    NSLog(@"    - Cannot access network");
    NSLog(@"    - Cannot access shared containers");
    NSLog(@"    - Cannot access location");
    NSLog(@"    - Limited pasteboard access");
    
    NSLog(@"\n[!] Open Access Mode:");
    NSLog(@"    - Can read user input (keystrokes)");
    NSLog(@"    - CAN access network");
    NSLog(@"    - CAN access shared containers");
    NSLog(@"    - CAN access location (with permission)");
    NSLog(@"    - CAN access contacts (with permission)");
    NSLog(@"    - Full pasteboard access");
    NSLog(@"    - CAN send keystrokes to server");
    
    NSLog(@"\n[!] Privacy implications:");
    NSLog(@"    - EVERY keystroke can be captured");
    NSLog(@"    - Passwords typed in any app are visible");
    NSLog(@"    - Credit card numbers can be harvested");
    NSLog(@"    - Messages can be read in real-time");
    NSLog(@"    - Search queries can be tracked");
}

+ (void)checkOpenAccessImplications {
    NSLog(@"\n[+] Open Access threat model:");
    
    // 模拟键盘记录攻击（仅用于安全研究）
    NSLog(@"    Attack scenario:");
    NSLog(@"    1. User installs third-party keyboard");
    NSLog(@"    2. User enables 'Full Access' in Settings");
    NSLog(@"    3. Keyboard extension captures all input");
    NSLog(@"    4. Input data sent to attacker's server");
    NSLog(@"    5. Sensitive data (passwords, CC#) compromised");
    
    // 检测方法
    NSLog(@"\n[+] Detection methods:");
    NSLog(@"    - Monitor network traffic from keyboard extension");
    NSLog(@"    - Check keyboard's Open Access entitlement");
    NSLog(@"    - Audit keyboard's privacy policy");
    NSLog(@"    - Use system keyboard for sensitive input");
}

@end
```

---

## 10. 广告追踪与隐私泄露

### 10.1 ATT框架分析

```objectivec
/*
 * App Tracking Transparency (ATT) 安全分析
 * 漏洞类型: 追踪绕过 + 指纹识别 + 跨应用关联
 */

@interface ATTFrameworkAnalyzer : NSObject

+ (void)analyzeATTImplementation;
+ (void)detectTrackingBypass;
+ (void)analyzeDeviceFingerprinting;

@end

@implementation ATTFrameworkAnalyzer

+ (void)analyzeATTImplementation {
    NSLog(@"[+] ATT Framework Analysis");
    
    // 检查ATT授权状态
    ATTrackingManagerAuthorizationStatus status =
        [ATTrackingManager trackingAuthorizationStatus];
    
    switch (status) {
        case ATTrackingManagerAuthorizationStatusAuthorized:
            NSLog(@"[!] Tracking AUTHORIZED - IDFA available");
            NSLog(@"    IDFA: %@", [ASIdentifierManager sharedManager]
                .advertisingIdentifier.UUIDString);
            break;
            
        case ATTrackingManagerAuthorizationStatusDenied:
            NSLog(@"[+] Tracking DENIED - IDFA zeroed out");
            NSLog(@"    IDFA: %@", [ASIdentifierManager sharedManager]
                .advertisingIdentifier.UUIDString);
            // 应该返回 00000000-0000-0000-0000-000000000000
            break;
            
        case ATTrackingManagerAuthorizationStatusNotDetermined:
            NSLog(@"[ ] ATT prompt not yet shown");
            break;
            
        case ATTrackingManagerAuthorizationStatusRestricted:
            NSLog(@"[+] Tracking RESTRICTED (parental controls)");
            break;
    }
}

+ (void)detectTrackingBypass {
    NSLog(@"\n[+] Tracking Bypass Techniques Analysis");
    
    // 即使ATT被拒绝，广告商仍可能通过以下方式追踪：
    
    NSLog(@"\n[!] Method 1: Device Fingerprinting");
    NSLog(@"    - Combine device model, OS version, screen size");
    NSLog(@"    - Use locale, timezone, language settings");
    NSLog(@"    - Analyze installed fonts");
    NSLog(@"    - Check available storage space");
    NSLog(@"    - Monitor battery level patterns");
    
    NSLog(@"\n[!] Method 2: Probabilistic Fingerprinting");
    NSLog(@"    - Statistical matching across apps");
    NSLog(@"    - IP address correlation");
    NSLog(@"    - WiFi network name matching");
    NSLog(@"    - Bluetooth device proximity");
    
    NSLog(@"\n[!] Method 3: Login-Based Correlation");
    NSLog(@"    - Same email/phone across apps");
    NSLog(@"    - Social login correlation");
    NSLog(@"    - Phone number verification linking");
    
    NSLog(@"\n[!] Method 4: Side-Channel Data");
    NSLog(@"    - Clipboard content sharing");
    NSLog(@"    - Universal Links parameters");
    NSLog(@"    - Deep link parameter passing");
    NSLog(@"    - Shared Keychain groups");
    
    NSLog(@"\n[!] Method 5: Probabilistic ID Recycling");
    NSLog(@"    - Generate pseudo-ID from device characteristics");
    NSLog(@"    - Use SKAdNetwork for attribution without IDFA");
    NSLog(@"    - Leverage conversion values for fingerprinting");
}

+ (void)analyzeDeviceFingerprinting {
    NSLog(@"\n[+] Device Fingerprint Entropy Analysis");
    
    // 计算设备指纹的总熵值
    NSMutableDictionary *fingerprint = [NSMutableDictionary dictionary];
    double totalEntropy = 0;
    
    // 设备型号
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *deviceModel = [NSString stringWithCString:systemInfo.machine
        encoding:NSUTF8StringEncoding];
    fingerprint[@"device_model"] = deviceModel;
    totalEntropy += 4.0; // ~16 possible models
    
    // 操作系统版本
    NSString *osVersion = [[UIDevice currentDevice] systemVersion];
    fingerprint[@"os_version"] = osVersion;
    totalEntropy += 3.0;
    
    // 屏幕尺寸
    CGRect screenBounds = [UIScreen mainScreen].bounds;
    fingerprint[@"screen_size"] = [NSString stringWithFormat:@"%.0fx%.0f",
        screenBounds.size.width, screenBounds.size.height];
    totalEntropy += 2.0;
    
    // 屏幕缩放
    CGFloat screenScale = [UIScreen mainScreen].scale;
    fingerprint[@"screen_scale"] = @(screenScale).stringValue;
    totalEntropy += 1.0;
    
    // 时区
    fingerprint[@"timezone"] = [NSTimeZone localTimeZone].name;
    totalEntropy += 5.0;
    
    // 语言
    fingerprint[@"language"] = [NSLocale preferredLanguages].firstObject;
    totalEntropy += 3.0;
    
    // 可用存储
    NSDictionary *attrs = [[NSFileManager defaultManager]
        attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    NSNumber *totalSpace = attrs[NSFileSystemSize];
    fingerprint[@"storage_size"] = @(totalSpace.longLongValue / 1000000000).stringValue;
    totalEntropy += 3.0;
    
    // CPU核心数
    fingerprint[@"cpu_cores"] = @([NSProcessInfo processInfo].processorCount).stringValue;
    totalEntropy += 2.0;
    
    // 物理内存
    fingerprint[@"physical_memory"] =
        @([NSProcessInfo processInfo].physicalMemory / 1000000000).stringValue;
    totalEntropy += 2.0;
    
    NSLog(@"    Fingerprint components:");
    for (NSString *key in fingerprint) {
        NSLog(@"      %@: %@", key, fingerprint[key]);
    }
    NSLog(@"\n    Total estimated entropy: %.1f bits", totalEntropy);
    NSLog(@"    Unique devices possible: ~%.0f", pow(2, totalEntropy));
    
    if (totalEntropy > 20) {
        NSLog(@"[!] WARNING: High fingerprint entropy (%.1f bits)", totalEntropy);
        NSLog(@"    Device can be uniquely identified with high probability");
    }
}

@end
```

---

## 11. 第三方SDK权限滥用

### 11.1 SDK权限行为分析

```objectivec
/*
 * 第三方SDK权限滥用分析
 * 漏洞类型: SDK过度权限请求 + 隐蔽数据收集
 */

@interface SDKPermissionAuditor : NSObject

@property (nonatomic, strong) NSMutableDictionary<NSString *, NSArray *> *sdkPermissions;

- (void)auditSDKPermissions;
- (void)analyzeDataCollectionBySDK;

@end

@implementation SDKPermissionAuditor

- (instancetype)init {
    self = [super init];
    if (self) {
        _sdkPermissions = [NSMutableDictionary dictionary];
        [self loadKnownSDKBehaviors];
    }
    return self;
}

- (void)loadKnownSDKBehaviors {
    // 已知的第三方SDK权限使用模式
    self.sdkPermissions = [NSMutableDictionary dictionary];
    
    self.sdkPermissions[@"advertising"] = @[
        @"NSUserTrackingUsageDescription",     // ATT
        @"NSLocationWhenInUseUsageDescription", // 位置（广告定向）
        @"NSContactsUsageDescription",          // 联系人（社交图谱）
    ];
    
    self.sdkPermissions[@"analytics"] = @[
        @"NSUserTrackingUsageDescription",
        @"NSLocationWhenInUseUsageDescription",
        @"NSMotionUsageDescription",           // 运动数据
    ];
    
    self.sdkPermissions[@"social_login"] = @[
        @"NSContactsUsageDescription",          // 查找好友
        @"NSPhotoLibraryUsageDescription",      // 头像上传
        @"NSCameraUsageDescription",            // 拍照
    ];
    
    self.sdkPermissions[@"crash_reporting"] = @[
        // 通常不需要特殊权限
        // 但可以访问设备信息和崩溃日志
    ];
    
    self.sdkPermissions[@"payment"] = @[
        @"NSCameraUsageDescription",            // 信用卡扫描
        @"NSContactsUsageDescription",          // 转账联系人
    ];
}

- (void)auditSDKPermissions {
    NSLog(@"[+] Third-Party SDK Permission Audit");
    
    // 扫描项目中集成的SDK
    // 通过分析framework和pod依赖
    
    NSLog(@"\n[!] Common SDK permission issues:");
    
    // 广告SDK
    NSLog(@"\n    --- Advertising SDKs ---");
    NSLog(@"    Issue: Request location for ad targeting");
    NSLog(@"    Impact: User location shared with ad networks");
    NSLog(@"    Fix: Use coarse location or remove permission");
    
    NSLog(@"\n    Issue: Collecting IDFA without ATT");
    NSLog(@"    Impact: Violation of App Store guidelines");
    NSLog(@"    Fix: Implement ATT prompt properly");
    
    // 分析SDK数据外传
    NSLog(@"\n[+] SDK Data Transmission Analysis");
    NSLog(@"    Check network requests from SDK domains:");
    
    NSArray *knownSDKDomains = @[
        @"google-analytics.com",
        @"facebook.com",
        @"appsflyer.com",
        @"adjust.com",
        @"branch.io",
        @"firebase.google.com",
        @"crashlytics.com",
        @"mixpanel.com",
        @"amplitude.com",
        @"flurry.com",
    ];
    
    for (NSString *domain in knownSDKDomains) {
        NSLog(@"    - %@", domain);
    }
}

- (void)analyzeDataCollectionBySDK {
    NSLog(@"\n[+] SDK Data Collection Categories");
    
    NSDictionary *dataCategories = @{
        @"Device Info": @[
            @"Device model", @"OS version", @"Screen size",
            @"Battery level", @"Free storage", @"Jailbreak status"
        ],
        @"User Behavior": @[
            @"App open/close events", @"Screen views",
            @"Tap events", @"Scroll patterns", @"Session duration"
        ],
        @"Location Data": @[
            @"GPS coordinates", @"WiFi SSID", @"Cell tower ID",
            @"IP address", @"Timezone"
        ],
        @"Personal Data": @[
            @"Email (if provided)", @"Phone (if provided)",
            @"Contacts (if permitted)", @"Photos (if permitted)"
        ],
        @"Identifiers": @[
            @"IDFA", @"IDFV", @"Advertising ID",
            @"App-set ID", @"Device fingerprint"
        ],
    };
    
    for (NSString *category in dataCategories) {
        NSLog(@"\n    [%@]", category);
        NSArray *items = dataCategories[category];
        for (NSString *item in items) {
            NSLog(@"      - %@", item);
        }
    }
}

@end
```

---

## 12. 权限降级与绕过技术

### 12.1 权限状态操纵

```objectivec
/*
 * 权限降级与绕过技术分析
 * 用于安全研究和防御目的
 */

// 权限状态检查绕过分析
@interface PermissionBypassAnalyzer : NSObject

+ (void)analyzePermissionCheckPatterns;
+ (void)detectWeakPermissionValidation;

@end

@implementation PermissionBypassAnalyzer

+ (void)analyzePermissionCheckPatterns {
    NSLog(@"[+] Permission Check Pattern Analysis");
    
    // 模式1：仅在前端检查权限
    NSLog(@"\n[!] Pattern 1: Client-side only permission check");
    NSLog(@"    Vulnerability: Server doesn't verify permission state");
    NSLog(@"    Attack: Directly call API endpoints");
    NSLog(@"    Fix: Server-side permission verification");
    
    // 模式2：缓存权限状态
    NSLog(@"\n[!] Pattern 2: Cached permission status");
    NSLog(@"    Vulnerability: Permission change not reflected");
    NSLog(@"    Attack: Revoke permission, app still uses cached state");
    NSLog(@"    Fix: Check permission before each sensitive operation");
    
    // 模式3：权限降级后继续使用
    NSLog(@"\n[!] Pattern 3: Continued access after downgrade");
    NSLog(@"    Vulnerability: Open file handles not closed");
    NSLog(@"    Attack: Keep resources open after permission revocation");
    NSLog(@"    Fix: Observe permission changes, close resources");
    
    // 模式4：利用系统权限缓存
    NSLog(@"\n[!] Pattern 4: TCC database manipulation");
    NSLog(@"    Vulnerability: Direct TCC database modification");
    NSLog(@"    Attack: Modify TCC.db to grant permissions");
    NSLog(@"    Fix: Requires jailbreak (mitigated by SIP)");
}

+ (void)detectWeakPermissionValidation {
    NSLog(@"\n[+] Weak Permission Validation Patterns");
    
    // 检测代码中的弱权限验证模式
    NSArray *weakPatterns = @[
        // 仅在viewDidLoad中检查权限
        @"- (void)viewDidLoad { [self checkPermission]; }",
        
        // 使用BOOL缓存权限状态
        @"@property (nonatomic, assign) BOOL hasLocationPermission;",
        
        // 权限检查与使用之间的TOCTOU
        @"if ([self hasPermission]) { /* time passes */ [self useResource]; }",
        
        // 忽略权限拒绝回调
        @"// No handler for permission denial",
    ];
    
    for (NSString *pattern in weakPatterns) {
        NSLog(@"    Pattern: %@", pattern);
    }
}

@end

// 权限变更监控
@interface PermissionChangeObserver : NSObject

- (void)observePermissionChanges;

@end

@implementation PermissionChangeObserver

- (void)observePermissionChanges {
    // 监控各类权限状态变化
    
    // 1. 位置权限变化
    // CLLocationManagerDelegate 的 locationManagerDidChangeAuthorization:
    
    // 2. 相机/麦克风权限变化
    // 需要定期检查（无通知机制）
    
    // 3. 照片权限变化
    // PHPhotoLibrary的registerChangeObserver:
    
    // 4. 通讯录权限变化
    // 无直接通知，需定期检查
    
    NSLog(@"[+] Setting up permission change monitoring");
    
    // 定期检查权限状态
    [NSTimer scheduledTimerWithTimeInterval:5.0
        target:self selector:@selector(checkAllPermissions)
        userInfo:nil repeats:YES];
}

- (void)checkAllPermissions {
    // 检查所有已请求权限的当前状态
    
    // 位置
    CLAuthorizationStatus locStatus = [CLLocationManager authorizationStatus];
    
    // 相机
    AVAuthorizationStatus camStatus =
        [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];
    
    // 麦克风
    AVAuthorizationStatus micStatus =
        [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
    
    // 通讯录
    CNAuthorizationStatus contactStatus =
        [CNContactStore authorizationStatusForEntityType:CNEntityTypeContacts];
    
    // 检测权限降级
    // 如果权限从Authorized变为Denied，应立即停止数据收集
    NSLog(@"[PERM] Location:%ld Camera:%ld Mic:%ld Contacts:%ld",
          (long)locStatus, (long)camStatus, (long)micStatus, (long)contactStatus);
}

@end
```

---

## 13. 隐私保护防御机制

### 13.1 应用层隐私保护框架

```objectivec
/*
 * iOS隐私保护完整防御框架
 * 涵盖: 权限管理、数据最小化、传输安全、审计日志
 */

// 隐私保护管理器
@interface PrivacyProtectionManager : NSObject

@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *permissionStates;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *accessLog;
@property (nonatomic, assign) BOOL privacyModeEnabled;

+ (instancetype)sharedInstance;
- (BOOL)requestPermission:(NSString *)permissionType purpose:(NSString *)purpose;
- (void)logAccess:(NSString *)resourceType action:(NSString *)action;
- (BOOL)shouldAllowAccess:(NSString *)resourceType;

@end

@implementation PrivacyProtectionManager

+ (instancetype)sharedInstance {
    static PrivacyProtectionManager *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[PrivacyProtectionManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _permissionStates = [NSMutableDictionary dictionary];
        _accessLog = [NSMutableArray array];
        _privacyModeEnabled = YES;
    }
    return self;
}

// 数据最小化原则实现
- (BOOL)requestPermission:(NSString *)permissionType purpose:(NSString *)purpose {
    // 1. 验证权限请求的必要性
    if (![self isPermissionNecessary:permissionType forPurpose:purpose]) {
        NSLog(@"[PRIVACY] Permission %@ not necessary for: %@",
              permissionType, purpose);
        return NO;
    }
    
    // 2. 请求最小必要权限
    NSString *minLevel = [self minimumPermissionLevel:permissionType
                                           forPurpose:purpose];
    
    // 3. 记录权限请求
    [self logAccess:permissionType action:@"permission_requested"];
    
    // 4. 显示清晰的用户说明
    NSLog(@"[PRIVACY] Requesting %@ for: %@", permissionType, purpose);
    NSLog(@"[PRIVACY] Minimum level needed: %@", minLevel);
    
    return YES;
}

- (BOOL)isPermissionNecessary:(NSString *)permissionType
                   forPurpose:(NSString *)purpose {
    // 权限-目的映射表
    NSDictionary *necessaryPermissions = @{
        @"camera": @[@"photo_capture", @"video_call", @"qr_scan", @"ar"],
        @"microphone": @[@"voice_call", @"voice_message", @"voice_command"],
        @"location": @[@"navigation", @"nearby_search", @"delivery"],
        @"contacts": @[@"invite_friends", @"sync_contacts"],
        @"photos": @[@"profile_picture", @"share_photo", @"upload_image"],
    };
    
    NSArray *validPurposes = necessaryPermissions[permissionType];
    return [validPurposes containsObject:purpose];
}

- (NSString *)minimumPermissionLevel:(NSString *)permissionType
                          forPurpose:(NSString *)purpose {
    NSDictionary *minLevels = @{
        @"location_navigation": @"WhenInUse",
        @"location_nearby_search": @"WhenInUse",
        @"location_delivery": @"WhenInUse",
        @"photos_profile_picture": @"Limited",
        @"photos_share_photo": @"Limited",
        @"photos_upload_image": @"Limited",
    };
    
    NSString *key = [NSString stringWithFormat:@"%@_%@", permissionType, purpose];
    return minLevels[key] ?: @"Standard";
}

// 访问日志
- (void)logAccess:(NSString *)resourceType action:(NSString *)action {
    NSDictionary *entry = @{
        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
        @"resource": resourceType,
        @"action": action,
        @"app_state": [[UIApplication sharedApplication] applicationState] ==
            UIApplicationStateActive ? @"foreground" : @"background",
    };
    
    [self.accessLog addObject:entry];
    
    // 限制日志大小
    if (self.accessLog.count > 10000) {
        [self.accessLog removeObjectsInRange:NSMakeRange(0, 1000)];
    }
}

- (BOOL)shouldAllowAccess:(NSString *)resourceType {
    if (!self.privacyModeEnabled) return YES;
    
    // 检查当前权限状态
    NSNumber *state = self.permissionStates[resourceType];
    if (!state || state.boolValue == NO) {
        [self logAccess:resourceType action:@"access_denied_no_permission"];
        return NO;
    }
    
    // 检查是否在后台
    if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) {
        // 后台访问需要额外验证
        [self logAccess:resourceType action:@"background_access_check"];
    }
    
    [self logAccess:resourceType action:@"access_allowed"];
    return YES;
}

// 隐私数据清理
- (void)cleanSensitiveData {
    // 清理剪贴板
    [UIPasteboard generalPasteboard].items = @[];
    
    // 清理缓存
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
    
    // 清理Cookie
    [[NSHTTPCookieStorage sharedHTTPCookieStorage]
        removeCookiesSinceDate:[NSDate dateWithTimeIntervalSinceNow:-3600]];
    
    // 清理Web数据
    WKWebsiteDataStore *dataStore = [WKWebsiteDataStore defaultDataStore];
    NSSet *dataTypes = WKWebsiteDataStore.allWebsiteDataTypes;
    
    [dataStore removeDataOfTypes:dataTypes
        modifiedSince:[NSDate dateWithTimeIntervalSinceNow:-86400]
        completionHandler:^{
            NSLog(@"[PRIVACY] Sensitive data cleaned");
        }];
    
    [self logAccess:@"all" action:@"sensitive_data_cleaned"];
}

@end
```

### 13.2 隐私合规检查清单

```objectivec
/*
 * 隐私合规自动检查框架
 * 支持: GDPR, CCPA, 中国个人信息保护法
 */

@interface PrivacyComplianceChecker : NSObject

+ (void)checkGDPRCompliance;
+ (void)checkCCPACompliance;
+ (void)checkChinaPIPLCompliance;
+ (NSDictionary *)generateComplianceReport;

@end

@implementation PrivacyComplianceChecker

+ (void)checkGDPRCompliance {
    NSLog(@"\n========================================");
    NSLog(@"  GDPR Compliance Check");
    NSLog(@"========================================\n");
    
    NSArray *gdprRequirements = @[
        @{@"id": @"GDPR-001",
          @"requirement": @"Lawful basis for data processing",
          @"check": @"Verify consent obtained before data collection",
          @"status": @"pending"},
        
        @{@"id": @"GDPR-002",
          @"requirement": @"Data minimization",
          @"check": @"Only collect data necessary for stated purpose",
          @"status": @"pending"},
        
        @{@"id": @"GDPR-003",
          @"requirement": @"Purpose limitation",
          @"check": @"Data used only for stated purposes",
          @"status": @"pending"},
        
        @{@"id": @"GDPR-004",
          @"requirement": @"Right to access",
          @"check": @"Users can request their data",
          @"status": @"pending"},
        
        @{@"id": @"GDPR-005",
          @"requirement": @"Right to erasure",
          @"check": @"Users can request data deletion",
          @"status": @"pending"},
        
        @{@"id": @"GDPR-006",
          @"requirement": @"Data portability",
          @"check": @"Users can export their data",
          @"status": @"pending"},
        
        @{@"id": @"GDPR-007",
          @"requirement": @"Privacy by design",
          @"check": @"Privacy controls built into app architecture",
          @"status": @"pending"},
        
        @{@"id": @"GDPR-008",
          @"requirement": @"Data breach notification",
          @"check": @"Process for notifying users of data breaches",
          @"status": @"pending"},
    ];
    
    for (NSDictionary *req in gdprRequirements) {
        NSLog(@"[%@] %@", req[@"id"], req[@"requirement"]);
        NSLog(@"    Check: %@", req[@"check"]);
    }
}

+ (void)checkCCPACompliance {
    NSLog(@"\n========================================");
    NSLog(@"  CCPA Compliance Check");
    NSLog(@"========================================\n");
    
    NSArray *ccpaRequirements = @[
        @{@"id": @"CCPA-001",
          @"requirement": @"Right to know",
          @"check": @"Disclose data collected in past 12 months"},
        
        @{@"id": @"CCPA-002",
          @"requirement": @"Right to delete",
          @"check": @"Allow consumers to request data deletion"},
        
        @{@"id": @"CCPA-003",
          @"requirement": @"Right to opt-out",
          @"check": @"""Do Not Sell My Personal Information" link"},
        
        @{@"id": @"CCPA-004",
          @"requirement": @"Non-discrimination",
          @"check": @"Don't penalize users who exercise privacy rights"},
    ];
    
    for (NSDictionary *req in ccpaRequirements) {
        NSLog(@"[%@] %@", req[@"id"], req[@"requirement"]);
        NSLog(@"    Check: %@", req[@"check"]);
    }
}

+ (void)checkChinaPIPLCompliance {
    NSLog(@"\n========================================");
    NSLog(@"  China PIPL (个人信息保护法) Compliance Check");
    NSLog(@"========================================\n");
    
    NSArray *piplRequirements = @[
        @{@"id": @"PIPL-001",
          @"requirement": @"告知同意原则",
          @"check": @"收集个人信息前需明确告知并取得同意"},
        
        @{@"id": @"PIPL-002",
          @"requirement": @"最小必要原则",
          @"check": @"仅收集实现功能所必需的最少信息"},
        
        @{@"id": @"PIPL-003",
          @"requirement": @"目的限制原则",
          @"check": @"个人信息使用不得超出声明的目的"},
        
        @{@"id": @"PIPL-004",
          @"requirement": @"数据本地化",
          @"check": @"关键个人信息需在境内存储"},
        
        @{@"id": @"PIPL-005",
          @"requirement": @"跨境传输限制",
          @"check": @"向境外提供个人信息需满足安全评估要求"},
        
        @{@"id": @"PIPL-006",
          @"requirement": @"敏感个人信息保护",
          @"check": @"处理敏感信息需取得单独同意"},
        
        @{@"id": @"PIPL-007",
          @"requirement": @"个人信息删除权",
          @"check": @"用户有权请求删除其个人信息"},
        
        @{@"id": @"PIPL-008",
          @"requirement": @"自动化决策透明度",
          @"check": @"算法推荐需提供不针对个人特征的选项"},
    ];
    
    for (NSDictionary *req in piplRequirements) {
        NSLog(@"[%@] %@", req[@"id"], req[@"requirement"]);
        NSLog(@"    Check: %@", req[@"check"]);
    }
}

+ (NSDictionary *)generateComplianceReport {
    NSMutableDictionary *report = [NSMutableDictionary dictionary];
    
    report[@"timestamp"] = [[NSDate date] description];
    report[@"app_bundle_id"] = [[NSBundle mainBundle] bundleIdentifier];
    report[@"app_version"] = [[NSBundle mainBundle]
        objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    
    // 权限使用情况
    NSMutableArray *permissions = [NSMutableArray array];
    NSDictionary *plist = [[NSBundle mainBundle] infoDictionary];
    
    NSArray *permissionKeys = @[
        @"NSLocationWhenInUseUsageDescription",
        @"NSCameraUsageDescription",
        @"NSMicrophoneUsageDescription",
        @"NSContactsUsageDescription",
        @"NSPhotoLibraryUsageDescription",
    ];
    
    for (NSString *key in permissionKeys) {
        if (plist[key]) {
            [permissions addObject:@{
                @"key": key,
                @"description": plist[key],
            }];
        }
    }
    report[@"requested_permissions"] = permissions;
    
    // 后台模式
    report[@"background_modes"] = plist[@"UIBackgroundModes"] ?: @[];
    
    // 网络传输
    report[@"ats_exceptions"] = plist[@"NSAppTransportSecurity"] ?: @{};
    
    return report;
}

@end
```

---

## 14. 隐私合规审计工具

### 14.1 自动化隐私审计

```python
#!/usr/bin/env python3
"""
iOS应用隐私合规自动化审计工具

功能模块:
1. Info.plist权限声明审计
2. 第三方SDK隐私分析
3. 网络数据传输检测
4. 权限使用合理性评估
5. 隐私政策合规性检查
"""

import os
import re
import json
import plistlib
import hashlib
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PrivacySeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PrivacyFinding:
    """隐私审计发现"""
    finding_id: str
    title: str
    severity: PrivacySeverity
    category: str
    description: str
    recommendation: str
    evidence: Dict = field(default_factory=dict)
    regulation: str = ""  # GDPR, CCPA, PIPL等


class InfoPlistPrivacyAuditor:
    """Info.plist隐私审计器"""
    
    # 所有iOS权限键
    PERMISSION_KEYS = {
        'NSLocationWhenInUseUsageDescription': {
            'service': 'Location (When In Use)',
            'sensitivity': 'HIGH',
            'data_type': 'location',
        },
        'NSLocationAlwaysAndWhenInUseUsageDescription': {
            'service': 'Location (Always)',
            'sensitivity': 'CRITICAL',
            'data_type': 'location',
        },
        'NSCameraUsageDescription': {
            'service': 'Camera',
            'sensitivity': 'HIGH',
            'data_type': 'media',
        },
        'NSMicrophoneUsageDescription': {
            'service': 'Microphone',
            'sensitivity': 'CRITICAL',
            'data_type': 'media',
        },
        'NSContactsUsageDescription': {
            'service': 'Contacts',
            'sensitivity': 'CRITICAL',
            'data_type': 'personal',
        },
        'NSCalendarsUsageDescription': {
            'service': 'Calendars',
            'sensitivity': 'HIGH',
            'data_type': 'personal',
        },
        'NSPhotoLibraryUsageDescription': {
            'service': 'Photo Library',
            'sensitivity': 'HIGH',
            'data_type': 'media',
        },
        'NSHealthShareUsageDescription': {
            'service': 'Health (Read)',
            'sensitivity': 'CRITICAL',
            'data_type': 'health',
        },
        'NSUserTrackingUsageDescription': {
            'service': 'App Tracking',
            'sensitivity': 'HIGH',
            'data_type': 'tracking',
        },
        'NSBluetoothAlwaysUsageDescription': {
            'service': 'Bluetooth',
            'sensitivity': 'MEDIUM',
            'data_type': 'device',
        },
        'NSMotionUsageDescription': {
            'service': 'Motion',
            'sensitivity': 'MEDIUM',
            'data_type': 'sensor',
        },
    }
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.findings: List[PrivacyFinding] = []
    
    def audit(self) -> List[PrivacyFinding]:
        """执行Info.plist隐私审计"""
        logger.info(f"Auditing Info.plist privacy in: {self.project_path}")
        
        # 查找所有Info.plist文件
        plist_files = list(self.project_path.rglob('Info.plist'))
        plist_files = [f for f in plist_files if 'Pods' not in str(f)
                       and 'DerivedData' not in str(f)]
        
        for plist_file in plist_files:
            self._audit_plist(plist_file)
        
        return self.findings
    
    def _audit_plist(self, plist_path: Path):
        """审计单个plist文件"""
        try:
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
        except Exception as e:
            logger.error(f"Failed to parse {plist_path}: {e}")
            return
        
        logger.info(f"Auditing: {plist_path}")
        
        # 检查权限声明
        requested_perms = []
        critical_perms = []
        
        for key, info in self.PERMISSION_KEYS.items():
            if key in plist:
                desc = plist[key]
                requested_perms.append({
                    'key': key,
                    'service': info['service'],
                    'sensitivity': info['sensitivity'],
                    'description': desc,
                })
                
                if info['sensitivity'] == 'CRITICAL':
                    critical_perms.append(info['service'])
                
                # 检查描述质量
                if len(desc) < 10:
                    self.findings.append(PrivacyFinding(
                        finding_id=f"PLIST-DESC-{key[:8]}",
                        title=f"Vague permission description: {info['service']}",
                        severity=PrivacySeverity.MEDIUM,
                        category="Permission Description",
                        description=f"Description too short ({len(desc)} chars): '{desc}'",
                        recommendation="Provide clear, specific explanation of why "
                                     "this permission is needed",
                        evidence={'description': desc, 'key': key}
                    ))
        
        # 检查后台模式
        bg_modes = plist.get('UIBackgroundModes', [])
        if bg_modes:
            high_risk_modes = {'location', 'audio', 'bluetooth-central',
                             'bluetooth-peripheral'}
            risky_modes = set(bg_modes) & high_risk_modes
            
            if risky_modes:
                self.findings.append(PrivacyFinding(
                    finding_id="PLIST-BG-001",
                    title="High-risk background modes enabled",
                    severity=PrivacySeverity.HIGH,
                    category="Background Modes",
                    description=f"Background modes: {', '.join(risky_modes)}",
                    recommendation="Ensure background modes are necessary for "
                                 "core app functionality",
                    evidence={'background_modes': bg_modes,
                              'risky_modes': list(risky_modes)}
                ))
        
        # 检查ATS配置
        ats = plist.get('NSAppTransportSecurity', {})
        if ats.get('NSAllowsArbitraryLoads'):
            self.findings.append(PrivacyFinding(
                finding_id="PLIST-ATS-001",
                title="ATS disabled - allows HTTP connections",
                severity=PrivacySeverity.HIGH,
                category="Network Security",
                description="NSAllowsArbitraryLoads is YES, allowing "
                           "unencrypted HTTP connections",
                recommendation="Enable ATS and only allow HTTPS connections",
                evidence={'ats_config': dict(ats)}
            ))
        
        # 总结
        logger.info(f"  Permissions requested: {len(requested_perms)}")
        logger.info(f"  Critical permissions: {len(critical_perms)}")
        if critical_perms:
            logger.info(f"  Critical list: {', '.join(critical_perms)}")


class SDKPrivacyAuditor:
    """第三方SDK隐私审计器"""
    
    # 已知SDK的数据收集行为
    KNOWN_SDK_BEHAVIORS = {
        'GoogleAnalytics': {
            'data_collected': ['device_info', 'app_usage', 'crash_data'],
            'network_domains': ['google-analytics.com', 'analytics.google.com'],
            'privacy_risk': 'MEDIUM',
        },
        'FacebookSDK': {
            'data_collected': ['device_info', 'app_usage', 'ad_data',
                             'contacts', 'location'],
            'network_domains': ['facebook.com', 'fbcdn.net',
                              'graph.facebook.com'],
            'privacy_risk': 'HIGH',
        },
        'AppsFlyer': {
            'data_collected': ['device_info', 'app_usage', 'attribution',
                             'location', 'idfa'],
            'network_domains': ['appsflyer.com'],
            'privacy_risk': 'HIGH',
        },
        'Firebase': {
            'data_collected': ['device_info', 'app_usage', 'crash_data',
                             'analytics', 'push_token'],
            'network_domains': ['firebase.google.com', 'firebaseio.com',
                              'googleapis.com'],
            'privacy_risk': 'MEDIUM',
        },
        'Adjust': {
            'data_collected': ['device_info', 'attribution', 'idfa',
                             'app_usage'],
            'network_domains': ['adjust.com'],
            'privacy_risk': 'HIGH',
        },
        'Branch': {
            'data_collected': ['device_info', 'attribution', 'deep_link',
                             'app_usage'],
            'network_domains': ['branch.io', 'bnc.lt'],
            'privacy_risk': 'MEDIUM',
        },
    }
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.findings: List[PrivacyFinding] = []
    
    def audit(self) -> List[PrivacyFinding]:
        """审计第三方SDK"""
        logger.info(f"Auditing SDK privacy in: {self.project_path}")
        
        # 检查CocoaPods
        podfile_lock = self.project_path / 'Podfile.lock'
        if podfile_lock.exists():
            self._audit_cocoapods(podfile_lock)
        
        # 检查Swift Package Manager
        package_resolved = list(self.project_path.rglob('Package.resolved'))
        for resolved in package_resolved:
            self._audit_spm(resolved)
        
        # 检查手动集成的framework
        for fw in self.project_path.rglob('*.framework'):
            self._audit_framework(fw)
        
        return self.findings
    
    def _audit_cocoapods(self, podfile_lock: Path):
        """审计CocoaPods依赖"""
        try:
            with open(podfile_lock, 'r') as f:
                content = f.read()
            
            for sdk_name, behavior in self.KNOWN_SDK_BEHAVIORS.items():
                if sdk_name.lower() in content.lower():
                    risk = behavior['privacy_risk']
                    severity = PrivacySeverity.HIGH if risk == 'HIGH' \
                        else PrivacySeverity.MEDIUM
                    
                    self.findings.append(PrivacyFinding(
                        finding_id=f"SDK-{sdk_name[:8]}",
                        title=f"Third-party SDK: {sdk_name}",
                        severity=severity,
                        category="Third-Party SDK",
                        description=f"SDK collects: {', '.join(behavior['data_collected'])}",
                        recommendation="Review SDK privacy policy. Consider "
                                     "privacy-preserving alternatives.",
                        evidence={
                            'sdk': sdk_name,
                            'data_collected': behavior['data_collected'],
                            'domains': behavior['network_domains'],
                        }
                    ))
        except Exception as e:
            logger.error(f"Error reading Podfile.lock: {e}")
    
    def _audit_spm(self, resolved_path: Path):
        """审计Swift Package Manager依赖"""
        try:
            with open(resolved_path, 'r') as f:
                content = f.read()
            
            for sdk_name, behavior in self.KNOWN_SDK_BEHAVIORS.items():
                if sdk_name.lower() in content.lower():
                    self.findings.append(PrivacyFinding(
                        finding_id=f"SPM-{sdk_name[:8]}",
                        title=f"SPM Package: {sdk_name}",
                        severity=PrivacySeverity.MEDIUM,
                        category="Third-Party Package",
                        description=f"Package collects: {', '.join(behavior['data_collected'])}",
                        recommendation="Review package privacy practices",
                        evidence={'sdk': sdk_name}
                    ))
        except Exception as e:
            logger.error(f"Error reading Package.resolved: {e}")
    
    def _audit_framework(self, fw_path: Path):
        """审计手动集成的framework"""
        fw_name = fw_path.stem
        logger.info(f"Found framework: {fw_name}")
        
        for sdk_name, behavior in self.KNOWN_SDK_BEHAVIORS.items():
            if sdk_name.lower() in fw_name.lower():
                self.findings.append(PrivacyFinding(
                    finding_id=f"FW-{fw_name[:8]}",
                    title=f"Manual framework: {fw_name}",
                    severity=PrivacySeverity.MEDIUM,
                    category="Manual Framework",
                    description=f"Framework collects: {', '.join(behavior['data_collected'])}",
                    recommendation="Review framework privacy policy",
                    evidence={'framework': fw_name, 'path': str(fw_path)}
                ))


class NetworkPrivacyAuditor:
    """网络隐私审计器"""
    
    # 已知的数据收集域名
    TRACKING_DOMAINS = {
        'google-analytics.com': 'Analytics',
        'facebook.com': 'Social/Advertising',
        'appsflyer.com': 'Attribution',
        'adjust.com': 'Attribution',
        'branch.io': 'Deep Linking/Attribution',
        'mixpanel.com': 'Analytics',
        'amplitude.com': 'Analytics',
        'flurry.com': 'Analytics',
        'crashlytics.com': 'Crash Reporting',
        'bugsnag.com': 'Crash Reporting',
        'onesignal.com': 'Push Notifications',
        'firebase.google.com': 'Backend/Analytics',
    }
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.findings: List[PrivacyFinding] = []
    
    def audit_source_code(self) -> List[PrivacyFinding]:
        """审计源代码中的网络请求"""
        logger.info(f"Auditing network privacy in source code")
        
        source_extensions = {'.m', '.mm', '.swift', '.c'}
        url_patterns = [
            r'https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/._-]*',
            r'URL\s*string:\s*@"([^"]+)"',
            r'URL\(string:\s*"([^"]+)"\)',
        ]
        
        found_domains: Dict[str, List[str]] = defaultdict(list)
        
        for ext in source_extensions:
            for source_file in self.project_path.rglob(f'*{ext}'):
                if any(skip in str(source_file) for skip in
                       ['Pods', 'DerivedData', '.git', 'build']):
                    continue
                
                try:
                    with open(source_file, 'r', encoding='utf-8',
                             errors='ignore') as f:
                        content = f.read()
                    
                    for pattern in url_patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            url = match.group(0) if match.lastindex is None \
                                else match.group(1)
                            
                            # 提取域名
                            domain_match = re.search(
                                r'https?://([a-zA-Z0-9._-]+)', url)
                            if domain_match:
                                domain = domain_match.group(1)
                                found_domains[domain].append(
                                    f"{source_file.name}")
                except Exception:
                    continue
        
        # 分析发现的域名
        for domain, files in found_domains.items():
            if domain in self.TRACKING_DOMAINS:
                category = self.TRACKING_DOMAINS[domain]
                self.findings.append(PrivacyFinding(
                    finding_id=f"NET-{domain[:12]}",
                    title=f"Tracking domain detected: {domain}",
                    severity=PrivacySeverity.MEDIUM,
                    category="Network Privacy",
                    description=f"Domain categorized as: {category}",
                    recommendation="Verify data sent to this domain is minimal "
                                 "and disclosed in privacy policy",
                    evidence={
                        'domain': domain,
                        'category': category,
                        'files': files[:5],  # 限制文件列表长度
                    }
                ))
        
        return self.findings


class PrivacyAuditReport:
    """隐私审计报告生成器"""
    
    def __init__(self):
        self.all_findings: List[PrivacyFinding] = []
    
    def add_findings(self, findings: List[PrivacyFinding]):
        self.all_findings.extend(findings)
    
    def generate_report(self) -> str:
        report = []
        report.append("=" * 70)
        report.append("  iOS App Privacy Compliance Audit Report")
        report.append(f"  Generated: {__import__('datetime').datetime.now()}")
        report.append("=" * 70)
        
        # 统计
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        
        for f in self.all_findings:
            severity_counts[f.severity.value] += 1
            category_counts[f.category] += 1
        
        report.append(f"\n  Total Findings: {len(self.all_findings)}")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                report.append(f"  {sev}: {count}")
        
        report.append(f"\n  Findings by Category:")
        for cat, count in sorted(category_counts.items()):
            report.append(f"    {cat}: {count}")
        
        report.append("\n" + "-" * 70)
        
        # 详细发现
        sorted_findings = sorted(self.all_findings,
            key=lambda f: list(PrivacySeverity).index(f.severity))
        
        for i, finding in enumerate(sorted_findings, 1):
            report.append(f"\n[{i}] [{finding.severity.value}] {finding.title}")
            report.append(f"    Category: {finding.category}")
            report.append(f"    Description: {finding.description}")
            report.append(f"    Recommendation: {finding.recommendation}")
            if finding.regulation:
                report.append(f"    Regulation: {finding.regulation}")
        
        report.append("\n" + "=" * 70)
        report.append("  End of Privacy Audit Report")
        report.append("=" * 70)
        
        return '\n'.join(report)


if __name__ == '__main__':
    import sys
    
    project_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    
    report = PrivacyAuditReport()
    
    # Info.plist审计
    plist_auditor = InfoPlistPrivacyAuditor(project_path)
    report.add_findings(plist_auditor.audit())
    
    # SDK审计
    sdk_auditor = SDKPrivacyAuditor(project_path)
    report.add_findings(sdk_auditor.audit())
    
    # 网络审计
    net_auditor = NetworkPrivacyAuditor(project_path)
    report.add_findings(net_auditor.audit_source_code())
    
    # 生成报告
    print(report.generate_report())
```

---

## 15. 总结与展望

### 15.1 关键发现总结

| 权限类别 | 风险等级 | 常见滥用方式 | 防御建议 |
|---------|---------|------------|---------|
| 位置 | 严重 | 后台持续追踪、精度过高 | 使用WhenInUse、降低精度 |
| 相机 | 高 | 隐蔽拍摄、元数据泄露 | 清除EXIF、限制分辨率 |
| 麦克风 | 严重 | 隐蔽录音、语音指纹 | 监控音频会话、限制后台 |
| 通讯录 | 严重 | 社交图谱构建、数据上传 | 字段级访问、本地处理 |
| 相册 | 高 | 全库访问、元数据泄露 | 使用Limited模式 |
| 追踪 | 高 | 指纹识别、跨应用关联 | ATT拒绝、减少设备信号 |
| 后台 | 中高 | 持续数据收集、隐蔽传输 | 最小化后台模式 |
| 剪贴板 | 中 | 敏感数据嗅探 | 使用安全粘贴板 |
| SDK | 高 | 隐蔽数据收集、追踪 | 审计SDK行为、最小集成 |

### 15.2 防御建议优先级

1. **数据最小化**: 仅请求功能必需的最小权限
2. **透明度**: 向用户清晰说明权限使用目的
3. **本地处理**: 敏感数据尽量在设备本地处理
4. **传输加密**: 所有数据外传使用端到端加密
5. **定期审计**: 自动化权限和隐私合规审计
6. **用户控制**: 提供细粒度的隐私控制选项

### 15.3 未来研究方向

1. **差分隐私应用**: 在数据收集中应用差分隐私保护
2. **联邦学习**: 在不共享原始数据的情况下训练模型
3. **隐私增强技术(PET)**: 安全多方计算、同态加密在iOS上的应用
4. **自动化合规**: AI驱动的隐私合规自动检测和修复
5. **用户隐私仪表板**: 直观的隐私控制和可视化

---

**联系**: telegram：@pengqing666

---

*免责声明：本文仅用于安全研究和教育目的。所有漏洞分析基于公开信息和合理推测，旨在帮助开发者理解和防范隐私泄露威胁。请勿将文中技术用于非法目的。*

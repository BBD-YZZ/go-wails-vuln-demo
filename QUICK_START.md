# 快速入门：添加新的漏洞扫描器

## 整体架构

整个系统的设计理念是：**界面和通用代码完全复用，只需修改漏洞扫描的具体实现部分**。

## 需要修改的代码位置

### 1. 创建新的扫描器实现 (`pkg/scanner/[your_scanner].go`)

**这是唯一需要编写新代码的地方**

```go
package scanner

import (
    "fmt"
    "net/http"
    "strings"
    "time"
)

// YourScanner 你的漏洞扫描器
type YourScanner struct{}

// NewYourScanner 创建你的漏洞扫描器
func NewYourScanner() *YourScanner {
    return &YourScanner{}
}

// GetScannerName 返回扫描器名称 - 【需要修改】
func (y *YourScanner) GetScannerName() string {
    return "your_scanner"  // 【修改为你的扫描器名称】
}

// GetSupportedVulnerabilities 返回支持的漏洞类型 - 【需要修改】
func (y *YourScanner) GetSupportedVulnerabilities() []string {
    return []string{
        "your_vuln_type",  // 【修改为你的漏洞类型】
    }
}

// Scan 执行漏洞扫描 - 【主要修改区域】
func (y *YourScanner) Scan(target string, options ScanOptions) ([]Vulnerability, error) {
    var vulnerabilities []Vulnerability

    // 创建HTTP客户端 - 【复用，无需修改】
    clientConfig := HTTPClientConfig{
        Timeout:     time.Duration(options.Timeout) * time.Second,
        Proxy:       options.Proxy,
        SkipSSL:     options.SkipSSL,
        Headers:     options.Headers,    // 【后端自定义的请求头】
        Cookies:     options.Cookies,    // 【后端自定义的Cookie】
        MaxRedirects: 10,
    }
    if options.RandomAgent {
        clientConfig.UserAgent = getRandomUserAgent()
    }

    client, err := NewHTTPClient(clientConfig)
    if err != nil {
        return nil, fmt.Errorf("创建HTTP客户端失败: %v", err)
    }

    // 【在这里实现你的扫描逻辑】
    // 示例：扫描特定漏洞
    endpoints := []string{
        // 【添加你的检测端点】
    }

    for _, endpoint := range endpoints {
        url := strings.TrimRight(target, "/") + endpoint
        
        resp, err := client.Get(url)
        if err != nil {
            continue // 跳过无法访问的端点
        }
        defer resp.Body.Close()

        // 【在这里判断漏洞是否存在】
        if resp.StatusCode == 200 {
            vulnerability := Vulnerability{
                ID:                len(vulnerabilities) + 1,
                VulnerabilityType: "你的漏洞类型",  // 【修改为你的漏洞类型描述】
                Severity:          "高危",         // 【根据实际情况修改】
                Target:            target,
                URL:               url,
                Payload:           "GET " + endpoint,  // 【根据实际情况修改】
                Description:       "你的漏洞描述",      // 【修改为你的漏洞描述】
                Proof:             "验证证据",         // 【修改为你的验证证据】
                Recommendation:    "修复建议",         // 【修改为你的修复建议】
                Timestamp:         time.Now(),
            }
            vulnerabilities = append(vulnerabilities, vulnerability)
        }
    }

    return vulnerabilities, nil
}
```

## 参数从前端传递到后端的机制

### 1. 代理配置传递
- 前端通过 `ProxyConfig` 结构体传递代理设置
- 包括代理类型、地址、端口、认证信息以及启用状态
- 后端根据 `Enabled` 字段决定是否启用代理

### 2. 扫描参数传递
- `Targets`: 目标地址列表
- `ScanType`: 扫描类型
- `Threads`: 并发线程数
- `Timeout`: 超时时间
- `Proxy`: 代理配置

### 3. 后端自定义配置
- `Headers`: 后端预定义的请求头，如 "X-Scanner": "VulnScanner"
- `Cookies`: 后端预定义的Cookie（通常为空）

### 4. 在扫描管理器中注册 (`pkg/scanner/scanner_manager.go`)

**这是唯一需要手动添加注册代码的地方**

```go
func NewScannerManager() *ScannerManager {
    manager := &ScannerManager{
        scanners: make(map[string]VulnerabilityScanner),
    }

    // 注册默认扫描器
    manager.RegisterScanner("spring_scanner", NewSpringScanner())
    manager.RegisterScanner("log4j_scanner", NewLog4jScanner())
    // 【在这里添加你的扫描器注册】
    manager.RegisterScanner("your_scanner", NewYourScanner())  // 【添加这一行】

    return manager
}
```

### 5. 更新后端支持 (`app.go`)

**这部分也是需要修改的，但非常简单**

```go
// 在StartScan方法中添加
switch options.ScanType {
case "spring_vulns":
    scannerName = "spring_scanner"
case "log4j_vulns":
    scannerName = "log4j_scanner"
case "your_vulns":  // 【添加你的漏洞类型case】
    scannerName = "your_scanner"  // 【关联到你的扫描器】
default:
    scannerName = "spring_scanner"
}

// 在GetSupportedVulnerabilityTypes方法中添加 - 【添加你的漏洞类型】
func (a *App) GetSupportedVulnerabilityTypes() []string {
    return []string{"spring_vulns", "nacos_vulns", "log4j_vulns", "your_vulns", ...}  // 【添加your_vulns】
}

// 在GetVulnerabilityTypeLabels方法中添加 - 【添加你的漏洞类型标签】
func (a *App) GetVulnerabilityTypeLabels() map[string]string {
    labels := make(map[string]string)
    labels["spring_vulns"] = "Spring漏洞"
    labels["nacos_vulns"] = "Nacos漏洞"
    labels["log4j_vulns"] = "Log4j漏洞"
    labels["your_vulns"] = "你的漏洞类别"  // 【添加这一行】
    // ... 其他标签
    return labels
}
```

## 按类别组织漏洞扫描器

如果您想按类别组织（如Spring类漏洞、其他类漏洞），可以在同一个扫描器中处理多种相关漏洞：

### 示例：Spring类漏洞扫描器 (`pkg/scanner/spring_family_scanner.go`)

```go
package scanner

import (
    "fmt"
    "net/http"
    "strings"
    "time"
)

// SpringFamilyScanner Spring家族漏洞扫描器
type SpringFamilyScanner struct{}

func NewSpringFamilyScanner() *SpringFamilyScanner {
    return &SpringFamilyScanner{}
}

func (s *SpringFamilyScanner) GetScannerName() string {
    return "spring_family_scanner"
}

func (s *SpringFamilyScanner) GetSupportedVulnerabilities() []string {
    return []string{
        "spring_boot_actuator_unauth",
        "spring_cloud_config_path_traversal",
        "spring_data_commons_rce",
        "spring_security_oauth_rce",
    }
}

func (s *SpringFamilyScanner) Scan(target string, options ScanOptions) ([]Vulnerability, error) {
    var vulnerabilities []Vulnerability

    // 创建HTTP客户端
    clientConfig := HTTPClientConfig{
        Timeout:     time.Duration(options.Timeout) * time.Second,
        Proxy:       options.Proxy,
        SkipSSL:     options.SkipSSL,
        Headers:     options.Headers,    // 【后端自定义的请求头】
        Cookies:     options.Cookies,    // 【后端自定义的Cookie】
        MaxRedirects: 10,
    }
    if options.RandomAgent {
        clientConfig.UserAgent = getRandomUserAgent()
    }

    client, err := NewHTTPClient(clientConfig)
    if err != nil {
        return nil, fmt.Errorf("创建HTTP客户端失败: %v", err)
    }

    // 根据不同的Spring漏洞类型进行扫描
    // 扫描Spring Boot Actuator未授权访问
    actuatorVulns := s.scanSpringBootActuator(client, target)
    vulnerabilities = append(vulnerabilities, actuatorVulns...)

    // 扫描Spring Cloud Config Server路径遍历
    configVulns := s.scanSpringCloudConfig(client, target)
    vulnerabilities = append(vulnerabilities, configVulns...)

    // 添加其他Spring相关漏洞扫描...

    return vulnerabilities, nil
}

// 扫描Spring Boot Actuator未授权访问
func (s *SpringFamilyScanner) scanSpringBootActuator(client *HTTPClient, target string) []Vulnerability {
    var vulnerabilities []Vulnerability
    // 具体实现...
    return vulnerabilities
}

// 扫描Spring Cloud Config Server路径遍历
func (s *SpringFamilyScanner) scanSpringCloudConfig(client *HTTPClient, target string) []Vulnerability {
    var vulnerabilities []Vulnerability
    // 具体实现...
    return vulnerabilities
}
```

## 前端功能调用说明

### 1. TestConnection (测试连接)
- **调用位置**: 前端通过Wails绑定调用 `TestConnection` 方法
- **功能**: 测试目标连接是否可达，支持代理配置
- **参数**: 目标地址和代理配置
- **返回**: 连接状态和详细信息

### 2. GetScanProgress (获取扫描进度)
- **调用位置**: 前端通过Wails绑定定期调用 `GetScanProgress` 方法
- **功能**: 获取当前扫描进度百分比
- **返回**: 当前进度值(0-100)

### 3. StopScan (停止扫描)
- **调用位置**: 前端通过Wails绑定调用 `StopScan` 方法
- **功能**: 停止正在进行的扫描任务
- **返回**: 操作结果

### 4. 前端体现
- **进度条**: 前端定时调用 `GetScanProgress` 更新进度条
- **状态显示**: 扫描状态和停止按钮根据扫描状态动态更新
- **日志输出**: 扫描日志实时显示在界面上
- **连接测试**: 在代理设置界面提供测试连接按钮

## 总结

**真正需要修改的代码位置：**

1. `pkg/scanner/[your_scanner].go` - 【**主要修改区域**】编写漏洞扫描逻辑
2. `pkg/scanner/scanner_manager.go` - 【**次要修改**】注册扫描器
3. `app.go` - 【**配置修改**】添加漏洞类型支持

**完全不需要修改的代码：**
- 前端界面代码（自动适配）
- HTTP客户端代码（复用）
- 扫描管理器核心逻辑（复用）
- 进度、日志、状态管理（复用）
- 代理设置功能（复用）

这样，您只需专注于漏洞扫描的具体实现，其他所有代码都可以复用。
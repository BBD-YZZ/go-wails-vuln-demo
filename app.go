package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"vuln-scanner/client"
	"vuln-scanner/common"
	"vuln-scanner/config"
	"vuln-scanner/logger"
	"vuln-scanner/scanner"
	"vuln-scanner/vulns"

	"github.com/xuri/excelize/v2"
)

// ProxyConfig 代理配置结构
type ProxyConfig struct {
	Type     string            `json:"type"`     // 代理类型: http, socks5
	Address  string            `json:"address"`  // 代理地址
	Port     string            `json:"port"`     // 代理端口
	Username string            `json:"username"` // 用户名（可选）
	Password string            `json:"password"` // 密码（可选）
	Enabled  bool              `json:"enabled"`  // 是否启用代理
	Headers  map[string]string `json:"headers"`  // 自定义请求头
	Cookies  map[string]string `json:"cookies"`  // 自定义Cookie
}

// ScanOptions 扫描选项结构
type ScanOptions struct {
	Targets       []string    `json:"targets"`
	ScanType      string      `json:"scanType"`
	Threads       int         `json:"threads"`
	Timeout       int         `json:"timeout"`
	Proxy         ProxyConfig `json:"proxy"`
	AllowRedirect bool        `json:"allowRedirect"` // 是否允许重定向
}

// Vulnerability 漏洞信息结构
type Vulnerability struct {
	ID                int               `json:"id"`
	VulnerabilityType string            `json:"vulnerabilityType"`
	Severity          string            `json:"severity"`
	Target            string            `json:"target"`
	URL               string            `json:"url"`
	Payload           string            `json:"payload"`
	Description       string            `json:"description"`
	Proof             string            `json:"proof"`
	Recommendation    string            `json:"recommendation"`
	ResponseHeaders   map[string]string `json:"responseHeaders"`
	ResponseContent   string            `json:"responseContent"`
	SupportedFeatures []string          `json:"supportedFeatures"` // 支持的功能: ["command", "shell", "memory"]
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Context   map[string]interface{} `json:"context,omitempty"` // 日志上下文（可选）
}

// App struct
type App struct {
	ctx             context.Context
	proxyConfig     ProxyConfig
	logMutex        sync.Mutex
	logs            []LogEntry
	progressMutex   sync.Mutex
	currentProgress int
	scanMutex       sync.Mutex
	isScanning      bool
	// 存储扫描过程中的临时结果
	tempResults      []Vulnerability
	tempResultsMutex sync.Mutex
	// 当前扫描的取消函数
	currentScanCancel context.CancelFunc
	// 扫描选项，包含代理设置等
	scanOptions vulns.ScanOptions
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		ctx: context.Background(),
		proxyConfig: ProxyConfig{
			Type:    "http",
			Address: "127.0.0.1",
			Port:    "8080",
			Enabled: false,
		},
		logs:            make([]LogEntry, 0),
		currentProgress: 0,
		isScanning:      false,
		scanOptions: vulns.ScanOptions{
			Timeout:       30,
			Proxy:         "",
			SkipSSL:       true,
			RandomAgent:   true,
			AllowRedirect: true,
			Logger:        nil,
			CeyeDNSLog:    nil,
		},
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// SetProxyConfig 设置代理配置
func (a *App) SetProxyConfig(config ProxyConfig) error {
	a.proxyConfig = config

	// 同时更新scanOptions中的Proxy字段，确保后续的命令执行、反弹shell和内存马注入操作使用最新的代理配置
	if config.Enabled {
		if config.Username != "" && config.Password != "" {
			// 对用户名和密码进行URL编码，确保特殊字符不会导致解析失败
			encodedUsername := url.QueryEscape(config.Username)
			encodedPassword := url.QueryEscape(config.Password)
			a.scanOptions.Proxy = fmt.Sprintf("%s://%s:%s@%s:%s", config.Type, encodedUsername, encodedPassword, config.Address, config.Port)
		} else {
			a.scanOptions.Proxy = fmt.Sprintf("%s://%s:%s", config.Type, config.Address, config.Port)
		}
	} else {
		a.scanOptions.Proxy = ""
	}

	fmt.Printf("代理配置已更新: %+v\n", config)
	fmt.Printf("scanOptions.Proxy已更新: %s\n", a.scanOptions.Proxy)
	return nil
}

// GetProxyConfig 获取代理配置
func (a *App) GetProxyConfig() ProxyConfig {
	return a.proxyConfig
}

// isTargetAccessible 检查目标是否可访问
func (a *App) isTargetAccessible(target, proxy string, skipSSL bool) bool {
	// 创建HTTP客户端配置
	clientConfig := client.HTTPClientConfig{
		Timeout:       5 * time.Second, // 快速检查，设置5秒超时
		Proxy:         proxy,
		SkipSSL:       skipSSL,
		AllowRedirect: true, // 默认允许重定向
		UserAgent:     client.GetRandomUserAgent(),
		Headers:       map[string]string{},
		Cookies:       map[string]string{},
	}

	// 创建HTTP客户端
	httpClient, err := client.NewHTTPClient(clientConfig)
	if err != nil {
		return false
	}

	// 构造简单的HEAD请求（比GET请求更轻量）
	req, err := http.NewRequest("HEAD", target, nil)
	if err != nil {
		return false
	}

	// 发送请求
	resp, err := httpClient.GetHTTPClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 只要能收到响应（不管状态码是什么），就认为目标可访问
	return true
}

// isValidTargetFormat 检查目标格式是否正确
func (a *App) isValidTargetFormat(target string) bool {
	// 检查目标是否为空
	if target == "" {
		return false
	}

	// 检查目标是否包含http://或https://前缀
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return false
	}

	// 解析URL，检查格式是否正确
	parsedURL, err := url.Parse(target)
	if err != nil {
		return false
	}

	// 检查主机部分是否为空
	if parsedURL.Host == "" {
		return false
	}

	// 检查主机部分是否有效：
	// 1. 对于域名：至少包含一个点，且点前后都有字符
	// 2. 对于IP地址：符合IPv4或IPv6格式
	hasDot := strings.Contains(parsedURL.Host, ".")

	// 如果包含点，尝试作为域名处理
	if hasDot {
		// 检查点前后是否都有字符
		parts := strings.Split(parsedURL.Host, ".")
		if len(parts) < 2 {
			return false
		}
		for _, part := range parts {
			if part == "" {
				return false
			}
		}
	} else {
		// 尝试作为IPv4地址处理
		parts := strings.Split(parsedURL.Host, ".")
		if len(parts) != 4 {
			// 不是有效的IPv4地址
			return false
		}
		for _, part := range parts {
			// 检查每个部分是否是0-255之间的数字
			num, err := strconv.Atoi(part)
			if err != nil || num < 0 || num > 255 {
				return false
			}
		}
	}

	return true
}

// StartScan 开始漏洞扫描
func (a *App) StartScan(options ScanOptions) ([]Vulnerability, error) {
	// 验证目标地址
	if len(options.Targets) == 0 || (len(options.Targets) == 1 && options.Targets[0] == "") {
		a.AddLog("ERROR", "错误: 请输入至少一个目标地址")
		return nil, fmt.Errorf("请输入至少一个目标地址")
	}

	a.scanMutex.Lock()
	a.isScanning = true
	a.scanMutex.Unlock()

	// 取消之前的扫描上下文（如果存在）并创建新的
	if a.currentScanCancel != nil {
		a.currentScanCancel()
	}
	// 创建新的扫描上下文
	scanCtx, cancel := context.WithCancel(a.ctx)
	a.currentScanCancel = cancel

	// 清空临时结果
	a.tempResultsMutex.Lock()
	a.tempResults = []Vulnerability{}
	a.tempResultsMutex.Unlock()

	a.AddLog("INFO", fmt.Sprintf("开始扫描，目标: %v，代理启用: %t", options.Targets, options.Proxy.Enabled))

	// 如果启用了代理，记录代理信息
	if options.Proxy.Enabled {
		a.AddLog("INFO", fmt.Sprintf("使用代理: %s://%s:%s", options.Proxy.Type, options.Proxy.Address, options.Proxy.Port))
	}

	// 构建代理字符串，根据前端配置决定是否启用代理
	var proxyString string
	if options.Proxy.Enabled {
		if options.Proxy.Username != "" && options.Proxy.Password != "" {
			// 对用户名和密码进行URL编码，确保特殊字符不会导致解析失败
			encodedUsername := url.QueryEscape(options.Proxy.Username)
			encodedPassword := url.QueryEscape(options.Proxy.Password)
			proxyString = fmt.Sprintf("%s://%s:%s@%s:%s", options.Proxy.Type, encodedUsername, encodedPassword, options.Proxy.Address, options.Proxy.Port)
		} else {
			proxyString = fmt.Sprintf("%s://%s:%s", options.Proxy.Type, options.Proxy.Address, options.Proxy.Port)
		}
	} else {
		proxyString = "" // 不启用代理
	}

	// 创建扫描管理器
	sm := scanner.NewScannerManager()

	// 创建日志适配器，将scanner包的日志转换为app层的日志
	logAdapter := logger.NewLogAdapter(func(level, message string, context map[string]interface{}) {
		// 首先构建基础日志消息
		logMsg := message
		if len(context) > 0 {
			// 添加关键上下文信息到消息中
			if target, ok := context["target"].(string); ok && target != "" {
				logMsg = fmt.Sprintf("[%s] %s", target, logMsg)
			}
			if scanner, ok := context["scanner"].(string); ok && scanner != "" {
				logMsg = fmt.Sprintf("[%s] %s", scanner, logMsg)
			}
			if vulnType, ok := context["vulnerability_type"].(string); ok && vulnType != "" {
				logMsg = fmt.Sprintf("[%s] %s", vulnType, logMsg)
			}
		}

		// 收集详细信息
		var details []string

		// 添加HTTP请求/响应的详细信息到details
		if reqHeaders, ok := context["request_headers"].(map[string]string); ok {
			// 输出请求头信息
			reqHeadersMsg := "    Request Headers:"
			for k, v := range reqHeaders {
				reqHeadersMsg += fmt.Sprintf("\n        %s: %s", k, v)
			}
			// 将多行拆分为多个详情项
			for i, line := range strings.Split(reqHeadersMsg, "\n") {
				if i == 0 {
					details = append(details, line)
				} else {
					details = append(details, line)
				}
			}
		}
		if reqBody, ok := context["request_body"].(string); ok && reqBody != "" {
			// 过滤不可打印字符
			filteredReqBody := a.filterPrintableCharacters(reqBody)
			details = append(details, fmt.Sprintf("    Request Body: %s", filteredReqBody))
		}
		if respHeaders, ok := context["response_headers"].(map[string]string); ok {
			// 输出响应头信息
			respHeadersMsg := "    Response Headers:"
			for k, v := range respHeaders {
				respHeadersMsg += fmt.Sprintf("\n        %s: %s", k, v)
			}
			// 将多行拆分为多个详情项
			for i, line := range strings.Split(respHeadersMsg, "\n") {
				if i == 0 {
					details = append(details, line)
				} else {
					details = append(details, line)
				}
			}
		}
		if respBody, ok := context["response_body"].(string); ok && respBody != "" {
			// 过滤不可打印字符
			filteredRespBody := a.filterPrintableCharacters(respBody)
			details = append(details, fmt.Sprintf("    Response Body: %s", filteredRespBody))
		}
		// 添加扫描步骤的详细信息
		if step, ok := context["step"].(string); ok && step != "" {
			details = append(details, fmt.Sprintf("    Step: %s", step))
		}
		// 处理LogScanStep的details信息
		for k, v := range context {
			// 排除已处理的键和其他内部键
			if k != "target" && k != "scanner" && k != "vulnerability_type" && k != "step" &&
				k != "request_method" && k != "request_url" && k != "request_headers" && k != "request_body" &&
				k != "response_status" && k != "response_headers" && k != "response_body" && k != "response_duration" {
				// 如果值是字符串，过滤不可打印字符
				if strVal, ok := v.(string); ok {
					filteredStrVal := a.filterPrintableCharacters(strVal)
					details = append(details, fmt.Sprintf("    %s: %v", k, filteredStrVal))
				} else {
					details = append(details, fmt.Sprintf("    %s: %v", k, v))
				}
			}
		}

		// 使用新方法添加日志（只在主行显示日志级别和时间戳）
		if len(details) > 0 {
			a.AddLogWithDetails(level, logMsg, details)
		} else {
			a.AddLog(level, logMsg)
		}
	})

	dnslog, err := config.LoadDNSLogConfigFromFile()
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("加载DNS Log配置时出错: %v", err))
		return nil, err
	}

	// if err != nil {
	// 	fmt.Printf("加载DNS Log配置失败: %v\n", err)
	// } else {
	// 	fmt.Printf("DNS Log配置加载成功: %s\n", dnslog.Domain)
	// }

	// 创建扫描选项
	scanOpts := vulns.ScanOptions{
		Targets:       options.Targets,
		Threads:       options.Threads,
		Timeout:       options.Timeout,
		Proxy:         proxyString,
		MaxRetries:    3,
		Delay:         0,                   // 可以根据需要设置请求间隔
		RandomAgent:   true,                // 使用随机User-Agent
		SkipSSL:       true,                // 跳过SSL验证
		AllowRedirect: true,                // 默认允许重定向
		Headers:       map[string]string{}, // 后端自定义请求头
		Cookies:       map[string]string{}, // 后端自定义Cookie
		Logger:        logAdapter,          // 设置日志适配器
		CeyeDNSLog:    dnslog,              // 设置Ceye DNS Log配置
	}

	// 更新App的scanOptions字段，用于后续的命令执行、反弹shell和内存马注入操作
	a.scanOptions = scanOpts

	// 优化：在开始扫描之前检查目标是否可访问，过滤出有效的目标
	validTargets := []string{}
	for _, target := range options.Targets {
		// 检查目标格式
		if !a.isValidTargetFormat(target) {
			a.AddLog("ERROR", fmt.Sprintf("目标格式不正确: %s", target))
			continue // 跳过格式不正确的目标
		}

		// 检查目标可访问性
		a.AddLog("INFO", fmt.Sprintf("检查目标可访问性: %s", target))
		if !a.isTargetAccessible(target, proxyString, scanOpts.SkipSSL) {
			a.AddLog("ERROR", fmt.Sprintf("目标不可访问: %s", target))
			continue // 跳过不可访问的目标
		}

		a.AddLog("INFO", fmt.Sprintf("目标可访问: %s", target))
		validTargets = append(validTargets, target)
	}

	// 如果没有有效的目标，返回错误
	if len(validTargets) == 0 {
		a.AddLog("ERROR", "错误: 没有有效的目标地址")
		// 扫描完成后重置状态
		a.scanMutex.Lock()
		a.isScanning = false
		a.scanMutex.Unlock()
		return nil, fmt.Errorf("没有有效的目标地址")
	}

	// 使用有效的目标列表
	scanOpts.Targets = validTargets

	vulnerabilities := []Vulnerability{}

	var allVulnerabilities []common.Vulnerability

	// 如果选择扫描所有漏洞类型
	if options.ScanType == "all" {
		// 获取所有支持的漏洞类型并逐一扫描
		supportedTypes := a.GetSupportedVulnerabilityTypes()
		totalTypes := len(supportedTypes)
		processedTypes := 0

		for _, vulnType := range supportedTypes {
			// 跳过"all"类型自身
			if vulnType == "all" {
				continue
			}

			// 检查扫描是否被停止
			a.scanMutex.Lock()
			if !a.isScanning {
				a.scanMutex.Unlock()
				a.AddLog("INFO", "扫描已被用户停止")
				break
			}
			a.scanMutex.Unlock()

			var scannerName string
			switch vulnType {
			case "CVE-2022-22963":
				scannerName = "cve_2022_22963_scanner"
			case "CVE-2022-22947":
				scannerName = "cve_2022_22947_scanner"
			case "CVE-2022-22965":
				scannerName = "cve_2022_22965_scanner"
			case "CVE-2025-55182":
				scannerName = "cve_2025_55182_scanner"
			default:
				a.AddLog("INFO", fmt.Sprintf("%s 该漏洞类型暂不支持", vulnType))
				continue // 跳过不支持的漏洞类型
			}

			a.AddLog("INFO", fmt.Sprintf("正在扫描 %s 类型漏洞", vulnType))

			// 为当前漏洞类型创建特定的扫描选项
			typeSpecificScanOpts := scanOpts
			typeSpecificScanOpts.Targets = validTargets // 使用过滤后的有效目标列表

			// 执行批量扫描
			vulns, err := sm.ScanMultipleWithContext(scanCtx, scannerName, validTargets, typeSpecificScanOpts)
			if err != nil {
				a.AddLog("ERROR", fmt.Sprintf("扫描 %s 类型漏洞时出错: %v", vulnType, err))
			} else {
				// 过滤重复的漏洞（基于ID和URL）
				filteredVulns := a.filterDuplicateVulnerabilities(allVulnerabilities, vulns)
				allVulnerabilities = append(allVulnerabilities, filteredVulns...)
				// 更新临时结果
				a.updateTempResults(filteredVulns)
			}

			processedTypes++
			// 更新进度
			progress := int(float64(processedTypes) / float64(totalTypes) * 100)
			a.progressMutex.Lock()
			a.currentProgress = progress
			a.progressMutex.Unlock()
		}
	} else {
		// 扫描特定类型的漏洞
		var scannerName string
		switch options.ScanType {
		case "CVE-2022-22963":
			scannerName = "cve_2022_22963_scanner"
		case "CVE-2022-22947":
			scannerName = "cve_2022_22947_scanner"
		case "CVE-2022-22965":
			scannerName = "cve_2022_22965_scanner"
		case "CVE-2025-55182":
			scannerName = "cve_2025_55182_scanner"
		default:
			a.AddLog("ERROR", fmt.Sprintf("%s 该漏洞类型暂不支持", options.ScanType))
			// 扫描完成后重置状态
			a.scanMutex.Lock()
			a.isScanning = false
			a.scanMutex.Unlock()
			return vulnerabilities, fmt.Errorf("%s 该漏洞类型暂不支持", options.ScanType)
		}

		// 检查扫描是否被停止
		a.scanMutex.Lock()
		if !a.isScanning {
			a.scanMutex.Unlock()
			a.AddLog("INFO", "扫描已被用户停止")
			return vulnerabilities, nil // 直接返回，结束扫描
		}
		a.scanMutex.Unlock()

		// 执行批量扫描
		vulns, err := sm.ScanMultipleWithContext(scanCtx, scannerName, validTargets, scanOpts)
		if err != nil {
			a.AddLog("ERROR", fmt.Sprintf("扫描过程中出错: %v", err))
		} else {
			allVulnerabilities = append(allVulnerabilities, vulns...)
			// 更新临时结果
			a.updateTempResults(vulns)
		}

		// 对于单个漏洞类型，设置为50%（一半进度，另一半留给结果处理）
		a.progressMutex.Lock()
		a.currentProgress = 50
		a.progressMutex.Unlock()
	}

	vulns := allVulnerabilities

	// 创建扫描器管理器
	sm = scanner.NewScannerManager()

	// 转换漏洞格式
	for i, v := range vulns {
		// 根据漏洞类型获取对应的扫描器
		var scannerName string
		switch v.VulnerabilityType {
		case "CVE-2022-22947":
			scannerName = "cve_2022_22947_scanner"
		case "CVE-2022-22963":
			scannerName = "cve_2022_22963_scanner"
		case "CVE-2022-22965":
			scannerName = "cve_2022_22965_scanner"
		case "CVE-2025-55182":
			scannerName = "cve_2025_55182_scanner"
		default:
			scannerName = ""
		}

		// 获取支持的功能
		supportedFeatures := []string{}
		if scannerName != "" {
			scan, err := sm.GetScanner(scannerName)
			if err == nil {
				supportedFeatures = scan.GetSupportedFeatures()
			}
		}

		// 为每个漏洞生成唯一的ID
		uniqueID := i + 1

		convertedVuln := Vulnerability{
			ID:                uniqueID,
			VulnerabilityType: v.VulnerabilityType,
			Severity:          v.Severity,
			Target:            v.Target,
			URL:               v.URL,
			Payload:           v.Payload,
			Description:       v.Description,
			Proof:             v.Proof,
			Recommendation:    v.Recommendation,
			ResponseHeaders:   v.ResponseHeaders,
			ResponseContent:   v.ResponseContent,
			SupportedFeatures: supportedFeatures,
		}
		vulnerabilities = append(vulnerabilities, convertedVuln)
	}

	// 更新进度为100%
	a.progressMutex.Lock()
	a.currentProgress = 100
	a.progressMutex.Unlock()

	a.AddLog("INFO", fmt.Sprintf("扫描完成，共发现 %d 个漏洞", len(vulnerabilities)))

	// 扫描完成后重置进度和状态
	a.scanMutex.Lock()
	a.isScanning = false
	a.scanMutex.Unlock()

	return vulnerabilities, nil
}

// GetSupportedVulnerabilityTypes 获取支持的漏洞类型
// 【扩展点：在这里添加新的漏洞类型字符串】
func (a *App) GetSupportedVulnerabilityTypes() []string {
	return []string{"all", "CVE-2022-22963", "CVE-2022-22947", "CVE-2022-22965", "CVE-2025-55182"}
}

// GetVulnerabilityTypeLabels 获取漏洞类型标签
// 【扩展点：在这里为新的漏洞类型添加中文标签】
func (a *App) GetVulnerabilityTypeLabels() map[string]string {
	labels := make(map[string]string)
	labels["all"] = "全部漏洞"
	labels["CVE-2022-22963"] = "CVE-2022-22963 (SpEL注入)"
	labels["CVE-2022-22947"] = "CVE-2022-22947 (SpEL RCE)"
	labels["CVE-2022-22965"] = "CVE-2022-22965 (spring4shell)"
	labels["CVE-2025-55182"] = "CVE-2025-55182 (Next.js RCE)"
	return labels
}

// TestConnection 测试连接
func (a *App) TestConnection(target string, proxy ProxyConfig) (bool, string) {
	fmt.Printf("测试连接到: %s", target)
	if proxy.Enabled {
		fmt.Printf(" (使用代理: %s://%s:%s)", proxy.Type, proxy.Address, proxy.Port)
	}
	fmt.Println()

	// 构建代理字符串
	var proxyString string
	if proxy.Enabled {
		if proxy.Username != "" && proxy.Password != "" {
			proxyString = fmt.Sprintf("%s://%s:%s@%s:%s", proxy.Type, proxy.Username, proxy.Password, proxy.Address, proxy.Port)
		} else {
			proxyString = fmt.Sprintf("%s://%s:%s", proxy.Type, proxy.Address, proxy.Port)
		}
	} else {
		proxyString = "" // 确保禁用代理时使用空字符串
	}

	// 创建HTTP客户端配置
	clientConfig := client.HTTPClientConfig{
		Timeout:       10 * time.Second,
		Proxy:         proxyString,
		SkipSSL:       true,          // 测试连接时跳过SSL验证
		AllowRedirect: true,          // 默认允许重定向
		UserAgent:     "",            // 使用随机User-Agent
		Headers:       proxy.Headers, // 使用从代理配置传递的自定义请求头
		Cookies:       proxy.Cookies, // 使用从代理配置传递的自定义Cookie
	}

	// 创建临时客户端用于测试连接
	client, err := client.NewHTTPClient(clientConfig)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("创建HTTP客户端失败: %v", err))
		return false, fmt.Sprintf("创建HTTP客户端失败: %v", err)
	}

	// 发送测试请求
	resp, err := client.Get(target)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("连接失败: %v", err))
		return false, fmt.Sprintf("连接失败: %v", err)
	}

	statusCode := resp.StatusCode
	resp.Body.Close()

	a.AddLog("INFO", fmt.Sprintf("连接成功，状态码: %d", statusCode))
	return true, fmt.Sprintf("连接成功，状态码: %d", statusCode)
}

// GetScanProgress 获取扫描进度
func (a *App) GetScanProgress() (int, error) {
	a.progressMutex.Lock()
	defer a.progressMutex.Unlock()

	// 返回当前扫描进度百分比
	return a.currentProgress, nil
}

// StopScan 停止扫描
func (a *App) StopScan() error {
	a.scanMutex.Lock()
	defer a.scanMutex.Unlock()

	// 检查是否有正在进行的扫描
	if !a.isScanning {
		a.AddLog("INFO", "没有正在进行的扫描任务")
		return fmt.Errorf("没有正在进行的扫描任务")
	}

	// 取消上下文以中断正在运行的扫描
	if a.currentScanCancel != nil {
		a.currentScanCancel()
	}

	a.isScanning = false
	a.AddLog("INFO", "扫描已停止")
	return nil
}

// AddLog 添加日志
func (a *App) AddLog(level, message string) {
	a.logMutex.Lock()
	defer a.logMutex.Unlock()

	a.logs = append(a.logs, LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	})
	fmt.Printf("[%s] %s: %s\n", time.Now().Format("15:04:05"), level, message)
}

// AddLogWithDetails 添加带有详细信息的日志
func (a *App) AddLogWithDetails(level, message string, details []string) {
	a.logMutex.Lock()
	defer a.logMutex.Unlock()

	// 构建完整的结构化消息
	fullMessage := message
	for _, detail := range details {
		fullMessage += "\n" + detail
	}

	// 添加到日志列表
	mainLogEntry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   fullMessage,
	}
	a.logs = append(a.logs, mainLogEntry)

	// 在控制台输出时，仍然保持格式化显示
	fmt.Printf("[%s] %s: %s\n", time.Now().Format("15:04:05"), level, message)
	for _, detail := range details {
		fmt.Printf("                          %s\n", detail) // 留出足够的空间以对齐
	}
}

// GetLogs 获取日志
func (a *App) GetLogs() []LogEntry {
	a.logMutex.Lock()
	defer a.logMutex.Unlock()

	// 返回日志副本，避免并发访问问题
	logsCopy := make([]LogEntry, len(a.logs))
	copy(logsCopy, a.logs)
	return logsCopy
}

// ClearLogs 清空日志
func (a *App) ClearLogs() {
	a.logMutex.Lock()
	defer a.logMutex.Unlock()

	a.logs = make([]LogEntry, 0)
}

// ExportLogsToFile 将日志导出到文件
func (a *App) ExportLogsToFile() (string, error) {
	// 先锁定日志，复制一份日志数据
	a.logMutex.Lock()
	if len(a.logs) == 0 {
		a.logMutex.Unlock() // 立即解锁，因为没有日志需要处理
		a.AddLog("INFO", "没有日志可导出")
		return "", fmt.Errorf("没有日志可导出")
	}
	// 复制日志数据，这样可以立即释放锁
	logsCopy := make([]LogEntry, len(a.logs))
	copy(logsCopy, a.logs)
	a.logMutex.Unlock() // 释放锁，不再持有文件期间的锁

	// 生成文件名
	filename := fmt.Sprintf("vuln_scan_logs_%s.txt", time.Now().Format("20060102_150405"))

	// 获取当前工作目录
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("获取当前工作目录失败: %v", err)
	}
	filePath := filepath.Join(wd, filename)

	// 创建文件
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("创建日志文件失败: %v", err)
	}
	// 显式关闭文件，而不是依赖defer，确保文件句柄立即释放
	err = writeLogsToFile(file, logsCopy)
	file.Close() // 显式关闭文件
	if err != nil {
		return "", fmt.Errorf("写入日志文件失败: %v", err)
	}

	// 添加日志记录
	a.AddLog("INFO", fmt.Sprintf("日志已导出到文件: %s", filePath))
	return filePath, nil
}

// writeLogsToFile 将日志写入文件（不持有锁）
func writeLogsToFile(file *os.File, logs []LogEntry) error {
	// 写入日志内容
	for _, log := range logs {
		// 格式化日志条目
		formattedLog := fmt.Sprintf("[%s] %s: %s\n",
			log.Timestamp.Format("2006-01-02 15:04:05"),
			log.Level,
			log.Message)
		_, err := file.WriteString(formattedLog)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExportResultsToExcel 将扫描结果导出为Excel文件
func (a *App) ExportResultsToExcel(results []Vulnerability) (string, error) {
	// 创建一个新的Excel工作簿
	file := excelize.NewFile()
	// 创建工作表
	sheet := "Sheet1"
	// 设置表头
	headers := []string{"ID", "漏洞类型", "严重程度", "目标地址", "漏洞URL", "测试载荷", "漏洞描述", "验证证据", "修复建议"}
	for i, header := range headers {
		col := string(rune('A' + i))
		cell := fmt.Sprintf("%s1", col)
		file.SetCellValue(sheet, cell, header)
	}

	// 填充数据行
	for i, result := range results {
		row := i + 2 // 从第二行开始
		file.SetCellValue(sheet, fmt.Sprintf("A%d", row), result.ID)
		file.SetCellValue(sheet, fmt.Sprintf("B%d", row), result.VulnerabilityType)
		file.SetCellValue(sheet, fmt.Sprintf("C%d", row), result.Severity)
		file.SetCellValue(sheet, fmt.Sprintf("D%d", row), result.Target)
		file.SetCellValue(sheet, fmt.Sprintf("E%d", row), result.URL)
		file.SetCellValue(sheet, fmt.Sprintf("F%d", row), result.Payload)
		file.SetCellValue(sheet, fmt.Sprintf("G%d", row), result.Description)
		file.SetCellValue(sheet, fmt.Sprintf("H%d", row), result.Proof)
		file.SetCellValue(sheet, fmt.Sprintf("I%d", row), result.Recommendation)
	}

	// 设置列宽
	cols := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}
	widths := []float64{5, 15, 10, 25, 30, 20, 30, 25, 30}
	for i, col := range cols {
		file.SetColWidth(sheet, col, col, widths[i])
	}

	// 设置表头样式
	headerStyle, _ := file.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#1E90FF"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	for i := range headers {
		col := string(rune('A' + i))
		cell := fmt.Sprintf("%s1", col)
		file.SetCellStyle(sheet, cell, cell, headerStyle)
	}

	// 生成文件名
	filename := fmt.Sprintf("vuln_scan_results_%s.xlsx", time.Now().Format("20060102_150405"))

	// 保存文件
	err := file.SaveAs(filename)
	if err != nil {
		return "", fmt.Errorf("保存Excel文件失败: %v", err)
	}

	a.AddLog("INFO", fmt.Sprintf("扫描结果已导出到Excel文件: %s", filename))
	return filename, nil
}

// Greet returns a greeting for the given name
// updateTempResults 更新临时扫描结果
func (a *App) updateTempResults(newVulns []common.Vulnerability) {
	a.tempResultsMutex.Lock()
	defer a.tempResultsMutex.Unlock()

	// 创建扫描器管理器
	sm := scanner.NewScannerManager()

	// 将新发现的漏洞转换并添加到临时结果中
	for _, v := range newVulns {
		// 根据漏洞类型获取对应的扫描器
		var scannerName string
		switch v.VulnerabilityType {
		case "CVE-2022-22947":
			scannerName = "cve_2022_22947_scanner"
		case "CVE-2022-22963":
			scannerName = "cve_2022_22963_scanner"
		case "CVE-2025-55182":
			scannerName = "cve_2025_55182_scanner"
		case "CVE-2022-22965":
			scannerName = "cve_2022_22965_scanner"
		default:
			scannerName = ""
		}

		// 获取支持的功能
		supportedFeatures := []string{}
		if scannerName != "" {
			scan, err := sm.GetScanner(scannerName)
			if err == nil {
				supportedFeatures = scan.GetSupportedFeatures()
			}
		}

		// 为每个漏洞生成唯一的ID
		uniqueID := len(a.tempResults) + 1

		convertedVuln := Vulnerability{
			ID:                uniqueID,
			VulnerabilityType: v.VulnerabilityType,
			Severity:          v.Severity,
			Target:            v.Target,
			URL:               v.URL,
			Payload:           v.Payload,
			Description:       v.Description,
			Proof:             v.Proof,
			Recommendation:    v.Recommendation,
			ResponseHeaders:   v.ResponseHeaders,
			ResponseContent:   v.ResponseContent,
			SupportedFeatures: supportedFeatures,
		}
		a.tempResults = append(a.tempResults, convertedVuln)
	}
}

// GetTempScanResults 获取临时扫描结果（用于实时显示）
func (a *App) GetTempScanResults() []Vulnerability {
	a.tempResultsMutex.Lock()
	defer a.tempResultsMutex.Unlock()

	// 返回副本，避免并发访问问题
	resultsCopy := make([]Vulnerability, len(a.tempResults))
	copy(resultsCopy, a.tempResults)
	return resultsCopy
}

// filterDuplicateVulnerabilities 过滤重复的漏洞
func (a *App) filterDuplicateVulnerabilities(existing []common.Vulnerability, newVulns []common.Vulnerability) []common.Vulnerability {
	// 创建一个map来跟踪已存在的漏洞
	existingMap := make(map[string]bool)
	for _, v := range existing {
		// 使用URL和漏洞类型作为唯一标识
		key := fmt.Sprintf("%s_%s_%s", v.URL, v.VulnerabilityType, v.Target)
		existingMap[key] = true
	}

	// 过滤新漏洞，只返回不重复的
	filtered := []common.Vulnerability{}
	for _, v := range newVulns {
		key := fmt.Sprintf("%s_%s_%s", v.URL, v.VulnerabilityType, v.Target)
		if !existingMap[key] {
			filtered = append(filtered, v)
			existingMap[key] = true // 标记为已存在
		}
	}
	return filtered
}

// ClearTempScanResults 清空临时扫描结果
func (a *App) ClearTempScanResults() {
	a.tempResultsMutex.Lock()
	defer a.tempResultsMutex.Unlock()
	a.tempResults = []Vulnerability{}
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

// ExecuteCommand 执行命令
func (a *App) ExecuteCommand(vulnID int, command string) (string, error) {
	a.AddLog("INFO", fmt.Sprintf("执行命令请求: 漏洞ID=%d, 命令=%s", vulnID, command))

	// 检查命令是否为空
	if command == "" {
		a.AddLog("ERROR", "命令不能为空")
		return "", fmt.Errorf("命令不能为空")
	}

	// 查找漏洞
	var targetVuln *Vulnerability
	a.tempResultsMutex.Lock()
	for i, v := range a.tempResults {
		if v.ID == vulnID {
			targetVuln = &a.tempResults[i]
			break
		}
	}
	a.tempResultsMutex.Unlock()

	if targetVuln == nil {
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞ID=%d", vulnID))
		return "", fmt.Errorf("未找到漏洞")
	}

	// 检查漏洞是否支持命令执行
	if !contains(targetVuln.SupportedFeatures, "command") {
		a.AddLog("ERROR", fmt.Sprintf("漏洞 %s 不支持命令执行", targetVuln.VulnerabilityType))
		return "", fmt.Errorf("该漏洞不支持命令执行")
	}

	// 创建扫描器管理器
	sm := scanner.NewScannerManager()

	// 根据漏洞类型获取对应的扫描器
	var scannerName string
	switch targetVuln.VulnerabilityType {
	case "CVE-2022-22947":
		scannerName = "cve_2022_22947_scanner"
	case "CVE-2022-22963":
		scannerName = "cve_2022_22963_scanner"
	case "CVE-2025-55182":
		scannerName = "cve_2025_55182_scanner"
	case "CVE-2022-22965":
		scannerName = "cve_2022_22965_scanner"
	default:
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞 %s 对应的扫描器", targetVuln.VulnerabilityType))
		return "", fmt.Errorf("未找到对应的扫描器")
	}

	// 获取扫描器
	scan, err := sm.GetScanner(scannerName)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("获取扫描器失败: %v", err))
		return "", err
	}

	// 直接执行命令，使用扫描器内置的超时机制
	result, err := scan.ExecuteCommand(targetVuln.Target, command, a.scanOptions)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("命令执行失败: %v", err))
		return "", err
	}
	a.AddLog("INFO", fmt.Sprintf("命令执行成功: %s", result))
	return result, nil
}

// StartReverseShell 启动反弹shell
func (a *App) StartReverseShell(vulnID int, host string, port string) (string, error) {
	a.AddLog("INFO", fmt.Sprintf("反弹shell请求: 漏洞ID=%d, 主机=%s, 端口=%s", vulnID, host, port))

	// 检查参数
	if host == "" || port == "" {
		a.AddLog("ERROR", "主机和端口不能为空")
		return "", fmt.Errorf("主机和端口不能为空")
	}

	// // 检查IP地址是否可达和端口是否开放
	// a.AddLog("INFO", fmt.Sprintf("正在检查主机 %s:%s 是否可达", host, port))
	// // 兼容 IPv6 的地址格式：若 host 已含 ":"，需加中括号
	// address := net.JoinHostPort(host, port)
	// // 设置5秒超时
	// timeout := 5 * time.Second
	// conn, err := net.DialTimeout("tcp", address, timeout)
	// if err != nil {
	// 	a.AddLog("ERROR", fmt.Sprintf("主机 %s:%s 不可达: %v", host, port, err))
	// 	return "", fmt.Errorf("主机 %s:%s 不可达，请检查IP地址和端口是否正确，以及防火墙是否开放", host, port)
	// }
	// conn.Close()
	// a.AddLog("INFO", fmt.Sprintf("主机 %s:%s 可达，端口开放", host, port))

	// 查找漏洞
	var targetVuln *Vulnerability
	a.tempResultsMutex.Lock()
	for i, v := range a.tempResults {
		if v.ID == vulnID {
			targetVuln = &a.tempResults[i]
			break
		}
	}
	a.tempResultsMutex.Unlock()

	if targetVuln == nil {
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞ID=%d", vulnID))
		return "", fmt.Errorf("未找到漏洞")
	}

	// 检查漏洞是否支持反弹shell
	if !contains(targetVuln.SupportedFeatures, "shell") {
		a.AddLog("ERROR", fmt.Sprintf("漏洞 %s 不支持反弹shell", targetVuln.VulnerabilityType))
		return "", fmt.Errorf("该漏洞不支持反弹shell")
	}

	// 创建扫描器管理器
	sm := scanner.NewScannerManager()

	// 根据漏洞类型获取对应的扫描器
	var scannerName string
	switch targetVuln.VulnerabilityType {
	case "CVE-2022-22947":
		scannerName = "cve_2022_22947_scanner"
	case "CVE-2022-22963":
		scannerName = "cve_2022_22963_scanner"
	case "CVE-2025-55182":
		scannerName = "cve_2025_55182_scanner"
	case "CVE-2022-22965":
		scannerName = "cve_2022_22965_scanner"
	default:
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞 %s 对应的扫描器", targetVuln.VulnerabilityType))
		return "", fmt.Errorf("未找到对应的扫描器")
	}

	// 获取扫描器
	scan, err := sm.GetScanner(scannerName)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("获取扫描器失败: %v", err))
		return "", err
	}

	// 直接启动反弹shell，使用扫描器内置的超时机制
	result, err := scan.StartReverseShell(targetVuln.Target, host, port, a.scanOptions)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("反弹shell失败: %v", err))
		return "", err
	}

	a.AddLog("INFO", "反弹shell请求已发送")
	return result, nil
}

// GetMemoryShellTypes 获取支持的内存马类型
func (a *App) GetMemoryShellTypes(vulnID int) ([]map[string]string, error) {
	a.AddLog("INFO", fmt.Sprintf("获取内存马类型请求: 漏洞ID=%d", vulnID))

	// 查找漏洞
	var targetVuln *Vulnerability
	a.tempResultsMutex.Lock()
	for i, v := range a.tempResults {
		if v.ID == vulnID {
			targetVuln = &a.tempResults[i]
			break
		}
	}
	a.tempResultsMutex.Unlock()

	if targetVuln == nil {
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞ID=%d", vulnID))
		return nil, fmt.Errorf("未找到漏洞")
	}

	// 检查漏洞是否支持注入内存马
	if !contains(targetVuln.SupportedFeatures, "memory") {
		a.AddLog("ERROR", fmt.Sprintf("漏洞 %s 不支持注入内存马", targetVuln.VulnerabilityType))
		return nil, fmt.Errorf("该漏洞不支持注入内存马")
	}

	// 创建扫描器管理器
	sm := scanner.NewScannerManager()

	// 根据漏洞类型获取对应的扫描器
	var scannerName string
	switch targetVuln.VulnerabilityType {
	case "CVE-2022-22947":
		scannerName = "cve_2022_22947_scanner"
	case "CVE-2022-22963":
		scannerName = "cve_2022_22963_scanner"
	case "CVE-2025-55182":
		scannerName = "cve_2025_55182_scanner"
	case "CVE-2022-22965":
		scannerName = "cve_2022_22965_scanner"
	default:
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞 %s 对应的扫描器", targetVuln.VulnerabilityType))
		return nil, fmt.Errorf("未找到对应的扫描器")
	}

	// 获取扫描器
	scan, err := sm.GetScanner(scannerName)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("获取扫描器失败: %v", err))
		return nil, err
	}

	// 获取支持的内存马类型
	memoryShellTypes, err := scan.GetMemoryShellTypes()
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("获取内存马类型失败: %v", err))
		return nil, err
	}

	a.AddLog("INFO", fmt.Sprintf("获取内存马类型成功: %v", memoryShellTypes))
	return memoryShellTypes, nil
}

// InjectMemoryShell 注入内存马
func (a *App) InjectMemoryShell(vulnID int, password string, path string, shellType string) (string, error) {
	a.AddLog("INFO", fmt.Sprintf("注入内存马请求: 漏洞ID=%d, 密码=%s, 路径=%s, 类型=%s", vulnID, password, path, shellType))

	// 检查参数
	if password == "" || path == "" || shellType == "" {
		a.AddLog("ERROR", "密码、路径和内存马类型不能为空")
		return "", fmt.Errorf("密码、路径和内存马类型不能为空")
	}

	// 查找漏洞
	var targetVuln *Vulnerability
	a.tempResultsMutex.Lock()
	for i, v := range a.tempResults {
		if v.ID == vulnID {
			targetVuln = &a.tempResults[i]
			break
		}
	}
	a.tempResultsMutex.Unlock()

	if targetVuln == nil {
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞ID=%d", vulnID))
		return "", fmt.Errorf("未找到漏洞")
	}

	// 检查漏洞是否支持注入内存马
	if !contains(targetVuln.SupportedFeatures, "memory") {
		a.AddLog("ERROR", fmt.Sprintf("漏洞 %s 不支持注入内存马", targetVuln.VulnerabilityType))
		return "", fmt.Errorf("该漏洞不支持注入内存马")
	}

	// 创建扫描器管理器
	sm := scanner.NewScannerManager()

	// 根据漏洞类型获取对应的扫描器
	var scannerName string
	switch targetVuln.VulnerabilityType {
	case "CVE-2022-22947":
		scannerName = "cve_2022_22947_scanner"
	case "CVE-2022-22963":
		scannerName = "cve_2022_22963_scanner"
	case "CVE-2025-55182":
		scannerName = "cve_2025_55182_scanner"
	case "CVE-2022-22965":
		scannerName = "cve_2022_22965_scanner"
	default:
		a.AddLog("ERROR", fmt.Sprintf("未找到漏洞 %s 对应的扫描器", targetVuln.VulnerabilityType))
		return "", fmt.Errorf("未找到对应的扫描器")
	}

	// 获取扫描器
	scan, err := sm.GetScanner(scannerName)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("获取扫描器失败: %v", err))
		return "", err
	}

	// 直接注入内存马，使用扫描器内置的超时机制
	result, err := scan.InjectMemoryShell(targetVuln.Target, password, path, shellType, a.scanOptions)
	if err != nil {
		a.AddLog("ERROR", fmt.Sprintf("内存马注入失败: %v", err))
		return "", err
	}

	a.AddLog("INFO", "内存马注入请求已发送")
	return result, nil
}

// contains 检查切片是否包含指定元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// 添加辅助函数来过滤不可打印字符
func (a *App) filterPrintableCharacters(s string) string {
	if len(s) == 0 {
		return s
	}

	// 检查是否包含过多不可打印字符，如果是则返回摘要
	// 注意：对于Unicode字符（如中文），我们需要更智能的判断
	printableCount := 0
	runeCount := 0

	for _, r := range s {
		runeCount++
		// 检查是否为可打印字符：ASCII可打印字符、Unicode可打印字符、常用空白字符
		if (r >= 32 && r <= 126) || // ASCII可打印字符
			(r >= 0x4E00 && r <= 0x9FFF) || // 中日韩统一汉字
			(r >= 0x3400 && r <= 0x4DBF) || // 中日韩统一汉字扩展A
			(r >= 0x20000 && r <= 0x2A6DF) || // 中日韩统一汉字扩展B
			r == '\n' || r == '\r' || r == '\t' || // 常用空白字符
			(r >= 0x0080 && r <= 0x00FF) || // Latin-1补充字符
			(r >= 0x0100 && r <= 0x017F) || // Latin扩展-A
			(r >= 0x0180 && r <= 0x024F) || // Latin扩展-B
			(r >= 0x1100 && r <= 0x11FF) || // 韩文字母
			(r >= 0xAC00 && r <= 0xD7AF) { // 韩文音节
			printableCount++
		}
	}

	// 如果可打印字符比例小于一定阈值（考虑到中文等Unicode字符的情况），则返回二进制数据提示
	// 降低阈值以适应多字节字符语言
	if runeCount > 0 && float64(printableCount)/float64(runeCount) < 0.3 {
		return fmt.Sprintf("[Binary Data - Length: %d bytes]", len(s))
	}

	// 否则，过滤掉不可打印字符
	var result []rune
	for _, r := range s {
		// 保留可打印字符
		if (r >= 32 && r <= 126) || // ASCII可打印字符
			(r >= 0x4E00 && r <= 0x9FFF) || // 中日韩统一汉字
			(r >= 0x3400 && r <= 0x4DBF) || // 中日韩统一汉字扩展A
			(r >= 0x20000 && r <= 0x2A6DF) || // 中日韩统一汉字扩展B
			r == '\n' || r == '\r' || r == '\t' || // 常用空白字符
			(r >= 0x0080 && r <= 0x00FF) || // Latin-1补充字符
			(r >= 0x0100 && r <= 0x017F) || // Latin扩展-A
			(r >= 0x0180 && r <= 0x024F) || // Latin扩展-B
			(r >= 0x1100 && r <= 0x11FF) || // 韩文字母
			(r >= 0xAC00 && r <= 0xD7AF) { // 韩文音节
			result = append(result, r)
		} else if r == '\u0000' { // null字符替换为空格
			result = append(result, ' ')
		}
	}

	return string(result)
}

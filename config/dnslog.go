package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"vuln-scanner/client"
)

// 常量定义固定URL，避免魔法字符串
const (
	defaultDNSLogDomainURL = "http://47.244.138.18/getdomain.php"
	defaultDNSLogResultURL = "http://47.244.138.18/getrecords.php"
	userAgent              = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
	phpSessIDCookieName    = "PHPSESSID"
)

// DNSLogCfg 存储DNSLog相关配置
type DNSLogCfg struct {
	DNSLogURL string       `json:"dnslog_url"`
	ResultURL string       `json:"result_url"`
	PhpSessID string       `json:"php_sessid"`
	client    *http.Client // 内嵌企业级HTTP客户端
}

// NewDNSLogCfg 创建并初始化DNSLogCfg实例
// 同时初始化内置的HTTP客户端，可传入自定义配置
func NewDNSLogCfg(proxyURL string, skipVerify bool, allowInsecure bool, timeout time.Duration) (*DNSLogCfg, error) {
	client, err := client.CreateHTTPClient(proxyURL, skipVerify, allowInsecure, timeout)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	// 设置DNSLog专用的UserAgent

	return &DNSLogCfg{
		DNSLogURL: defaultDNSLogDomainURL,
		ResultURL: defaultDNSLogResultURL,
		client:    client,
	}, nil
}

// GetDNSLog 获取DNSLog域名
// 适配新客户端的调用方式，简化参数传递
func (c *DNSLogCfg) GetDNSLog() (string, error) {
	// 检查客户端是否初始化
	if c.client == nil {
		return "", errors.New("HTTP客户端未初始化，请使用NewDNSLogCfg创建实例")
	}

	// 使用新客户端发送GET请求
	resp, err := c.client.Get(c.DNSLogURL)
	if err != nil {
		return "", fmt.Errorf("获取DNSLog域名失败: %w", err)
	}
	defer resp.Body.Close()

	bodyTxt, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应体失败: %w", err)
	}
	// 检查响应状态码
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("获取DNSLog域名失败，状态码: %d, 响应: %s", resp.StatusCode, string(bodyTxt))
	}

	// 从响应Cookie中提取PHPSESSID（新客户端自动解析Cookie）
	c.extractPhpSessID(resp.Cookies())

	return string(bodyTxt), nil
}

// GetResult 获取DNSLog记录结果
func (c *DNSLogCfg) GetResult() (string, error) {
	// 检查客户端是否初始化
	if c.client == nil {
		return "", errors.New("HTTP客户端未初始化，请使用NewDNSLogCfg创建实例")
	}

	// 检查PHPSESSID是否存在
	if c.PhpSessID == "" {
		return "", errors.New("PHPSESSID为空，请先调用GetDNSLog获取")
	}

	cookies := &http.Cookie{

		Name:  phpSessIDCookieName,
		Value: c.PhpSessID,
		Path:  "/",
	}

	req, err := http.NewRequest("GET", c.ResultURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建GET请求失败: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	// 设置cookie
	req.AddCookie(cookies)
	// 使用新客户端发送带Cookie的GET请求
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("获取DNSLog记录失败: %w", err)
	}
	defer resp.Body.Close()

	bodyTxt, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应体失败: %w", err)
	}

	// 检查响应状态码
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("获取DNSLog记录失败，状态码: %d, 响应: %s", resp.StatusCode, string(bodyTxt))
	}

	// 解析JSON数据
	queries, err := ParseDNSLogs(string(bodyTxt))
	if err != nil {
		return "", fmt.Errorf("解析DNSLog记录失败: %w", err)
	}

	// 格式化输出
	var result string
	for _, query := range queries {
		result += fmt.Sprintf("%s %s %s\n", query.Timestamp.Format("2006-01-02 15:04:05"), query.Domain, query.IP)
	}

	return result, nil
}

// extractPhpSessID 从Cookie列表中提取PHPSESSID
func (c *DNSLogCfg) extractPhpSessID(cookies []*http.Cookie) {
	for _, cookie := range cookies {
		if cookie.Name == phpSessIDCookieName {
			c.PhpSessID = cookie.Value
			break // 找到后立即退出循环
		}
	}
}

// DNS查询记录结构体
type DNSQuery struct {
	Domain    string    `json:"domain"`
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
}

func ParseDNSLogs(jsonStr string) ([]DNSQuery, error) {
	var rawData [][]string
	err := json.Unmarshal([]byte(jsonStr), &rawData)
	if err != nil {
		return nil, err
	}
	var queries []DNSQuery
	for i, row := range rawData {
		if len(row) != 3 {
			return nil, fmt.Errorf("第%d行数据格式错误: 期望3个字段, 实际%d个", i+1, len(row))
		}
		domain := row[0]
		ip := row[1]
		timestamp, err := time.Parse("2006-01-02 15:04:05", row[2])
		if err != nil {
			fmt.Println("解析时间戳失败:", row[2])
			timestamp = time.Now() // 解析失败时使用当前时间
		}
		queries = append(queries, DNSQuery{
			Domain:    domain,
			IP:        ip,
			Timestamp: timestamp,
		})
	}

	return queries, nil
}

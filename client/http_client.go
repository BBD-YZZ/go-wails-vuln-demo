package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// HTTPClientConfig HTTP客户端配置
type HTTPClientConfig struct {
	Timeout               time.Duration     // 请求超时时间
	Proxy                 string            // 代理地址，格式：protocol://[user:password@]host:port
	UserAgent             string            // 用户代理
	SkipSSL               bool              // 是否跳过SSL验证
	AllowRedirect         bool              // 是否允许重定向
	MaxRedirects          int               // 最大重定向次数
	Headers               map[string]string // 自定义请求头（可选）
	Cookies               map[string]string // 自定义Cookie（可选）
	DisableKeepAlives     bool              // 是否禁用Keep-Alive
	MaxIdleConns          int               // 最大空闲连接数
	MaxConnsPerHost       int               // 每个主机的最大连接数
	IdleConnTimeout       time.Duration     // 空闲连接超时时间
	TLSClientConfig       *tls.Config       // TLS客户端配置
	ForceAttemptHTTP2     bool              // 是否强制使用HTTP/2
	ExpectContinueTimeout time.Duration     // 100-continue超时时间
	ResponseHeaderTimeout time.Duration     // 响应头超时时间
	TLSHandshakeTimeout   time.Duration     // TLS握手超时时间
}

// HTTPClient HTTP客户端
// 【复用组件：所有漏洞扫描器都使用此HTTP客户端，无需修改】
type HTTPClient struct {
	client *http.Client
	config HTTPClientConfig
}

// NewHTTPClient 创建新的HTTP客户端
func NewHTTPClient(config HTTPClientConfig) (*HTTPClient, error) {
	// 默认配置
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}
	// if config.MaxRedirects == 0 {
	// 	config.MaxRedirects = 10
	// }
	// if config.MaxIdleConns == 0 {
	// 	config.MaxIdleConns = 100
	// }
	// if config.MaxConnsPerHost == 0 {
	// 	config.MaxConnsPerHost = 10
	// }
	// if config.IdleConnTimeout == 0 {
	// 	config.IdleConnTimeout = 90 * time.Second
	// }
	// if config.ExpectContinueTimeout == 0 {
	// 	config.ExpectContinueTimeout = 1 * time.Second
	// }
	// if config.ResponseHeaderTimeout == 0 {
	// 	config.ResponseHeaderTimeout = 0 // 无超时限制
	// }
	// if config.TLSHandshakeTimeout == 0 {
	// 	config.TLSHandshakeTimeout = 10 * time.Second
	// }

	// 创建传输层配置
	transport := &http.Transport{
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		DisableKeepAlives:     config.DisableKeepAlives,
		ForceAttemptHTTP2:     config.ForceAttemptHTTP2,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		TLSClientConfig:       config.TLSClientConfig,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		TLSHandshakeTimeout: config.TLSHandshakeTimeout,
	}

	// 如果没有提供TLS配置，使用默认配置
	if config.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: config.SkipSSL, // 跳过SSL验证
		}
	}

	// 配置代理
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err != nil {
			return nil, fmt.Errorf("解析代理URL失败: %v", err)
		}

		// 根据协议类型配置代理
		switch strings.ToLower(proxyURL.Scheme) {
		case "http", "https":
			transport.Proxy = http.ProxyURL(proxyURL)
		case "socks5", "socks5h":
			// 提取SOCKS5代理的认证信息
			var auth *proxy.Auth
			if proxyURL.User != nil {
				username := proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				if username != "" {
					auth = &proxy.Auth{
						User:     username,
						Password: password,
					}
				}
			}
			socksDialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("创建SOCKS5代理失败: %v", err)
			}
			transport.DialContext = socksDialer.(proxy.ContextDialer).DialContext
		default:
			return nil, fmt.Errorf("不支持的代理协议: %s", proxyURL.Scheme)
		}
	}

	// 创建HTTP客户端
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.AllowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("超过最大重定向次数: %d", config.MaxRedirects)
			}
			return nil
		},
	}

	return &HTTPClient{
		client: client,
		config: config,
	}, nil
}

// GetHTTPClient 获取配置后的标准http.Client
func (c *HTTPClient) GetHTTPClient() *http.Client {
	return c.client
}

func (c *HTTPClient) Get(url string) (*http.Response, error) {
	req, err := c.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(req)
}

func (c *HTTPClient) Post(url string, body []byte) (*http.Response, error) {
	req, err := c.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return c.client.Do(req)
}

func (c *HTTPClient) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// Do 发送自定义请求
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// // setHeaders 设置请求头（内部方法）
// func (c *HTTPClient) setHeaders(req *http.Request) {
// 	// 设置User-Agent
// 	userAgent := c.config.UserAgent
// 	if userAgent == "" {
// 		userAgent = GetRandomUserAgent()
// 	}
// 	req.Header.Set("User-Agent", userAgent)

// 	// 设置默认请求头
// 	if req.Header.Get("Accept") == "" {
// 		req.Header.Set("Accept", "*/*")
// 	}
// 	if req.Header.Get("Accept-Language") == "" {
// 		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
// 	}
// 	if req.Header.Get("Accept-Encoding") == "" {
// 		req.Header.Set("Accept-Encoding", "gzip, deflate")
// 	}
// 	if req.Header.Get("Connection") == "" {
// 		req.Header.Set("Connection", "keep-alive")
// 	}
// 	if req.Header.Get("Upgrade-Insecure-Requests") == "" {
// 		req.Header.Set("Upgrade-Insecure-Requests", "1")
// 	}

// 	// 设置自定义请求头
// 	for key, value := range c.config.Headers {
// 		req.Header.Set(key, value)
// 	}

// 	// 设置Cookie
// 	if c.config.Cookies != nil && len(c.config.Cookies) > 0 {
// 		var cookies []string
// 		for name, value := range c.config.Cookies {
// 			cookies = append(cookies, fmt.Sprintf("%s=%s", name, value))
// 		}
// 		req.Header.Set("Cookie", strings.Join(cookies, "; "))
// 	}
// }

// GetRandomUserAgent 随机获取User-Agent
func GetRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	}

	return userAgents[rand.Intn(len(userAgents))]
}

// 创建HTTP客户端（支持代理）
func CreateHTTPClient(proxyURL string, SkipSSL bool, AllowRedirect bool, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{}

	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: SkipSSL, // 跳过SSL验证
	}

	// 如果提供了代理，则配置代理
	if proxyURL != "" {
		proxyURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("解析代理URL失败: %v", err)
		}

		// 根据协议类型配置代理
		switch strings.ToLower(proxyURL.Scheme) {
		case "http", "https":
			transport.Proxy = http.ProxyURL(proxyURL)
		case "socks5", "socks5h":
			// 提取SOCKS5代理的认证信息
			var auth *proxy.Auth
			if proxyURL.User != nil {
				username := proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				if username != "" {
					auth = &proxy.Auth{
						User:     username,
						Password: password,
					}
				}
			}
			socksDialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("创建SOCKS5代理失败: %v", err)
			}
			transport.DialContext = socksDialer.(proxy.ContextDialer).DialContext
		default:
			return nil, fmt.Errorf("不支持的代理协议: %s", proxyURL.Scheme)
		}
	}

	var checkRedirect func(req *http.Request, via []*http.Request) error
	if !AllowRedirect {
		checkRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向
		}
	} else {
		checkRedirect = nil // 使用默认的重定向行为
	}

	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}, nil
}

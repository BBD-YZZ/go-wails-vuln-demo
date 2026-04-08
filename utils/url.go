package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateURL 验证URL是否有效
// 如果URL没有协议头，会自动添加http://
// 返回验证后的URL和是否有效
func ValidateURL(rawURL string) (string, error) {
	// 去除前后空白
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("URL不能为空")
	}

	// 检查是否有协议头（支持http, https, ftp, sftp）
	hasProtocol := false
	protocols := []string{"http://", "https://", "ftp://", "sftp://"}
	for _, protocol := range protocols {
		if strings.HasPrefix(rawURL, protocol) {
			hasProtocol = true
			break
		}
	}

	if !hasProtocol {
		// 添加默认的http协议头
		rawURL = "http://" + rawURL
	}

	// 解析URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("URL解析失败: %v", err)
	}

	// 检查主机名是否有效
	if parsedURL.Hostname() == "" {
		return "", fmt.Errorf("URL主机名无效")
	}

	// 检查端口是否有效（如果指定了端口）
	if parsedURL.Port() != "" {
		// 这里可以添加端口范围检查，如果需要的话
	}

	// 重新构建URL，确保格式正确
	validURL := parsedURL.String()

	return validURL, nil
}

// ValidateURLs 批量验证URLs
// 返回有效的URL列表和无效的URL列表
func ValidateURLs(rawURLs []string) ([]string, map[string]string) {
	var validURLs []string
	invalidURLs := make(map[string]string)

	for _, rawURL := range rawURLs {
		validURL, err := ValidateURL(rawURL)
		if err != nil {
			invalidURLs[rawURL] = err.Error()
		} else {
			validURLs = append(validURLs, validURL)
		}
	}

	return validURLs, invalidURLs
}

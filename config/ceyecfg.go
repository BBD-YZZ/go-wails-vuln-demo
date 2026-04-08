package config

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	c "vuln-scanner/client"

	"gopkg.in/yaml.v2"
)

type DNSLogConfig struct {
	Token   string `json:"token"`
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
}

type DNSLogRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemoteAddr string `json:"remote_addr"`
	CreatedAt  string `json:"created_at"`
}

type DNSLogResponse struct {
	Meta struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"meta"`
	Data []DNSLogRecord `json:"data"`
}

func LoadDNSLogConfigFromFile() (*DNSLogConfig, error) {
	currentPath, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("获取当前目录失败: %w", err)
	}

	// 检查config目录是否存在，如果不存在则创建
	configDir := fmt.Sprintf("%s/config", currentPath)
	if _, err = os.Stat(configDir); os.IsNotExist(err) {
		if err = os.Mkdir(configDir, 0755); err != nil {
			return nil, fmt.Errorf("创建config目录失败: %w", err)
		}
		fmt.Printf("已创建config目录: %s\n", configDir)
	}

	// 尝试加载不同格式的配置文件
	var cfgFilePath string
	var fileExists bool

	// 优先尝试JSON格式
	jsonPath := fmt.Sprintf("%s/config/config.json", currentPath)
	if _, err = os.Stat(jsonPath); err == nil {
		cfgFilePath = jsonPath
		fileExists = true
	}

	// 如果JSON文件不存在，尝试YAML格式
	if !fileExists {
		yamlPath := fmt.Sprintf("%s/config/config.yaml", currentPath)
		if _, err = os.Stat(yamlPath); err == nil {
			cfgFilePath = yamlPath
			fileExists = true
		} else {
			// 尝试yml扩展名
			ymlPath := fmt.Sprintf("%s/config/config.yml", currentPath)
			if _, err = os.Stat(ymlPath); err == nil {
				cfgFilePath = ymlPath
				fileExists = true
			}
		}
	}

	// 如果没有找到任何配置文件，创建一个示例JSON文件
	if !fileExists {
		jsonPath := fmt.Sprintf("%s/config/config.json", currentPath)

		// 创建示例配置内容
		exampleConfig := &DNSLogConfig{
			Token:   "your_ceye_token",
			Domain:  "your_ceye_domain.ceye.io",
			Enabled: false,
		}

		// 转换为JSON格式
		var jsonData []byte
		jsonData, err = json.MarshalIndent(exampleConfig, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("生成示例配置失败: %w", err)
		}

		// 写入文件
		if err = os.WriteFile(jsonPath, jsonData, 0644); err != nil {
			return nil, fmt.Errorf("创建示例配置文件失败: %w", err)
		}

		fmt.Printf("已创建示例配置文件: %s\n", jsonPath)
		fmt.Println("请编辑配置文件，填写正确的Ceye Token和Domain")

		// 返回默认配置
		return exampleConfig, nil
	}

	// 读取文件
	data, err := os.ReadFile(cfgFilePath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 根据文件扩展名确定格式
	ext := filepath.Ext(cfgFilePath)

	var cfg DNSLogConfig
	switch ext {
	case ".json":
		err = json.Unmarshal(data, &cfg)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &cfg)
	default:
		return nil, fmt.Errorf("不支持的配置文件格式: %s。请使用.json、.yaml或.yml格式", ext)
	}
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	return &cfg, nil
}

func CheckDNSLogRecord(cfg *DNSLogConfig, httpCfg *c.HTTPClientConfig, subdomain string) (bool, []DNSLogRecord, error) {
	if cfg == nil {
		return false, nil, fmt.Errorf("dnslog config is nil")
	}
	if !cfg.Enabled {
		return false, nil, fmt.Errorf("dnslog is not enabled")
	}
	if cfg.Token == "" {
		return false, nil, fmt.Errorf("token is empty")
	}
	if cfg.Domain == "" {
		return false, nil, fmt.Errorf("domain is empty")
	}

	if subdomain == "" {
		return false, nil, fmt.Errorf("subdomain is empty")
	}

	filter := strings.Split(strings.TrimSpace(subdomain), ".")
	if len(filter) != 4 {
		return false, nil, fmt.Errorf("subdomain format is invalid")
	}

	apiURL := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", cfg.Token, filter[0])

	client, err := c.NewHTTPClient(*httpCfg)
	dnslogresp, err := client.Get(apiURL)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get dnslog record: %w", err)
	}
	defer dnslogresp.Body.Close()

	var dnslogResp DNSLogResponse
	if err := json.NewDecoder(dnslogresp.Body).Decode(&dnslogResp); err != nil {
		return false, nil, fmt.Errorf("failed to decode dnslog response: %w", err)
	}
	if dnslogResp.Meta.Code != 200 {
		return false, nil, fmt.Errorf("dnslog response code is not 200: %d", dnslogResp.Meta.Code)
	}
	if len(dnslogResp.Data) == 0 {
		return false, nil, fmt.Errorf("no dnslog record found")
	}
	return true, dnslogResp.Data, nil
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

package logger

import (
	"fmt"
	"sync"
	"time"
	"vuln-scanner/common"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
)

// LogContext 日志上下文，包含扫描相关的上下文信息
type LogContext struct {
	Target            string                 `json:"target"`            // 扫描目标
	ScannerName       string                 `json:"scannerName"`       // 扫描器名称
	VulnerabilityType string                 `json:"vulnerabilityType"` // 漏洞类型
	Step              string                 `json:"step"`              // 当前步骤
	Timestamp         time.Time              `json:"timestamp"`         // 时间戳
	Extra             map[string]interface{} `json:"extra"`             // 额外信息
}

// LogEntry 日志条目
type LogEntry struct {
	Level     LogLevel   `json:"level"`     // 日志级别
	Message   string     `json:"message"`   // 日志消息
	Context   LogContext `json:"context"`   // 日志上下文
	Timestamp time.Time  `json:"timestamp"` // 时间戳
}

// Logger 日志记录器接口
// 所有扫描器都可以使用此接口记录详细的扫描过程
type Logger interface {
	// Debug 记录调试信息
	Debug(message string, ctx ...LogContext)
	// Info 记录一般信息
	Info(message string, ctx ...LogContext)
	// Warn 记录警告信息
	Warn(message string, ctx ...LogContext)
	// Error 记录错误信息
	Error(message string, err error, ctx ...LogContext)
	// LogRequest 记录HTTP请求详情
	LogRequest(method, url string, headers map[string]string, body []byte, ctx ...LogContext)
	// LogResponse 记录HTTP响应详情
	LogResponse(statusCode int, headers map[string]string, body []byte, duration time.Duration, ctx ...LogContext)
	// LogVulnerabilityFound 记录漏洞发现
	LogVulnerabilityFound(vuln common.Vulnerability, ctx ...LogContext)
	// LogScanStep 记录扫描步骤
	LogScanStep(step string, details map[string]interface{}, ctx ...LogContext)
	// GetLogs 获取所有日志
	GetLogs() []LogEntry
	// ClearLogs 清空日志
	ClearLogs()
}

// DefaultLogger 默认日志记录器实现
type DefaultLogger struct {
	logs  []LogEntry
	mutex sync.RWMutex
}

// NewDefaultLogger 创建默认日志记录器
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{
		logs: make([]LogEntry, 0),
	}
}

// log 内部日志记录方法
func (l *DefaultLogger) log(level LogLevel, message string, ctx ...LogContext) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	var logCtx LogContext
	if len(ctx) > 0 {
		logCtx = ctx[0]
	} else {
		logCtx = LogContext{
			Timestamp: time.Now(),
		}
	}

	if logCtx.Timestamp.IsZero() {
		logCtx.Timestamp = time.Now()
	}

	entry := LogEntry{
		Level:     level,
		Message:   message,
		Context:   logCtx,
		Timestamp: time.Now(),
	}

	l.logs = append(l.logs, entry)

	// 同时输出到控制台
	fmt.Printf("[%s] [%s] %s", entry.Timestamp.Format("2006-01-02 15:04:05.000"), level, message)
	if logCtx.Target != "" {
		fmt.Printf(" [Target: %s]", logCtx.Target)
	}
	if logCtx.ScannerName != "" {
		fmt.Printf(" [Scanner: %s]", logCtx.ScannerName)
	}
	if logCtx.VulnerabilityType != "" {
		fmt.Printf(" [VulnType: %s]", logCtx.VulnerabilityType)
	}
	if logCtx.Step != "" {
		fmt.Printf(" [Step: %s]", logCtx.Step)
	}
	if len(logCtx.Extra) > 0 {
		fmt.Println()
		for k, v := range logCtx.Extra {
			switch k {
			case "headers":
				if headers, ok := v.(map[string]string); ok {
					fmt.Printf("    Headers:\n")
					for hk, hv := range headers {
						fmt.Printf("        %s: %s\n", hk, hv)
					}
				} else {
					fmt.Printf("    %s: %v\n", k, v)
				}
			case "body":
				// 对于body，根据内容类型决定是否格式化输出
				if bodyStr, ok := v.(string); ok {
					// 如果body是JSON或其他文本格式，可以考虑美化输出
					if len(bodyStr) > 1000 {
						// 如果body太长，分段显示
						fmt.Printf("    Body (first 1000 chars): %s...(truncated)\n", bodyStr[:1000])
					} else {
						fmt.Printf("    Body: %s\n", bodyStr)
					}
				} else {
					fmt.Printf("    %s: %v\n", k, v)
				}
			case "requestBody":
				// 单独处理request body
				if bodyStr, ok := v.(string); ok {
					if len(bodyStr) > 1000 {
						fmt.Printf("    Request Body (first 1000 chars): %s...(truncated)\n", bodyStr[:1000])
					} else {
						fmt.Printf("    Request Body: %s\n", bodyStr)
					}
				} else {
					fmt.Printf("    %s: %v\n", k, v)
				}
			case "responseBody":
				// 单独处理response body
				if bodyStr, ok := v.(string); ok {
					if len(bodyStr) > 1000 {
						fmt.Printf("    Response Body (first 1000 chars): %s...(truncated)\n", bodyStr[:1000])
					} else {
						fmt.Printf("    Response Body: %s\n", bodyStr)
					}
				} else {
					fmt.Printf("    %s: %v\n", k, v)
				}
			default:
				fmt.Printf("    %s: %v\n", k, v)
			}
		}
	} else {
		fmt.Println()
	}
}

// Debug 记录调试信息
func (l *DefaultLogger) Debug(message string, ctx ...LogContext) {
	l.log(LogLevelDebug, message, ctx...)
}

// Info 记录一般信息
func (l *DefaultLogger) Info(message string, ctx ...LogContext) {
	l.log(LogLevelInfo, message, ctx...)
}

// Warn 记录警告信息
func (l *DefaultLogger) Warn(message string, ctx ...LogContext) {
	l.log(LogLevelWarn, message, ctx...)
}

// Error 记录错误信息
func (l *DefaultLogger) Error(message string, err error, ctx ...LogContext) {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}
	l.log(LogLevelError, errorMsg, ctx...)
}

// LogRequest 记录HTTP请求详情
func (l *DefaultLogger) LogRequest(method, url string, headers map[string]string, body []byte, ctx ...LogContext) {
	var logCtx LogContext
	if len(ctx) > 0 {
		logCtx = ctx[0]
	}
	if logCtx.Extra == nil {
		logCtx.Extra = make(map[string]interface{})
	}
	logCtx.Extra["method"] = method
	logCtx.Extra["url"] = url
	logCtx.Extra["headers"] = headers
	if body != nil && len(body) > 0 {
		bodyStr := string(body)
		if len(bodyStr) > 1000 {
			bodyStr = bodyStr[:1000] + "...(truncated)"
		}
		logCtx.Extra["requestBody"] = bodyStr
	}

	message := fmt.Sprintf("HTTP Request: %s %s", method, url)
	l.log(LogLevelDebug, message, logCtx)
}

// LogResponse 记录HTTP响应详情
func (l *DefaultLogger) LogResponse(statusCode int, headers map[string]string, body []byte, duration time.Duration, ctx ...LogContext) {
	var logCtx LogContext
	if len(ctx) > 0 {
		logCtx = ctx[0]
	}
	if logCtx.Extra == nil {
		logCtx.Extra = make(map[string]interface{})
	}
	logCtx.Extra["statusCode"] = statusCode
	logCtx.Extra["headers"] = headers
	logCtx.Extra["duration"] = duration.String()
	if body != nil && len(body) > 0 {
		bodyStr := string(body)
		if len(bodyStr) > 1000 {
			bodyStr = bodyStr[:1000] + "...(truncated)"
		}
		logCtx.Extra["responseBody"] = bodyStr
	}

	message := fmt.Sprintf("HTTP Response: %d (Duration: %v)", statusCode, duration)
	l.log(LogLevelDebug, message, logCtx)
}

// LogVulnerabilityFound 记录漏洞发现
func (l *DefaultLogger) LogVulnerabilityFound(vuln common.Vulnerability, ctx ...LogContext) {
	var logCtx LogContext
	if len(ctx) > 0 {
		logCtx = ctx[0]
	}
	if logCtx.Extra == nil {
		logCtx.Extra = make(map[string]interface{})
	}
	logCtx.Extra["vulnerability"] = vuln
	logCtx.Target = vuln.Target
	logCtx.VulnerabilityType = vuln.VulnerabilityType

	message := fmt.Sprintf("漏洞发现: %s [%s] - %s", vuln.VulnerabilityType, vuln.Severity, vuln.URL)
	l.log(LogLevelInfo, message, logCtx)
}

// LogScanStep 记录扫描步骤
func (l *DefaultLogger) LogScanStep(step string, details map[string]interface{}, ctx ...LogContext) {
	var logCtx LogContext
	if len(ctx) > 0 {
		logCtx = ctx[0]
	}
	logCtx.Step = step
	if logCtx.Extra == nil {
		logCtx.Extra = make(map[string]interface{})
	}
	for k, v := range details {
		logCtx.Extra[k] = v
	}

	message := fmt.Sprintf("扫描步骤: %s", step)
	l.log(LogLevelDebug, message, logCtx)
}

// GetLogs 获取所有日志
func (l *DefaultLogger) GetLogs() []LogEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	logsCopy := make([]LogEntry, len(l.logs))
	copy(logsCopy, l.logs)
	return logsCopy
}

// ClearLogs 清空日志
func (l *DefaultLogger) ClearLogs() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.logs = make([]LogEntry, 0)
}

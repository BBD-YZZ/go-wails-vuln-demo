package logger

import (
	"fmt"
	"time"
	"vuln-scanner/common"
)

// LogAdapter 日志适配器，将scanner包的日志转换为app层的日志格式
// 这个适配器允许scanner包的日志系统与app层的日志系统集成
type LogAdapter struct {
	logCallback func(level, message string, context map[string]interface{})
}

// NewLogAdapter 创建日志适配器
func NewLogAdapter(callback func(level, message string, context map[string]interface{})) *LogAdapter {
	return &LogAdapter{
		logCallback: callback,
	}
}

// Debug 记录调试信息
func (a *LogAdapter) Debug(message string, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		a.logCallback("DEBUG", message, context)
	}
}

// Info 记录一般信息
func (a *LogAdapter) Info(message string, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		a.logCallback("INFO", message, context)
	}
}

// Warn 记录警告信息
func (a *LogAdapter) Warn(message string, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		a.logCallback("WARN", message, context)
	}
}

// Error 记录错误信息
func (a *LogAdapter) Error(message string, err error, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		if err != nil {
			context["error"] = err.Error()
		}
		a.logCallback("ERROR", message, context)
	}
}

// LogRequest 记录HTTP请求详情
func (a *LogAdapter) LogRequest(method, url string, headers map[string]string, body []byte, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		context["request_method"] = method
		context["request_url"] = url
		context["request_headers"] = headers
		if body != nil && len(body) > 0 {
			bodyStr := string(body)
			if len(bodyStr) > 500 {
				bodyStr = bodyStr[:500] + "...(truncated)"
			}
			context["request_body"] = bodyStr
		}
		a.logCallback("DEBUG", fmt.Sprintf("HTTP Request: %s %s", method, url), context)
	}
}

// LogResponse 记录HTTP响应详情
func (a *LogAdapter) LogResponse(statusCode int, headers map[string]string, body []byte, duration time.Duration, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		context["response_status"] = statusCode
		context["response_headers"] = headers
		context["response_duration"] = duration.String()
		if body != nil && len(body) > 0 {
			bodyStr := string(body)
			if len(bodyStr) > 500 {
				bodyStr = bodyStr[:500] + "...(truncated)"
			}
			context["response_body"] = bodyStr
		}
		a.logCallback("DEBUG", fmt.Sprintf("HTTP Response: %d (Duration: %v)", statusCode, duration), context)
	}
}

// LogVulnerabilityFound 记录漏洞发现
func (a *LogAdapter) LogVulnerabilityFound(vuln common.Vulnerability, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		context["vulnerability_id"] = vuln.ID
		context["vulnerability_type"] = vuln.VulnerabilityType
		context["severity"] = vuln.Severity
		context["vulnerability_url"] = vuln.URL
		context["payload"] = vuln.Payload
		context["proof"] = vuln.Proof
		a.logCallback("INFO", fmt.Sprintf("漏洞发现: %s [%s] - %s", vuln.VulnerabilityType, vuln.Severity, vuln.URL), context)
	}
}

// LogScanStep 记录扫描步骤
func (a *LogAdapter) LogScanStep(step string, details map[string]interface{}, ctx ...LogContext) {
	if a.logCallback != nil {
		context := a.extractContext(ctx...)
		context["step"] = step
		for k, v := range details {
			context[k] = v
		}
		a.logCallback("DEBUG", fmt.Sprintf("扫描步骤: %s", step), context)
	}
}

// GetLogs 获取所有日志（适配器不存储日志，返回空）
func (a *LogAdapter) GetLogs() []LogEntry {
	return []LogEntry{}
}

// ClearLogs 清空日志（适配器不存储日志，无操作）
func (a *LogAdapter) ClearLogs() {
	// 适配器不存储日志，无需清空
}

// extractContext 提取日志上下文
func (a *LogAdapter) extractContext(ctx ...LogContext) map[string]interface{} {
	context := make(map[string]interface{})
	if len(ctx) > 0 {
		c := ctx[0]
		if c.Target != "" {
			context["target"] = c.Target
		}
		if c.ScannerName != "" {
			context["scanner"] = c.ScannerName
		}
		if c.VulnerabilityType != "" {
			context["vulnerability_type"] = c.VulnerabilityType
		}
		if c.Step != "" {
			context["step"] = c.Step
		}
		if c.Extra != nil {
			for k, v := range c.Extra {
				context[k] = v
			}
		}
	}
	return context
}

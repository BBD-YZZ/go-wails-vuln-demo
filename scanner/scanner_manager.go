package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
	"vuln-scanner/client"
	"vuln-scanner/common"
	"vuln-scanner/logger"
	"vuln-scanner/utils"
	"vuln-scanner/vulns"
)

// ScannerManager 扫描器管理器
// 用于统一管理和调度不同的漏洞扫描器
// 这是通用漏洞扫描工具的核心管理组件
type ScannerManager struct {
	scanners          map[string]vulns.VulnerabilityScanner                     // 扫描器注册表
	mutex             sync.RWMutex                                              // 并发安全锁
	logger            logger.Logger                                             // 日志记录器
	httpClientFactory func(client.HTTPClientConfig) (*client.HTTPClient, error) // HTTP客户端工厂函数
}

// NewScannerManager 创建扫描器管理器
// 初始化管理器并注册默认扫描器
func NewScannerManager() *ScannerManager {
	manager := &ScannerManager{
		scanners:          make(map[string]vulns.VulnerabilityScanner),
		logger:            logger.NewDefaultLogger(),
		httpClientFactory: client.NewHTTPClient,
	}

	// 注册默认扫描器
	// 【扩展点：在这里注册新的扫描器，添加manager.RegisterScanner(...)行】
	// 新增漏洞扫描器只需在此处注册即可
	// manager.RegisterScanner("spring_cloud_gateway_scanner", NewSpringCloudGatewayScanner())

	// 注册独立的CVE扫描器
	manager.RegisterScanner("cve_2022_22947_scanner", vulns.NewCVE202222947Scanner())
	manager.RegisterScanner("cve_2022_22963_scanner", vulns.NewCVE202222963Scanner())
	manager.RegisterScanner("cve_2022_22965_scanner", vulns.NewCVE202222965Scanner())
	manager.RegisterScanner("cve_2025_55182_scanner", vulns.NewCVE202555182Scanner())

	return manager
}

// WithLogger 设置日志记录器
// 支持依赖注入，提高可测试性
func (sm *ScannerManager) WithLogger(logger logger.Logger) *ScannerManager {
	sm.logger = logger
	return sm
}

// WithHTTPClientFactory 设置HTTP客户端工厂函数
// 支持依赖注入，提高可测试性
func (sm *ScannerManager) WithHTTPClientFactory(factory func(client.HTTPClientConfig) (*client.HTTPClient, error)) *ScannerManager {
	sm.httpClientFactory = factory
	return sm
}

// RegisterScanner 注册扫描器
// 用于添加新的漏洞扫描器到管理器中
// 要添加新的扫描器，只需要创建新的扫描器实例并调用此方法注册
func (sm *ScannerManager) RegisterScanner(name string, scanner vulns.VulnerabilityScanner) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.scanners[name] = scanner
}

// GetScanner 获取扫描器
// 根据名称获取已注册的扫描器实例
func (sm *ScannerManager) GetScanner(name string) (vulns.VulnerabilityScanner, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	scanner, exists := sm.scanners[name]
	if !exists {
		return nil, fmt.Errorf("扫描器 %s 不存在", name)
	}
	return scanner, nil
}

// ScannerInfo 扫描器信息结构
// 用于返回扫描器的元数据信息
type ScannerInfo struct {
	Name                     string   `json:"name"`                     // 扫描器名称
	SupportedVulnerabilities []string `json:"supportedVulnerabilities"` // 支持的漏洞类型
}

// GetAllScannerNames 获取所有扫描器名称
// 返回所有已注册扫描器的名称列表
func (sm *ScannerManager) GetAllScannerNames() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	names := make([]string, 0, len(sm.scanners))
	for name := range sm.scanners {
		names = append(names, name)
	}
	return names
}

// UnregisterScanner 注销扫描器
// 从管理器中移除指定名称的扫描器
func (sm *ScannerManager) UnregisterScanner(name string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.scanners[name]; !exists {
		return fmt.Errorf("扫描器 %s 不存在", name)
	}
	delete(sm.scanners, name)
	return nil
}

// GetScannerInfo 获取扫描器信息
// 返回指定扫描器的详细信息
func (sm *ScannerManager) GetScannerInfo(name string) (ScannerInfo, error) {
	scanner, err := sm.GetScanner(name)
	if err != nil {
		return ScannerInfo{}, err
	}

	return ScannerInfo{
		Name:                     name,
		SupportedVulnerabilities: scanner.GetSupportedVulnerabilities(),
	}, nil
}

// ScanWithScanner 使用指定扫描器进行扫描
// 执行单个目标的扫描操作
func (sm *ScannerManager) ScanWithScanner(scannerName string, target string, options vulns.ScanOptions) ([]common.Vulnerability, error) {
	// 使用默认上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return sm.ScanWithScannerWithContext(ctx, scannerName, target, options)
}

// ScanWithScannerWithContext 使用指定扫描器进行扫描（支持上下文）
// 执行单个目标的扫描操作，支持上下文取消和超时控制
func (sm *ScannerManager) ScanWithScannerWithContext(ctx context.Context, scannerName string, target string, options vulns.ScanOptions) ([]common.Vulnerability, error) {
	// 验证URL
	validTarget, err := utils.ValidateURL(target)
	if err != nil {
		return nil, &vulns.ScanError{
			Type:    vulns.ErrorTypeTarget,
			Message: "目标URL无效",
			Target:  target,
			Err:     err,
		}
	}

	scanner, err := sm.GetScanner(scannerName)
	if err != nil {
		return nil, &vulns.ScanError{
			Type:    vulns.ErrorTypeScanner,
			Message: "获取扫描器失败",
			Target:  validTarget,
			Err:     err,
		}
	}

	// 如果Logger未设置，创建默认Logger
	if options.Logger == nil {
		options.Logger = logger.NewDefaultLogger()
	}

	// 如果没有ScanContext，创建一个默认的
	if options.Context == nil {
		options.Context = &vulns.ScanContext{
			ScanID:     fmt.Sprintf("scan_%d", time.Now().UnixNano()),
			StartTime:  time.Now(),
			Logger:     options.Logger,
			Statistics: &vulns.ScanStatistics{},
		}
	}

	// 记录扫描开始（使用验证后的URL）
	options.Logger.Info(fmt.Sprintf("开始扫描目标: %s", validTarget), logger.LogContext{
		Target:      validTarget,
		ScannerName: scannerName,
		Timestamp:   time.Now(),
	})

	// 使用验证后的URL进行扫描
	return scanner.Scan(ctx, validTarget, options)
}

// GetSupportedVulnerabilitiesByScanner 获取指定扫描器支持的漏洞类型
// 查询特定扫描器能够检测的漏洞类型
func (sm *ScannerManager) GetSupportedVulnerabilitiesByScanner(scannerName string) ([]string, error) {
	scanner, err := sm.GetScanner(scannerName)
	if err != nil {
		return nil, err
	}

	return scanner.GetSupportedVulnerabilities(), nil
}

// ScanMultiple 批量扫描多个目标
// 支持并发扫描多个目标，提高扫描效率
// 这是通用扫描工具的主要入口方法
func (sm *ScannerManager) ScanMultiple(scannerName string, targets []string, options vulns.ScanOptions) ([]common.Vulnerability, error) {
	// 使用默认上下文调用ScanMultipleWithContext
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return sm.ScanMultipleWithContext(ctx, scannerName, targets, options)
}

// ScanMultipleWithContext 批量扫描多个目标（支持上下文取消）
// 支持并发扫描多个目标，提高扫描效率
// 这是通用扫描工具的主要入口方法，支持外部取消信号
func (sm *ScannerManager) ScanMultipleWithContext(ctx context.Context, scannerName string, targets []string, options vulns.ScanOptions) ([]common.Vulnerability, error) {
	var allVulnerabilities []common.Vulnerability
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var errors []string

	// 确保Logger已设置
	if options.Logger == nil {
		options.Logger = logger.NewDefaultLogger()
	}

	// 批量验证URLs
	validURLs, invalidURLs := utils.ValidateURLs(targets)

	// 记录URL验证结果
	if len(invalidURLs) > 0 {
		options.Logger.Warn(fmt.Sprintf("发现 %d 个无效URL，将跳过这些目标", len(invalidURLs)), logger.LogContext{
			ScannerName: scannerName,
			Timestamp:   time.Now(),
		})

		// 记录每个无效URL的错误信息
		for rawURL, errMsg := range invalidURLs {
			options.Logger.Error(fmt.Sprintf("无效URL: %s - %s", rawURL, errMsg), nil, logger.LogContext{
				ScannerName: scannerName,
				Timestamp:   time.Now(),
			})

			mutex.Lock()
			errors = append(errors, fmt.Sprintf("URL %s 无效: %s", rawURL, errMsg))
			mutex.Unlock()
		}
	}

	if len(validURLs) == 0 {
		return nil, &vulns.ScanError{
			Type:    vulns.ErrorTypeTarget,
			Message: "没有有效的URL可扫描",
			Err:     fmt.Errorf("所有目标URL都无效"),
		}
	}

	// 记录即将扫描的有效URL数量
	options.Logger.Info(fmt.Sprintf("将扫描 %d 个有效URL", len(validURLs)), logger.LogContext{
		ScannerName: scannerName,
		Timestamp:   time.Now(),
	})

	// 确保线程数有效（最小为1，最大为100）
	threads := options.Threads
	if threads <= 0 {
		threads = 1
	} else if threads > 100 {
		threads = 100
	}

	// 创建通道来控制并发数，防止过多并发导致资源耗尽
	semaphore := make(chan struct{}, threads)

	// 创建带超时的上下文，防止长时间挂起，同时合并外部上下文
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), time.Duration(options.Timeout)*time.Second*2)
	defer timeoutCancel()

	// 创建上下文合并，当任一上下文被取消时都会触发
	mergedCtx, mergedCancel := context.WithCancel(ctx)
	defer mergedCancel()

	// 只扫描有效的URL
	for _, target := range validURLs {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			// 检查上下文是否已被取消
			select {
			case <-mergedCtx.Done():
				mutex.Lock()
				errors = append(errors, fmt.Sprintf("扫描目标 %s 时上下文已取消: %v", t, mergedCtx.Err()))
				mutex.Unlock()
				return
			case <-timeoutCtx.Done():
				mutex.Lock()
				errors = append(errors, fmt.Sprintf("扫描目标 %s 时超时: %v", t, timeoutCtx.Err()))
				mutex.Unlock()
				return
			default:
			}

			// 获取信号量许可，控制并发数量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 执行单个目标的扫描
			vulns, err := sm.ScanWithScanner(scannerName, t, options)
			if err != nil {
				mutex.Lock()
				errors = append(errors, fmt.Sprintf("扫描目标 %s 时出错: %v", t, err))
				mutex.Unlock()
			} else {
				mutex.Lock()
				allVulnerabilities = append(allVulnerabilities, vulns...)
				mutex.Unlock()
			}
		}(target)
	}

	// 等待所有goroutine完成或任一上下文被取消
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// 正常完成
	case <-mergedCtx.Done():
		// 上下文被外部取消
		mutex.Lock()
		errors = append(errors, fmt.Sprintf("扫描被外部取消: %v", mergedCtx.Err()))
		mutex.Unlock()
	case <-timeoutCtx.Done():
		// 扫描超时
		mutex.Lock()
		errors = append(errors, fmt.Sprintf("扫描超时: %v", timeoutCtx.Err()))
		mutex.Unlock()
	}

	if len(errors) > 0 {
		// 只返回第一个错误，但打印所有错误
		for _, err := range errors {
			fmt.Println(err)
		}
	}

	return allVulnerabilities, nil
}

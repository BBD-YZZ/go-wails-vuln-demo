import React, { useState, useEffect } from 'react';
import '../App.css';
import ProxySettingsModal from './ProxySettingsModal';
import { SetProxyConfig } from '../../wailsjs/go/main/App';

interface ProxyConfig {
  type: string;
  address: string;
  port: string;
  username?: string;
  password?: string;
  enabled: boolean;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
}

interface ScanOptions {
  scanType: string;
  threads: number;
  timeout: number;
  proxy: ProxyConfig;
}

interface TargetInputSectionProps {
  onStartScan: (targets: string[], options: ScanOptions) => void;
  isScanning: boolean;
  onStopScan?: () => void;
  onTestConnection?: (target: string, proxy: ProxyConfig) => Promise<boolean>;
  scanProgress?: number;
  onProxyConfigChange?: (config: ProxyConfig) => void;
  showProxyModal?: boolean;
  onShowProxyModal?: (show: boolean) => void;
  proxyConfig?: ProxyConfig;
  showAlert?: (message: string) => void;
  showConfirm?: (message: string, callback: (result: boolean) => void) => void;
}

const TargetInputSection: React.FC<TargetInputSectionProps> = ({ 
  onStartScan, 
  isScanning, 
  onStopScan,
  onTestConnection,
  scanProgress,
  onProxyConfigChange,
  showProxyModal,
  onShowProxyModal,
  proxyConfig: propProxyConfig,
  showAlert,
  showConfirm
}) => {
  const [targets, setTargets] = useState<string>('');
  const [scanType, setScanType] = useState<string>('all');
  const [threads, setThreads] = useState<number>(10);
  const [timeout, setTimeout] = useState<number>(30);

  const [vulnTypeLabels, setVulnTypeLabels] = useState<Record<string, string>>({});
  const [progress, setProgress] = useState<number>(0);
  
  // 使用从父组件传入的代理配置，如果没有则使用默认值
  const [localProxyConfig, setLocalProxyConfig] = useState<ProxyConfig>(propProxyConfig || {
    type: 'http',
    address: '127.0.0.1',
    port: '8080',
    username: '',
    password: '',
    enabled: false,
    headers: {},
    cookies: {},
  });
  
  // 根据是否有传入的配置决定使用哪个代理配置
  const proxyConfig = propProxyConfig || localProxyConfig;
  
  useEffect(() => {
    const fetchVulnTypes = async () => {
      try {
        const { GetVulnerabilityTypeLabels } = await import('../../wailsjs/go/main/App');
        const labels = await GetVulnerabilityTypeLabels();
        setVulnTypeLabels(labels);
      } catch (error) {
        console.error('获取漏洞类型标签失败:', error);
        // 设置默认值
        setVulnTypeLabels({
          "all": "全部漏洞",
        });
      }
    };
    
    fetchVulnTypes();
  }, []);

  // 更新进度条
  useEffect(() => {
    if (typeof scanProgress === 'number') {
      setProgress(scanProgress);
    }
  }, [scanProgress]);

  // URL验证函数
  const validateURL = (url: string): { valid: boolean; message: string; formatted?: string } => {
    url = url.trim();
    if (url === '') {
      return { valid: false, message: 'URL不能为空' };
    }

    // 检查是否有协议头
    const hasProtocol = url.startsWith('http://') || url.startsWith('https://') || url.startsWith('ftp://') || url.startsWith('sftp://');
    
    // 特殊情况：检查协议头格式是否正确
    if (url.startsWith('http:')) {
      if (!url.startsWith('http://')) {
        return { valid: false, message: 'URL协议头格式错误' };
      }
    } else if (url.startsWith('https:')) {
      if (!url.startsWith('https://')) {
        return { valid: false, message: 'URL协议头格式错误' };
      }
    }
    
    // 检查是否有缺少冒号的协议头（如 http// 或 https//）
    if (url.startsWith('http//')) {
      return { valid: false, message: 'URL协议头格式错误' };
    } else if (url.startsWith('https//')) {
      return { valid: false, message: 'URL协议头格式错误' };
    }
    
    // 尝试解析URL
    try {
      const parsedURL = new URL(hasProtocol ? url : `http://${url}`);
      
      // 检查主机名是否有效
      if (!parsedURL.hostname || parsedURL.hostname === '') {
        return { valid: false, message: 'URL主机名无效' };
      }
      
      // 额外检查IP地址格式（可选）
      // 如果主机名是IP地址，检查是否是有效的IPv4格式
      if (/^\d+(\.\d+)*$/.test(parsedURL.hostname)) {
        const parts = parsedURL.hostname.split('.');
        if (parts.length < 2 || parts.length > 4) {
          return { valid: false, message: 'URL主机名（IP地址）格式无效' };
        }
        for (const part of parts) {
          const num = parseInt(part);
          if (isNaN(num) || num < 0 || num > 255) {
            return { valid: false, message: 'URL主机名（IP地址）格式无效' };
          }
        }
      }
      
      return { 
        valid: true, 
        message: 'URL有效', 
        formatted: hasProtocol ? url : `http://${url}` 
      };
    } catch (error) {
      return { valid: false, message: 'URL格式无效' };
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // 分割字符串并去除反引号和空行
    const rawTargetList = targets.split('\n');
    const targetList = rawTargetList.map(t => t.trim().replace(/`/g, '')).filter(t => t !== '');
    
    if (targetList.length === 0) {
      if (showAlert) {
        showAlert('请输入至少一个目标地址');
      }
      return;
    }
    
    // 在前端进行URL验证，提供即时反馈
    const invalidURLs: string[] = [];
    const validURLs: string[] = [];
    
    for (const url of targetList) {
      const validation = validateURL(url);
      if (validation.valid) {
        validURLs.push(validation.formatted || url);
      } else {
        invalidURLs.push(url.trim());
      }
    }
    
    // 定义开始扫描的函数
    const startScan = () => {
      if (validURLs.length > 0 && onStartScan) {
        onStartScan(validURLs, {
          scanType,
          threads,
          timeout,
          proxy: proxyConfig
        });
      }
    };
    
    if (invalidURLs.length > 0) {
      // 如果有有效的URL，可以选择继续扫描
      if (validURLs.length > 0) {
        console.log('发现无效URL，准备显示确认提示');
        console.log('有效URL列表:', validURLs);
        console.log('无效URL列表:', invalidURLs);
        
        // 保存当前状态到闭包中
        const currentValidURLs = [...validURLs];
        const currentScanType = scanType;
        const currentThreads = threads;
        const currentTimeout = timeout;
        const currentProxyConfig = proxyConfig;
        
        if (showConfirm) {
          console.log('使用自定义确认提示框');
          // 创建回调函数
          const callback = (shouldContinue: boolean) => {
            console.log('确认回调函数被调用，结果:', shouldContinue);
            if (shouldContinue && onStartScan) {
              console.log('准备开始扫描，有效URL:', currentValidURLs);
              // 直接调用onStartScan，确保使用当前状态
              onStartScan(currentValidURLs, {
                scanType: currentScanType,
                threads: currentThreads,
                timeout: currentTimeout,
                proxy: currentProxyConfig
              });
            }
          };
          
          // 使用自定义的确认提示框
          showConfirm(`发现${invalidURLs.length}个无效URL。是否继续扫描其余${currentValidURLs.length}个有效URL？`, callback);
        } else {
          // 降级使用原生confirm
          const shouldContinue = confirm(`发现${invalidURLs.length}个无效URL。是否继续扫描其余${validURLs.length}个有效URL？`);
          if (!shouldContinue) {
            return;
          }
          startScan();
        }
      } else {
        // 没有有效的URL，显示所有无效URL
        let errorMessage = '';
        if (invalidURLs.length === 1) {
          errorMessage = `URL无效: ${invalidURLs[0]}`;
        } else {
          errorMessage = `发现${invalidURLs.length}个无效URL:\n${invalidURLs.join('\n')}`;
        }
        
        if (showAlert) {
          showAlert(errorMessage);
        } else {
          alert(errorMessage);
        }
        // 没有有效的URL，直接返回
        return;
      }
    } else {
      // 所有URL都有效，直接开始扫描
      onStartScan(validURLs, {
        scanType,
        threads,
        timeout,
        proxy: proxyConfig
      });
    }
  };

  const handleStop = () => {
    if (onStopScan) {
      onStopScan();
    }
  };

  const handleOpenProxySettings = () => {
    if (onShowProxyModal) {
      onShowProxyModal(true);
    }
  };

  const handleSaveProxySettings = async (config: ProxyConfig) => {
    // 更新本地状态
    setLocalProxyConfig(config);
    
    // 如果有传入的回调函数，也调用它
    if (onShowProxyModal) {
      onShowProxyModal(false);
    }
    
    // 更新后端代理配置，确保所有字段都有默认值
    const backendConfig = {
      ...config,
      username: config.username || '',
      password: config.password || '',
      headers: config.headers || {},
      cookies: config.cookies || {}
    };
    
    // 更新后端代理配置
    try {
      await SetProxyConfig(backendConfig);
      
      // 获取最新的日志以显示代理设置保存结果
      if (window.parent && (window.parent as any).GetLogs) {
        // 如果有父组件的日志更新函数，调用它
        try {
          const { GetLogs } = await import('../../wailsjs/go/main/App');
          const logs = await GetLogs();
          if (logs && logs.length > 0) {
            // 将最新的日志转换为前端格式
            const formattedLogs = logs.map((log: any) => {
              let logStr = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.level}: ${log.message}`;
              
              // 检查是否有上下文信息
              if (log.context) {
                const ctx = log.context;
                if (ctx.target) logStr += ` [Target: ${ctx.target}]`;
                if (ctx.scannerName) logStr += ` [Scanner: ${ctx.scannerName}]`;
                if (ctx.vulnerabilityType) logStr += ` [VulnType: ${ctx.vulnerabilityType}]`;
                if (ctx.step) logStr += ` [Step: ${ctx.step}]`;
                
                // 检查是否有额外信息
                if (ctx.extra && Object.keys(ctx.extra).length > 0) {
                  logStr += '\n    ';
                  const extraInfo = [];
                  for (const [key, value] of Object.entries(ctx.extra)) {
                    if (key === 'headers') {
                      // 格式化显示headers
                      const headers = value as Record<string, string>;
                      const headerStr = Object.entries(headers)
                        .map(([hKey, hValue]) => `${hKey}=${hValue}`)
                        .join(', ');
                      extraInfo.push(`Headers: ${headerStr}`);
                    } else if (key === 'body') {
                      // 单独显示body
                      extraInfo.push(`Body: ${value}`);
                    } else {
                      extraInfo.push(`${key}: ${value}`);
                    }
                  }
                  logStr += extraInfo.join('\n    ');
                }
              }
              
              return logStr;
            });
            // 通知父组件更新日志
            console.log('Updated logs after saving proxy settings:', formattedLogs);
          }
        } catch (logError) {
          console.error('获取最新日志失败:', logError);
        }
      }
    } catch (error) {
      console.error('更新后端代理配置失败:', error);
    }
    
    // 通知父组件代理配置已更改
    if (onProxyConfigChange) {
      onProxyConfigChange(config);
    }
  };


  return (
    <section className="input-section">
      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <textarea
            id="targets"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="目标地址 (每行一个)，例如:
https://example.com
https://test.com
192.168.1.1:8080"
            disabled={isScanning}
            rows={5}
          />
        </div>

        <div className="input-group label-inline">
          <label htmlFor="scanType">选择漏洞类型:</label>
          <select 
            id="scanType" 
            value={scanType} 
            onChange={(e) => setScanType(e.target.value)}
            disabled={isScanning}
          >
            {Object.entries(vulnTypeLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>

        <div className="input-group label-inline">
          <label htmlFor="threads">设置并发数量:</label>
          <input
            type="number"
            id="threads"
            min="1"
            max="100"
            value={threads}
            onChange={(e) => setThreads(parseInt(e.target.value))}
            disabled={isScanning}
          />
        </div>

        <div className="input-group label-inline">
          <label htmlFor="timeout">设置超时时间:</label>
          <input
            type="number"
            id="timeout"
            min="1"
            max="300"
            value={timeout}
            onChange={(e) => setTimeout(parseInt(e.target.value))}
            disabled={isScanning}
          />
        </div>

        {/* 进度条显示 */}
        <div className="progress-container">
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <div className="progress-text">{progress}%</div>
        </div>

        <div className="button-group-aligned">
          <button 
            type="submit" 
            className={`primary-btn ${isScanning ? 'disabled' : ''}`}
            disabled={isScanning}
          >
            {isScanning ? '扫描中...' : '开始扫描'}
          </button>
          <button 
            type="button" 
            className="secondary-btn"
            onClick={handleStop}
            disabled={!isScanning}
          >
            停止扫描
          </button>
          <button 
            type="button" 
            className="settings-btn"
            onClick={handleOpenProxySettings}
          >
            代理设置
          </button>
        </div>
      </form>
      
      {/* 免责声明 */}
      <div className="disclaimer">
        <p className="disclaimer-title">免责声明</p>
        <p className="disclaimer-text">1. 合法授权限定：仅用于已获书面授权的安全研究场景（如漏洞验证、防护测试），禁止未经授权的渗透行为。</p>
        <p className="disclaimer-text">2. 责任自负原则：所有操作后果由使用者独立承担法律责任及民事赔偿，开发者不承担任何连带责任。</p>
      </div>

    </section>
  );
};

export default TargetInputSection;
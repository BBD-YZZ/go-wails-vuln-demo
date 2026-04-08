import React, { useState, useEffect, useRef } from 'react';
import './App.css';
import TargetInputSection from './components/TargetInputSection';
import ScanResultsSection from './components/ScanResultsSection';
import ScanLogSection from './components/ScanLogSection';
import StatusBar from './components/StatusBar';
import ProxySettingsModal from './components/ProxySettingsModal';
import { StartScan, GetLogs, TestConnection, GetScanProgress, StopScan, ClearLogs, ExportResultsToExcel, GetTempScanResults, ExecuteCommand, StartReverseShell, InjectMemoryShell } from '../wailsjs/go/main/App';

// 定义漏洞类型
interface Vulnerability {
  id: number;
  vulnerabilityType: string;
  severity: string;
  target: string;
  url: string;
  payload: string;
  description: string;
  proof: string;
  recommendation: string;
  responseHeaders?: Record<string, string>;
  responseContent?: string;
  supportedFeatures?: string[];
}

// 定义代理配置类型 - 与后端保持一致
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

// 定义扫描选项类型
interface ScanOptions {
  scanType: string;
  threads: number;
  timeout: number;
  proxy: ProxyConfig;
}

function App() {
  const [scanResults, setScanResults] = useState<Vulnerability[]>([]);
  const [tempScanResults, setTempScanResults] = useState<Vulnerability[]>([]);
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>('就绪');
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [isProxyEnabled, setIsProxyEnabled] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'scan' | 'info' | 'command' | 'shell' | 'memory'>('scan');
    
  const [showProxyModal, setShowProxyModal] = useState<boolean>(false);
  const [proxyConfig, setProxyConfig] = useState<ProxyConfig>({
    type: 'http',
    address: '',
    port: '8080',
    username: '',
    password: '',
    enabled: false,
    headers: {},
    cookies: {}
  });
  const [showAlert, setShowAlert] = useState<boolean>(false);
  const [alertMessage, setAlertMessage] = useState<string>('');
  
  // 自定义确认提示框状态
  const [showConfirm, setShowConfirm] = useState<boolean>(false);
  const [confirmMessage, setConfirmMessage] = useState<string>('');
  const [confirmCallback, setConfirmCallback] = useState<(result: boolean) => void>(() => {});
  
  // 显示确认提示框的函数
  const showCustomConfirm = (message: string, callback: (result: boolean) => void) => {
    console.log('showCustomConfirm called with message:', message);
    console.log('Callback function:', callback);
    setConfirmMessage(message);
    // 使用useState的函数形式确保设置正确的回调函数
    setConfirmCallback(() => {
      console.log('Confirm callback set up');
      return callback;
    });
    setShowConfirm(true);
  };
  // 为每个功能创建单独的选中漏洞状态
  const [selectedCommandVulnerability, setSelectedCommandVulnerability] = useState<Vulnerability | null>(null);
  const [selectedShellVulnerability, setSelectedShellVulnerability] = useState<Vulnerability | null>(null);
  const [selectedMemoryVulnerability, setSelectedMemoryVulnerability] = useState<Vulnerability | null>(null);
  
  // 当扫描结果更新时，自动设置默认的选中漏洞
  useEffect(() => {
    if (scanResults.length > 0) {
      // 为命令执行设置默认漏洞
      const commandVuln = scanResults.find(vuln => vuln.supportedFeatures && vuln.supportedFeatures.includes('command'));
      if (commandVuln) {
        setSelectedCommandVulnerability(commandVuln);
      }
      
      // 为反弹shell设置默认漏洞
      const shellVuln = scanResults.find(vuln => vuln.supportedFeatures && vuln.supportedFeatures.includes('shell'));
      if (shellVuln) {
        setSelectedShellVulnerability(shellVuln);
      }
      
      // 为注入内存马设置默认漏洞
      const memoryVuln = scanResults.find(vuln => vuln.supportedFeatures && vuln.supportedFeatures.includes('memory'));
      if (memoryVuln) {
        setSelectedMemoryVulnerability(memoryVuln);
      }
    }
  }, [scanResults]);
  
  // 当选中的内存马漏洞变化时，获取支持的内存马类型
  useEffect(() => {
    if (selectedMemoryVulnerability) {
      // 调用后端API获取支持的内存马类型
      const fetchMemoryShellTypes = async () => {
        try {
          const { GetMemoryShellTypes } = await import('../wailsjs/go/main/App');
          const types = await GetMemoryShellTypes(selectedMemoryVulnerability.id);
          // 类型转换：将Record<string, string>[]转换为{value: string, label: string}[]
          const convertedTypes = (types || []).map((type: Record<string, string>) => ({
            value: type.value || '',
            label: type.label || ''
          }));
          setMemoryShellTypes(convertedTypes);
          // 如果有默认类型，设置第一个为默认值
          if (convertedTypes && convertedTypes.length > 0) {
            setMemoryShellType(convertedTypes[0].value);
          }
        } catch (error) {
          console.error('获取内存马类型失败:', error);
          setMemoryShellTypes([]);
        }
      };
      
      fetchMemoryShellTypes();
    } else {
      setMemoryShellTypes([]);
    }
  }, [selectedMemoryVulnerability]);
  
  // 执行命令相关状态
  const [command, setCommand] = useState<string>('');
  const [commandResults, setCommandResults] = useState<string[]>([]);
  const [isExecutingCommand, setIsExecutingCommand] = useState<boolean>(false);
  
  // 反弹shell相关状态
  const [shellHost, setShellHost] = useState<string>('');
  const [shellPort, setShellPort] = useState<string>('');
  const [shellStatus, setShellStatus] = useState<string>('');
  const [isStartingShell, setIsStartingShell] = useState<boolean>(false);
  
  // 注入内存马相关状态
  const [memoryShellType, setMemoryShellType] = useState<string>('jsp');
  const [memoryShellPassword, setMemoryShellPassword] = useState<string>('rebeyond');
  const [memoryShellPath, setMemoryShellPath] = useState<string>('/');
  const [memoryShellStatus, setMemoryShellStatus] = useState<string>('');
  const [isInjectingMemoryShell, setIsInjectingMemoryShell] = useState<boolean>(false);
  const [memoryShellTypes, setMemoryShellTypes] = useState<{value: string, label: string}[]>([]);
  
  // 模态框显示状态
  const [showVulnerabilityDetails, setShowVulnerabilityDetails] = useState<boolean>(false);
  // 用于漏洞详情模态框的选中漏洞状态
  const [modalSelectedVulnerability, setModalSelectedVulnerability] = useState<Vulnerability | null>(null);
  
  const openVulnerabilityDetails = (vuln: Vulnerability) => {
    setModalSelectedVulnerability(vuln);
    setShowVulnerabilityDetails(true);
  };

  const closeVulnerabilityDetails = () => {
    setModalSelectedVulnerability(null);
    setShowVulnerabilityDetails(false);
  };
  
  const getSeverityClass = (severity: string) => {
    switch(severity) {
      case '严重':
        return 'severity-critical';
      case '高危':
        return 'severity-high';
      case '中危':
        return 'severity-medium';
      case '低危':
        return 'severity-low';
      default:
        return 'severity-low';
    }
  };

  // 更新代理状态
  const handleProxyConfigChange = (config: ProxyConfig) => {
    setIsProxyEnabled(config.enabled);
    // 只有在非扫描状态时才更新状态消息
    if (!isScanning) {
      if (config.enabled) {
        setStatusMessage(`代理已启用: ${config.type.toUpperCase()}://${config.address}:${config.port}`);
      } else {
        setStatusMessage('就绪');
      }
    }
  };
  
  // 保存代理设置
  const handleSaveProxySettings = async (config: ProxyConfig) => {
    setProxyConfig(config);
    setShowProxyModal(false);
    
    // 更新后端代理配置，确保所有字段都有默认值
    const backendConfig = {
      ...config,
      username: config.username || '',
      password: config.password || '',
      headers: config.headers || {},
      cookies: config.cookies || {}
    };
    
    try {
      const { SetProxyConfig } = await import('../wailsjs/go/main/App');
      await SetProxyConfig(backendConfig);
      
      // 更新代理状态
      handleProxyConfigChange(config);
    } catch (error) {
      console.error('更新后端代理配置失败:', error);
    }
  };

  // 实际扫描过程
  const handleStartScan = async (targets: string[], options: ScanOptions) => {
    // 检查目标地址是否为空
    if (targets.length === 0) {
      setAlertMessage('请输入至少一个目标地址');
      setShowAlert(true);
      setIsScanning(false); // 确保扫描状态为false
      return;
    }
    
    // 自动切换到结果日志标签页
    setActiveTab('scan');

    setIsScanning(true);
    setIsProxyEnabled(options.proxy.enabled);
    const proxyInfo = options.proxy.enabled ? ` (代理: ${options.proxy.type.toUpperCase()}://${options.proxy.address}:${options.proxy.port})` : '';
    setStatusMessage(`正在扫描...${proxyInfo}`);
    setScanProgress(0);
    
    // 清空之前的扫描结果，但保留日志以便查看历史信息
    setScanResults([]);
    // 不清空日志，让日志持续累积显示
    
    // 清空反弹shell和注入内存马的输出状态
    setShellStatus('');
    setMemoryShellStatus('');
    
    try {
      // 调用后端开始扫描
      const scanOptions = new (await import('../wailsjs/go/models')).main.ScanOptions({
        targets: targets,
        scanType: options.scanType,
        threads: options.threads,
        timeout: options.timeout,
        proxy: {
          ...options.proxy,
          headers: options.proxy.headers || {},
          cookies: options.proxy.cookies || {},
          username: options.proxy.username || '',
          password: options.proxy.password || ''
        }
      });
      
      // 启动定时器定期获取日志、进度和临时结果
      let scanInterval: number | null = null;
      
      // 在后台启动扫描，不阻塞定时器
      const scanPromise = StartScan(scanOptions);
      
      // 启动定时器，持续获取日志直到扫描完成
      scanInterval = setInterval(async () => {
        try {
          // 获取日志
          const logs = await GetLogs();
          if (logs && logs.length > 0) {
            // 将后端日志转换为前端格式
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
            setScanLogs(formattedLogs);
          }
          
          // 获取扫描进度
          const progress = await GetScanProgress();
          setScanProgress(progress);
          
          // 获取临时扫描结果
          const tempResults = await GetTempScanResults();
          if (tempResults && tempResults.length > 0) {
            setScanResults(tempResults);
          }
          
          // 检查扫描是否完成
          if (progress >= 100) {
            if (scanInterval) {
              clearInterval(scanInterval);
              scanInterval = null;
            }
          }
        } catch (error) {
          console.error('获取日志、进度或临时结果失败:', error);
        }
      }, 200); // 每200ms获取一次，提高实时性
      
      // 等待扫描完成
      const results = await scanPromise;
      
      // 停止定时器
      if (scanInterval) {
        clearInterval(scanInterval);
      }
      
      // 最后获取一次完整的日志、进度和结果
      try {
        const finalLogs = await GetLogs();
        if (finalLogs && finalLogs.length > 0) {
          // 将后端日志转换为前端格式
          const formattedLogs = finalLogs.map((log: any) => {
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
          setScanLogs(formattedLogs);
        }
        
        const finalProgress = await GetScanProgress();
        setScanProgress(finalProgress);
        
        const finalResults = await GetTempScanResults();
        if (finalResults && finalResults.length > 0) {
          setScanResults(finalResults);
        } else {
          setScanResults(results);
        }
      } catch (error) {
        console.error('获取最终结果失败:', error);
        setScanResults(results);
      }
      
      setIsScanning(false);
      setScanProgress(100);
      setStatusMessage(`扫描完成，发现 ${results.length} 个漏洞${proxyInfo}`);
    } catch (error) {
      console.error('扫描失败:', error);
      setIsScanning(false);
      setScanProgress(0);
      
      // 显示具体的错误消息
      let errorMessage = '扫描失败';
      if (error instanceof Error) {
        errorMessage = error.message;
        // 检查是否包含无效URL的错误信息
        if (errorMessage.includes('TARGET') || errorMessage.includes('URL') || errorMessage.includes('目标')) {
          // 这是URL验证错误，直接显示给用户
          setAlertMessage(errorMessage);
          setShowAlert(true);
        }
      }
      
      setStatusMessage(errorMessage);
    }
  };

  // 停止扫描功能
  const handleStopScan = async () => {
    if (!isScanning) {
      // 如果没有扫描任务，直接返回，不执行任何操作
      return;
    }
    
    try {
      await StopScan();
      setIsScanning(false);
      setStatusMessage('扫描已停止');
    } catch (error) {
      console.error('停止扫描失败:', error);
      setStatusMessage('停止扫描失败');
    }
  };

  // 测试连接功能
  // 清除日志功能
  const handleClearLogs = async () => {
    try {
      await ClearLogs();
      setScanLogs([]); // 清空前端日志显示
      setStatusMessage('日志已清除');
    } catch (error) {
      console.error('清除日志失败:', error);
      setStatusMessage('清除日志失败');
    }
  };

  // 清除扫描结果功能
  const handleClearResults = () => {
    setScanResults([]);
    setTempScanResults([]);
    setStatusMessage('扫描结果已清除');
  };
  
  // 测试连接功能
  const handleTestConnection = async (target: string, proxy: ProxyConfig) => {
    const proxyInfo = proxy.enabled ? ` (代理: ${proxy.type.toUpperCase()}://${proxy.address}:${proxy.port})` : '';
    
    // 立即获取一次日志，以便显示测试连接的实时日志
    const fetchLogsImmediately = async () => {
      try {
        const logs = await GetLogs();
        if (logs && logs.length > 0) {
          // 将后端日志转换为前端格式
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
          setScanLogs(formattedLogs);
        }
      } catch (error) {
        console.error('获取日志失败:', error);
      }
    };
    
    // 在测试连接期间启动日志轮询
    const logInterval = setInterval(fetchLogsImmediately, 500); // 每500毫秒获取一次日志
    
    try {
      const result = await TestConnection(target, {
        ...proxy,
        headers: proxy.headers || {},
        cookies: proxy.cookies || {},
        username: proxy.username || '',
        password: proxy.password || ''
      });
      
      // 再获取一次日志，确保显示最新的测试结果
      await fetchLogsImmediately();
      
      if (Array.isArray(result) && result.length >= 2) {
        const [success, message] = result;
        if (success) {
          setStatusMessage(`连接测试成功: ${message}${proxyInfo}`);
        } else {
          setStatusMessage(`连接测试失败: ${message}${proxyInfo}`);
        }
        return success;
      } else {
        // 如果结果不是数组，根据结果的真值性来判断
        const success = !!result;
        setStatusMessage(`连接测试${success ? '成功' : '失败'}: ${result}${proxyInfo}`);
        return success;
      }
    } catch (error) {
      console.error('连接测试失败:', error);
      setStatusMessage(`连接测试失败: ${(error as Error).message}${proxyInfo}`);
      return false;
    } finally {
      // 停止日志轮询
      clearInterval(logInterval);
      // 最后再获取一次日志
      setTimeout(fetchLogsImmediately, 100);
    }
  };
  

  
  return (
    <div id="App" className="app-container">
      <header className="app-header">
        <h1>漏洞扫描工具</h1>
      </header>
      
      <main className="app-main">
        {/* 左侧扫描设置区域 */}
        <aside className="settings-panel">
          <div className="input-section-wrapper">
            <h2>扫描配置</h2>
            <TargetInputSection 
              onStartScan={handleStartScan} 
              isScanning={isScanning} 
              onStopScan={handleStopScan}
              onTestConnection={handleTestConnection}
              scanProgress={scanProgress}
              onProxyConfigChange={handleProxyConfigChange}
              showProxyModal={showProxyModal}
              onShowProxyModal={setShowProxyModal}
              proxyConfig={proxyConfig}
              showAlert={(message: string) => { setAlertMessage(message); setShowAlert(true); }}
              showConfirm={showCustomConfirm}
            />
          </div>
        </aside>
        
        {/* 右侧内容区域 - 标签页布局 */}
        <div className="content-panel">
          {/* 标签页头部 */}
          <div className="tab-header">
            <button 
              className={`tab-button ${activeTab === 'scan' ? 'active' : ''}`}
              onClick={() => setActiveTab('scan')}
            >
              结果日志
            </button>
            <button 
              className={`tab-button ${activeTab === 'command' ? 'active' : ''}`}
              onClick={() => setActiveTab('command')}
            >
              执行命令
            </button>
            <button 
              className={`tab-button ${activeTab === 'shell' ? 'active' : ''}`}
              onClick={() => setActiveTab('shell')}
            >
              反弹shell
            </button>
            <button 
              className={`tab-button ${activeTab === 'memory' ? 'active' : ''}`}
              onClick={() => setActiveTab('memory')}
            >
              注入内存马
            </button>
            <button 
              className={`tab-button ${activeTab === 'info' ? 'active' : ''}`}
              onClick={() => setActiveTab('info')}
            >
              工具信息
            </button>
          </div>
          
          {/* 标签页内容 */}
          <div className="tab-content">
            {activeTab === 'scan' ? (
              <div className="scan-content">
                <div className="results-and-logs-container">
                  {/* 扫描结果区域 */}
                  <ScanResultsSection 
                    results={scanResults}
                    onVulnerabilitySelect={openVulnerabilityDetails}
                    onClearResults={handleClearResults}
                  />
                  
                  {/* 扫描日志区域 */}
                  <ScanLogSection logs={scanLogs} onClearLogs={handleClearLogs} />
                </div>
              </div>
            ) : activeTab === 'command' ? (
              <div className="command-content">
                <div className="tool-section">
                  <h2>执行命令</h2>
                  <div className="tool-content">
                    {(() => {
                      // 查找支持命令执行的漏洞
                      const supportedVulns = scanResults.filter(vuln => 
                        vuln.supportedFeatures && vuln.supportedFeatures.includes('command')
                      );
                      
                      // 检查是否有支持的漏洞
                      if (supportedVulns.length > 0) {
                        return supportedVulns;
                      }
                      
                      return null;
                    })() ? (
                      <>
                        <div className="vulnerability-info">
                          <div className="form-row" style={{alignItems: 'center', gap: '0px'}}>
                            <div className="form-item" style={{flex: '0 0 auto', minWidth: '150px'}}>
                              <label htmlFor="command-vuln-select">支持命令执行的漏洞:</label>
                            </div>
                            <div className="form-item" style={{flex: 1, minWidth: 0}}>
                              <select
                                id="command-vuln-select"
                                className="vuln-select"
                                value={selectedCommandVulnerability?.id || ''}
                                onChange={(e) => {
                                  const selectedId = parseInt(e.target.value);
                                  const selectedVuln = scanResults.find(vuln => vuln.id === selectedId);
                                  if (selectedVuln) {
                                    setSelectedCommandVulnerability(selectedVuln);
                                    // 切换漏洞时清空之前的命令执行结果
                                    setCommandResults([]);
                                  }
                                }}
                              >
                                {scanResults
                                  .filter(vuln => vuln.supportedFeatures && vuln.supportedFeatures.includes('command'))
                                  .map(vuln => (
                                    <option key={vuln.id} value={vuln.id}>
                                      {vuln.vulnerabilityType} - {vuln.target}
                                    </option>
                                  ))}
                              </select>
                            </div>
                          </div>
                          {selectedCommandVulnerability && (
                            <div className="selected-vuln-details">
                              <div className="vuln-detail-row">
                                <span className="detail-label">漏洞类型:</span>
                                <span className="detail-value">{selectedCommandVulnerability.vulnerabilityType}</span>
                              </div>
                              <div className="vuln-detail-row">
                                <span className="detail-label">目标:</span>
                                <span className="detail-value truncate">{selectedCommandVulnerability.target}</span>
                              </div>
                            </div>
                          )}
                        </div>
                        
                        <div className="command-section">
                          <div className="form-row" style={{alignItems: 'center', marginBottom: '10px', gap: '15px'}}>
                            <div className="form-item" style={{flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', flexDirection: 'row'}}>
                              <label htmlFor="command-input" style={{marginRight: '0px', whiteSpace: 'nowrap', display: 'inline-block', verticalAlign: 'middle', lineHeight: '36px'}}>输入命令: </label>
                              <input
                                type="text"
                                id="command-input"
                                value={command}
                                onChange={(e) => setCommand(e.target.value)}
                                placeholder="例如: whoami"
                                className="vuln-select"
                                style={{flex: 1, marginLeft: '0px', display: 'inline-flex', verticalAlign: 'middle', height: '36px'}}
                              />
                            </div>
                            <div className="form-item form-item-button" style={{flex: '0 0 auto', minWidth: '120px', marginRight: '10px'}}>
                              <button 
                                className="primary-btn full-width-btn"
                                onClick={async () => {
                                  if (!command.trim()) {
                                    setAlertMessage('请输入命令');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  if (!selectedCommandVulnerability) {
                                    setAlertMessage('请选择一个漏洞');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  try {
                                    setIsExecutingCommand(true);
                                    setStatusMessage('正在执行命令...');
                                    
                                    // 调用后端API执行命令
                                    const result = await ExecuteCommand(selectedCommandVulnerability.id, command);
                                    
                                    // 获取最新日志
                                    const logs = await GetLogs();
                                    if (logs && logs.length > 0) {
                                      // 将后端日志转换为前端格式
                                      const formattedLogs = logs.map((log: any) => {
                                        let logStr = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.level}: ${log.message}`;
                                        return logStr;
                                      });
                                      setScanLogs(formattedLogs);
                                    }
                                    
                                    // 格式化执行结果，添加漏洞类型信息
                                    const formattedResult = `[${new Date().toLocaleTimeString()}] ${selectedCommandVulnerability.vulnerabilityType} - 执行命令: ${command}\n${result}`;
                                    setCommandResults(prev => [formattedResult, ...prev]);
                                    setStatusMessage('命令执行完成');
                                    setIsExecutingCommand(false);
                                  } catch (error) {
                                    console.error('执行命令失败:', error);
                                    setStatusMessage('执行命令失败');
                                    
                                    // 获取最新日志
                                    try {
                                      const logs = await GetLogs();
                                      if (logs && logs.length > 0) {
                                        // 将后端日志转换为前端格式
                                        const formattedLogs = logs.map((log: any) => {
                                          let logStr = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.level}: ${log.message}`;
                                          return logStr;
                                        });
                                        setScanLogs(formattedLogs);
                                      }
                                    } catch (logError) {
                                      console.error('获取日志失败:', logError);
                                    }
                                    
                                    // 格式化错误结果，显示在结果区域，添加漏洞类型信息
                                    const errorMessage = (error as Error).message;
                                    const formattedError = `[${new Date().toLocaleTimeString()}] ${selectedCommandVulnerability.vulnerabilityType} - 执行命令: ${command}\n错误: ${errorMessage}`;
                                    setCommandResults(prev => [formattedError, ...prev]);
                                    setIsExecutingCommand(false);
                                  }
                                }}
                                disabled={isExecutingCommand}
                              >
                                {isExecutingCommand ? '执行中...' : '执行命令'}
                              </button>
                            </div>
                            <div className="form-item form-item-button" style={{flex: '0 0 auto', minWidth: '120px'}}>
                              <button 
                                className="secondary-btn full-width-btn"
                                onClick={() => setCommandResults([])}
                                disabled={commandResults.length === 0}
                              >
                                清除结果
                              </button>
                            </div>
                          </div>
                          
                          <div className="command-results">
                            {commandResults.length === 0 ? (
                              <p className="no-results">暂无执行结果</p>
                            ) : (
                              <div className="command-results-content">
                                {commandResults.map((result, index) => (
                                  <div key={index} className="command-result-item">
                                    <pre>{result}</pre>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="alert-message">
                          <p>请先进行漏洞扫描，系统将自动检测是否支持命令执行功能。</p>
                          <p>如果支持，此界面将显示可用的漏洞列表，您可以选择漏洞执行命令。</p>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ) : activeTab === 'shell' ? (
              <div className="shell-content">
                <div className="tool-section">
                  <h2>反弹shell</h2>
                  <div className="tool-content">
                    {(() => {
                      // 查找支持反弹shell的漏洞
                      const supportedVulns = scanResults.filter(vuln => 
                        vuln.supportedFeatures && vuln.supportedFeatures.includes('shell')
                      );
                      
                      // 检查是否有支持的漏洞
                      if (supportedVulns.length > 0) {
                        return supportedVulns;
                      }
                      
                      return null;
                    })() ? (
                      <>
                        <div className="vulnerability-info">
                          <div className="form-row" style={{alignItems: 'center', gap: '0px'}}>
                            <div className="form-item" style={{flex: '0 0 auto', minWidth: '150px'}}>
                              <label htmlFor="shell-vuln-select">支持反弹shell的漏洞:</label>
                            </div>
                            <div className="form-item" style={{flex: 1, minWidth: 0}}>
                              <select
                                id="shell-vuln-select"
                                className="vuln-select"
                                value={selectedShellVulnerability?.id || ''}
                                onChange={(e) => {
                                  const selectedId = parseInt(e.target.value);
                                  const selectedVuln = scanResults.find(vuln => vuln.id === selectedId);
                                  if (selectedVuln) {
                                    setSelectedShellVulnerability(selectedVuln);
                                    setShellStatus('');
                                  }
                                }}
                              >
                                {scanResults
                                  .filter(vuln => vuln.supportedFeatures && vuln.supportedFeatures.includes('shell'))
                                  .map(vuln => (
                                    <option key={vuln.id} value={vuln.id}>
                                      {vuln.vulnerabilityType} - {vuln.target}
                                    </option>
                                  ))}
                              </select>
                            </div>
                          </div>
                          {selectedShellVulnerability && (
                            <div className="selected-vuln-details">
                              <div className="vuln-detail-row">
                                <span className="detail-label">漏洞类型:</span>
                                <span className="detail-value">{selectedShellVulnerability.vulnerabilityType}</span>
                              </div>
                              <div className="vuln-detail-row">
                                <span className="detail-label">目标:</span>
                                <span className="detail-value truncate">{selectedShellVulnerability.target}</span>
                              </div>
                            </div>
                          )}
                        </div>
                        
                        <div className="shell-section">
                          <div className="form-row" style={{alignItems: 'center', marginBottom: '10px', gap: '15px'}}>
                            <div className="form-item" style={{flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', flexDirection: 'row'}}>
                              <label htmlFor="shell-host" style={{marginRight: '0px', whiteSpace: 'nowrap', display: 'inline-block', verticalAlign: 'middle', lineHeight: '36px'}}>监听主机:</label>
                              <input
                                type="text"
                                id="shell-host"
                                value={shellHost}
                                onChange={(e) => setShellHost(e.target.value)}
                                placeholder="例如: 192.168.1.100"
                                style={{flex: 1, marginLeft: '0px', display: 'inline-flex', verticalAlign: 'middle', height: '36px'}}
                              />
                            </div>
                            <div className="form-item" style={{flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', flexDirection: 'row'}}>
                              <label htmlFor="shell-port" style={{marginRight: '0px', whiteSpace: 'nowrap', display: 'inline-block', verticalAlign: 'middle', lineHeight: '36px'}}>监听端口:</label>
                              <input
                                type="text"
                                id="shell-port"
                                value={shellPort}
                                onChange={(e) => setShellPort(e.target.value)}
                                placeholder="例如: 4444"
                                style={{flex: 1, marginLeft: '0px', display: 'inline-flex', verticalAlign: 'middle', height: '36px'}}
                              />
                            </div>
                            <div className="form-item form-item-button" style={{flex: '0 0 auto', minWidth: '120px', marginRight: '10px'}}>
                              <button 
                                className="primary-btn full-width-btn"
                                onClick={async () => {
                                  if (!shellHost.trim()) {
                                    setAlertMessage('请输入监听主机');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  if (!shellPort.trim() || isNaN(parseInt(shellPort))) {
                                    setAlertMessage('请输入有效的监听端口');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  if (!selectedShellVulnerability) {
                                    setAlertMessage('请选择一个漏洞');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  try {
                                    setIsStartingShell(true);
                                    setStatusMessage('正在启动反弹shell...');
                                    setShellStatus('正在尝试反弹shell...');
                                    
                                    // 调用后端API启动反弹shell
                                    const result = await StartReverseShell(selectedShellVulnerability.id, shellHost, shellPort);
                                    
                                    // 获取最新日志
                                    const logs = await GetLogs();
                                    if (logs && logs.length > 0) {
                                      // 将后端日志转换为前端格式
                                      const formattedLogs = logs.map((log: any) => {
                                        let logStr = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.level}: ${log.message}`;
                                        return logStr;
                                      });
                                      setScanLogs(formattedLogs);
                                    }
                                    
                                    setShellStatus(result);
                                    setStatusMessage('Shell反弹请求已发送');
                                    setIsStartingShell(false);
                                  } catch (error) {
                                    console.error('启动反弹shell失败:', error);
                                    console.error('错误详情:', JSON.stringify(error));
                                    console.error('错误类型:', typeof error);
                                    if (error && typeof error === 'object') {
                                      console.error('错误属性:', Object.keys(error));
                                    } else {
                                      console.error('错误属性: 无 (非对象类型)');
                                    }
                                    setStatusMessage('启动反弹shell失败');
                                    
                                    // 获取最新日志
                                    try {
                                      const logs = await GetLogs();
                                      if (logs && logs.length > 0) {
                                        // 将后端日志转换为前端格式
                                        const formattedLogs = logs.map((log: any) => {
                                          let logStr = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.level}: ${log.message}`;
                                          return logStr;
                                        });
                                        setScanLogs(formattedLogs);
                                      }
                                    } catch (logError) {
                                      console.error('获取日志失败:', logError);
                                    }
                                    
                                    // 优化错误处理，确保错误信息不为undefined
                                    let errorMessage = '未知错误';
                                    if (error instanceof Error) {
                                      errorMessage = error.message;
                                    } else if (typeof error === 'string') {
                                      errorMessage = error;
                                    } else if (error && typeof error === 'object') {
                                      // 尝试从error对象中获取更多信息
                                      if ('error' in error) {
                                        errorMessage = String(error.error);
                                      } else if ('message' in error) {
                                        errorMessage = String(error.message);
                                      } else if ('data' in error) {
                                        errorMessage = String(error.data);
                                      }
                                    }
                                    
                                    // 如果错误信息为空或未知，尝试从日志中获取
                                    if (errorMessage === '未知错误' || errorMessage === 'undefined' || errorMessage === '') {
                                      try {
                                        const logs = await GetLogs();
                                        if (logs && logs.length > 0) {
                                          // 查找最近的ERROR日志
                                          const errorLogs = logs.filter((log: any) => log.level === 'ERROR');
                                          if (errorLogs.length > 0) {
                                            errorMessage = errorLogs[errorLogs.length - 1].message;
                                          }
                                        }
                                      } catch (logError) {
                                        console.error('从日志获取错误信息失败:', logError);
                                      }
                                    }
                                    
                                    setShellStatus('启动反弹shell失败: ' + errorMessage);
                                    setIsStartingShell(false);
                                  }
                                }}
                                disabled={isStartingShell}
                              >
                                {isStartingShell ? '启动中...' : '启动反弹shell'}
                              </button>
                            </div>
                            <div className="form-item form-item-button" style={{flex: '0 0 auto', minWidth: '120px'}}>
                              <button 
                                className="secondary-btn full-width-btn"
                                onClick={() => setShellStatus('')}
                                disabled={!shellStatus}
                              >
                                清除状态
                              </button>
                            </div>
                          </div>
                          
                          {shellStatus && (
                            <div className="shell-status">
                              <pre>{shellStatus}</pre>
                            </div>
                          )}
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="alert-message">
                          <p>请先进行漏洞扫描，系统将自动检测是否支持反弹shell功能。</p>
                          <p>如果支持，此界面将显示可用的漏洞列表，您可以选择漏洞进行反弹shell操作。</p>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ) : activeTab === 'memory' ? (
              <div className="memory-content">
                <div className="tool-section">
                  <h2>注入内存马</h2>
                  <div className="tool-content">
                    {(() => {
                      // 查找支持注入内存马的漏洞
                      const supportedVulns = scanResults.filter(vuln => 
                        vuln.supportedFeatures && vuln.supportedFeatures.includes('memory')
                      );
                      
                      // 检查是否有支持的漏洞
                      if (supportedVulns.length > 0) {
                        return supportedVulns;
                      }
                      
                      return null;
                    })() ? (
                      <>
                        <div className="vulnerability-info">
                          <div className="form-row" style={{alignItems: 'center', gap: '0px'}}>
                            <div className="form-item" style={{flex: '0 0 auto', minWidth: '150px'}}>
                              <label htmlFor="memory-vuln-select">支持注入内存马的漏洞:</label>
                            </div>
                            <div className="form-item" style={{flex: 1, minWidth: 0}}>
                              <select
                                id="memory-vuln-select"
                                className="vuln-select"
                                value={selectedMemoryVulnerability?.id || ''}
                                onChange={(e) => {
                                  console.log('Memory select onChange:', e.target.value);
                                  const selectedId = parseInt(e.target.value);
                                  console.log('Selected ID:', selectedId);
                                  // 从 scanResults 中查找选中的漏洞
                                  const selectedVuln = scanResults.find(vuln => vuln.id === selectedId);
                                  console.log('Selected Vuln from scanResults:', selectedVuln);
                                  if (selectedVuln) {
                                    setSelectedMemoryVulnerability(selectedVuln);
                                    setMemoryShellStatus('');
                                    console.log('Selected memory vulnerability updated:', selectedVuln);
                                  } else {
                                    console.error('Selected memory vulnerability not found in scanResults:', selectedId);
                                  }
                                }}
                              >
                                {scanResults
                                  .filter(vuln => vuln.supportedFeatures && vuln.supportedFeatures.includes('memory'))
                                  .map(vuln => (
                                    <option key={vuln.id} value={vuln.id}>
                                      {vuln.vulnerabilityType} - {vuln.target}
                                    </option>
                                  ))}
                              </select>
                            </div>
                          </div>
                          {selectedMemoryVulnerability && (
                            <div className="selected-vuln-details">
                              <div className="vuln-detail-row">
                                <span className="detail-label">漏洞类型:</span>
                                <span className="detail-value">{selectedMemoryVulnerability.vulnerabilityType}</span>
                              </div>
                              <div className="vuln-detail-row">
                                <span className="detail-label">目标:</span>
                                <span className="detail-value truncate">{selectedMemoryVulnerability.target}</span>
                              </div>
                            </div>
                          )}
                        </div>
                        
                        <div className="memory-section">
                          <div className="form-row" style={{alignItems: 'center', marginBottom: '10px', gap: '15px'}}>
                            <div className="form-item" style={{flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', flexDirection: 'row'}}>
                              <label htmlFor="memory-shell-type" style={{marginRight: '0px', whiteSpace: 'nowrap', display: 'inline-block', verticalAlign: 'middle', lineHeight: '36px'}}>内存马类型:</label>
                              <select
                                id="memory-shell-type"
                                className="vuln-select"
                                value={memoryShellType}
                                onChange={(e) => setMemoryShellType(e.target.value)}
                                style={{flex: 1, marginLeft: '0px', display: 'inline-flex', verticalAlign: 'middle', height: '36px'}}
                              >
                                {memoryShellTypes.map(type => (
                                  <option key={type.value} value={type.value}>
                                    {type.label}
                                  </option>
                                ))}
                              </select>
                            </div>
                            <div className="form-item" style={{flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', flexDirection: 'row'}}>
                              <label htmlFor="memory-shell-password" style={{marginRight: '0px', whiteSpace: 'nowrap', display: 'inline-block', verticalAlign: 'middle', lineHeight: '36px'}}>访问密码:</label>
                              <input
                                type="text"
                                id="memory-shell-password"
                                value={memoryShellPassword}
                                onChange={(e) => setMemoryShellPassword(e.target.value)}
                                placeholder="例如: rebeyond"
                                style={{flex: 1, marginLeft: '0px', display: 'inline-flex', verticalAlign: 'middle', height: '36px'}}
                              />
                            </div>
                            <div className="form-item" style={{flex: 2, minWidth: 0, display: 'flex', alignItems: 'center', flexDirection: 'row'}}>
                              <label htmlFor="memory-shell-path" style={{marginRight: '0px', whiteSpace: 'nowrap', display: 'inline-block', verticalAlign: 'middle', lineHeight: '36px'}}>访问路径:</label>
                              <input
                                type="text"
                                id="memory-shell-path"
                                value={memoryShellPath}
                                onChange={(e) => setMemoryShellPath(e.target.value)}
                                placeholder="例如: /"
                                style={{flex: 1, marginLeft: '0px', display: 'inline-flex', verticalAlign: 'middle', height: '36px'}}
                              />
                            </div>
                            <div className="form-item form-item-button" style={{flex: '0 0 auto', minWidth: '120px', marginRight: '10px'}}>
                              <button 
                                className="primary-btn full-width-btn"
                                onClick={async () => {
                                  if (!memoryShellPassword.trim()) {
                                    setAlertMessage('请输入内存马密码');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  if (!memoryShellPath.trim()) {
                                    setAlertMessage('请输入内存马访问路径');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  if (!selectedMemoryVulnerability) {
                                    setAlertMessage('请选择一个漏洞');
                                    setShowAlert(true);
                                    return;
                                  }
                                  
                                  try {
                                    setIsInjectingMemoryShell(true);
                                    setStatusMessage('正在注入内存马...');
                                    setMemoryShellStatus('正在尝试注入内存马...');
                                    
                                    // 调用后端API注入内存马，传递用户选择的内存马类型
                                    const result = await InjectMemoryShell(selectedMemoryVulnerability.id, memoryShellPassword, memoryShellPath, memoryShellType);
                                    
                                    // 获取最新日志
                                    const logs = await GetLogs();
                                    if (logs && logs.length > 0) {
                                      // 将后端日志转换为前端格式
                                      const formattedLogs = logs.map((log: any) => {
                                        let logStr = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.level}: ${log.message}`;
                                        return logStr;
                                      });
                                      setScanLogs(formattedLogs);
                                    }
                                    
                                    setMemoryShellStatus(result);
                                    setStatusMessage('内存马注入请求已发送');
                                    setIsInjectingMemoryShell(false);
                                  } catch (error) {
                                    console.error('注入内存马失败:', error);
                                    setStatusMessage('注入内存马失败');
                                    
                                    // 获取最新日志
                                    try {
                                      const logs = await GetLogs();
                                      if (logs && logs.length > 0) {
                                        // 将后端日志转换为前端格式
                                        const formattedLogs = logs.map((log: any) => {
                                          let logStr = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.level}: ${log.message}`;
                                          return logStr;
                                        });
                                        setScanLogs(formattedLogs);
                                      }
                                    } catch (logError) {
                                      console.error('获取日志失败:', logError);
                                    }
                                    
                                    // 优化错误处理，确保错误信息不为undefined
                                    const errorMessage = error instanceof Error ? error.message : typeof error === 'string' ? error : '未知错误';
                                    setMemoryShellStatus('注入内存马失败: ' + errorMessage);
                                    setIsInjectingMemoryShell(false);
                                  }
                                }}
                                disabled={isInjectingMemoryShell}
                              >
                                {isInjectingMemoryShell ? '注入中...' : '注入内存马'}
                              </button>
                            </div>
                            <div className="form-item form-item-button" style={{flex: '0 0 auto', minWidth: '120px'}}>
                              <button 
                                className="secondary-btn full-width-btn"
                                onClick={() => setMemoryShellStatus('')}
                                disabled={!memoryShellStatus}
                              >
                                清除状态
                              </button>
                            </div>
                          </div>
                          
                          {memoryShellStatus && (
                            <div className="memory-shell-status">
                              <pre>{memoryShellStatus}</pre>
                            </div>
                          )}
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="alert-message">
                          <p>请先进行漏洞扫描，系统将自动检测是否支持注入内存马功能。</p>
                          <p>如果支持，此界面将显示可用的漏洞列表，您可以选择漏洞进行内存马注入操作。</p>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="info-content">
                <div className="tool-info-section">
                  <h2>工具信息</h2>
                  <div className="tool-info-layout">
                    <div className="tool-info-text">
                      <p><strong>工具名称:</strong> 漏洞扫描器</p>
                      <p><strong>工具版本:</strong> V1.0.0</p>
                      <p><strong>开发作者:</strong> YZZ-BBD</p>
                      <p><strong>主要功能:</strong> 自动化漏洞扫描与检测</p>
                      <p><strong>联系方式:</strong> security@example.com</p>
                      <p><strong>支持类型:</strong> 漏洞扫描(CVE-2022-22963 | CVE-2022-22947 | CVE-2025-55182)</p>
                    </div>
                    <div className="tool-info-qr">
                      <p>联系我们</p>
                      <img src="/wechat.png" alt="联系方式二维码" className="qr-image" onError={(e) => {
                        const target = e.target as HTMLImageElement;
                        target.style.display = 'none';
                        if(target.nextElementSibling) {
                          (target.nextElementSibling as HTMLElement).style.display = 'flex';
                        }
                      }} />
                      <div className="qr-placeholder" style={{display: 'none'}}>二维码区域</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
      
      {/* 代理设置模态框 - 移到应用根部 */}
      {showProxyModal && (
        <ProxySettingsModal
          isOpen={showProxyModal}
          onClose={() => setShowProxyModal(false)}
          onSave={handleSaveProxySettings}
          currentConfig={proxyConfig}
          onTestConnection={handleTestConnection}
        />
      )}
      
      {/* 自定义提示框 - 移到应用根部 */}
      {showAlert && (
        <div className="custom-alert-overlay">
          <div className="custom-alert">
            <div className="custom-alert-content">{alertMessage}</div>
            <div className="custom-alert-actions">
              <button className="primary-btn" onClick={() => setShowAlert(false)}>确定</button>
            </div>
          </div>
        </div>
      )}
      
      {/* 自定义确认提示框 - 移到应用根部 */}
      {showConfirm && (
        <div className="custom-alert-overlay">
          <div className="custom-alert">
            <div className="custom-alert-content">{confirmMessage}</div>
            <div className="custom-alert-actions">
              <button className="primary-btn" onClick={() => {
                console.log('确认按钮被点击');
                setShowConfirm(false);
                // 使用setTimeout确保状态更新完成后再调用回调
                setTimeout(() => {
                  console.log('调用确认回调函数');
                  confirmCallback(true);
                }, 0);
              }}>确定</button>
              <button className="secondary-btn" onClick={() => {
                console.log('取消按钮被点击');
                setShowConfirm(false);
                // 使用setTimeout确保状态更新完成后再调用回调
                setTimeout(() => {
                  console.log('调用取消回调函数');
                  confirmCallback(false);
                }, 0);
              }}>取消</button>
            </div>
          </div>
        </div>
      )}
      
      {/* 漏洞详情模态框 - 移到应用根部 */}
      {showVulnerabilityDetails && modalSelectedVulnerability && (
        <div className="modal-overlay" onClick={closeVulnerabilityDetails}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{modalSelectedVulnerability.vulnerabilityType}</h2>
              <button className="modal-close" onClick={closeVulnerabilityDetails}>
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="vuln-details-flex">
                <div className="vuln-detail-row">
                  <div className="detail-label">目标地址</div>
                  <div className="detail-value">{modalSelectedVulnerability.target}</div>
                </div>
                
                <div className="vuln-detail-row">
                  <div className="detail-label">漏洞地址</div>
                  <div className="detail-value">{modalSelectedVulnerability.url}</div>
                </div>
                
                <div className="vuln-detail-row">
                  <div className="detail-label">测试载荷</div>
                  <div className="detail-value">{modalSelectedVulnerability.payload}</div>
                </div>
                
                <div className="vuln-detail-row">
                  <div className="detail-label">漏洞描述</div>
                  <div className="detail-value">{modalSelectedVulnerability.description}</div>
                </div>
                
                <div className="vuln-detail-row">
                  <div className="detail-label">验证证据</div>
                  <div className="detail-value">{modalSelectedVulnerability.proof}</div>
                </div>
                
                <div className="vuln-detail-row">
                  <div className="detail-label">修复建议</div>
                  <div className="detail-value">{modalSelectedVulnerability.recommendation}</div>
                </div>
                
                <div className="vuln-detail-row">
                  <div className="detail-label">风险等级</div>
                  <div className="detail-value">
                    <span className={getSeverityClass(modalSelectedVulnerability.severity)}>
                      {modalSelectedVulnerability.severity}
                    </span>
                  </div>
                </div>
                
                {/* 显示响应头 */}
                {modalSelectedVulnerability.responseHeaders && Object.keys(modalSelectedVulnerability.responseHeaders).length > 0 && (
                  <div className="vuln-detail-row">
                    <div className="detail-label">响应头部</div>
                    <div className="detail-value response-details">
                      <pre className="response-headers">
                        {Object.entries(modalSelectedVulnerability.responseHeaders).map(([key, value]) => (
                          <div key={key} className="header-item">
                            <strong>{key}:</strong> {value}
                          </div>
                        ))}
                      </pre>
                    </div>
                  </div>
                )}
                
                {/* 显示响应内容 */}
                {modalSelectedVulnerability.responseContent && modalSelectedVulnerability.responseContent.length > 0 && (
                  <div className="vuln-detail-row">
                    <div className="detail-label">响应内容</div>
                    <div className="detail-value response-details">
                      <pre className="response-content">
                        {modalSelectedVulnerability.responseContent}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* 状态栏 */}
      <StatusBar 
        message={statusMessage} 
        isScanning={isScanning} 
        isProxyEnabled={isProxyEnabled}
      />
    </div>
  );
}

export default App;
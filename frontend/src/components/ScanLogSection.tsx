import React, { useEffect, useRef, useState } from 'react';
import '../App.css';

interface ScanLogSectionProps {
  logs: string[];
  onClearLogs?: () => void; // 添加清除日志的回调函数
}

const ScanLogSection: React.FC<ScanLogSectionProps> = ({ logs, onClearLogs }) => {
  const logContainerRef = useRef<HTMLDivElement>(null);
  const [showAlert, setShowAlert] = useState<boolean>(false);
  const [alertMessage, setAlertMessage] = useState<string>('');
  
  const exportLogs = async () => {
    if (logs.length === 0) {
      setAlertMessage('没有日志可导出');
      setShowAlert(true);
      return;
    }
    
    try {
      // 调用后端的ExportLogsToFile方法获取实际的文件路径
      const { ExportLogsToFile } = await import('../../wailsjs/go/main/App');
      const filePath = await ExportLogsToFile();
      setAlertMessage(`日志已导出到: ${filePath}`);
      setShowAlert(true);
    } catch (error) {
      console.error('导出日志失败:', error);
      setAlertMessage('导出日志失败: ' + (error as Error).message);
      setShowAlert(true);
    }
  };

  const parseLogEntry = (log: string) => {
    // 检查是否为结构化日志（包含换行符）
    const lines = log.split('\n');
    const firstLine = lines[0];
    
    // 匹配格式: [时间] LEVEL: 消息
    const logMatch = firstLine.match(/\[(\d{1,2}:\d{2}:\d{2}(?::\d{2})?)\]\s*([A-Z]+):\s*(.+)/);
    
    if (logMatch) {
      const time = logMatch[1];
      const level = logMatch[2].toUpperCase();
      const message = logMatch[3];
      
      // 根据日志级别确定类型
      let type = 'info';
      switch (level) {
        case 'ERROR':
          type = 'error';
          break;
        case 'WARN':
        case 'WARNING':
          type = 'warn';
          break;
        case 'DEBUG':
          type = 'debug';
          break;
        case 'INFO':
          type = 'info';
          break;
        default:
          type = 'info';
      }
      
      return { time, message: `${level}: ${message}`, type, details: lines.slice(1) };
    }
    
    // 如果没有匹配到标准格式，尝试匹配旧格式
    const timeMatch = firstLine.match(/\[(\d{1,2}:\d{2}:\d{2})\]/);
    if (timeMatch) {
      const time = timeMatch[1];
      const message = firstLine.replace(/\[\d{1,2}:\d{2}:\d{2}\]\s*/, '');
      let type = 'info';
      
      // 检查消息中的关键词
      const lowerMessage = message.toLowerCase();
      if (lowerMessage.includes('error') || lowerMessage.includes('失败')) {
        type = 'error';
      } else if (lowerMessage.includes('完成') || lowerMessage.includes('成功')) {
        type = 'success';
      } else if (lowerMessage.includes('warn') || lowerMessage.includes('警告')) {
        type = 'warn';
      } else if (lowerMessage.includes('debug')) {
        type = 'debug';
      }
      
      return { time, message, type, details: lines.slice(1) };
    }
    
    return { time: '', message: firstLine, type: 'info', details: lines.slice(1) };
  };
  
  // 当日志变化时，自动滚动到底部
  useEffect(() => {
    const container = logContainerRef.current;
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="logs-section">
      <div className="log-header">
        <h2>扫描日志</h2>
        <div className="log-actions">
          <button 
            className="export-logs-btn-style" 
            onClick={exportLogs} 
            title="导出日志"
            disabled={logs.length === 0}
          >
            导出日志
          </button>
          <button 
            className="clear-logs-btn-style" 
            onClick={onClearLogs} 
            title="清除日志"
            disabled={logs.length === 0}
          >
            清除日志
          </button>
        </div>
      </div>
      <div className="log-container" ref={logContainerRef}>
        {logs.length === 0 ? (
          <div className="no-logs">暂无日志信息</div>
        ) : (
          <div className="log-entries">
            {logs.map((log, index) => {
              const { time, message, type, details } = parseLogEntry(log);
              return (
                <div key={index} className="log-group">
                  <div className={`log-entry log-${type}`}>
                    {time && <span className="log-time">[{time}]</span>}
                    <span className={`log-message log-${type}`}>{message}</span>
                  </div>
                  {/* 渲染详细信息行 */}
                  {details && details.map((detail, detailIndex) => (
                    <div key={`detail-${index}-${detailIndex}`} className="log-entry log-detail">
                      <span className="log-message log-detail">{detail}</span>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>
      
      {/* 自定义提示框 */}
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
    </div>
  );
};

export default ScanLogSection;
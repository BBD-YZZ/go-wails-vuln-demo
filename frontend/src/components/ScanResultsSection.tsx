import React, { useState } from 'react';
import '../App.css';
import { ExportResultsToExcel } from '../../wailsjs/go/main/App';

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

interface ScanResultsSectionProps {
  results: Vulnerability[];
  onVulnerabilitySelect?: (vulnerability: Vulnerability) => void;
  onClearResults?: () => void;
}

const ScanResultsSection: React.FC<ScanResultsSectionProps> = ({ results, onVulnerabilitySelect, onClearResults }) => {
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const [showAlert, setShowAlert] = useState<boolean>(false);
  const [alertMessage, setAlertMessage] = useState<string>('');
  const [showConfirm, setShowConfirm] = useState<boolean>(false);
  const [confirmMessage, setConfirmMessage] = useState<string>('');
  const [confirmCallback, setConfirmCallback] = useState<(() => void) | null>(null);
  
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

  const handleExportToExcel = async () => {
    if (results.length === 0) {
      setAlertMessage('没有扫描结果可以导出');
      setShowAlert(true);
      return;
    }
    
    try {
      // 转换结果类型，确保与wails模型兼容
      const exportResults = results.map(vuln => ({
        ...vuln,
        responseHeaders: vuln.responseHeaders || {},
        responseContent: vuln.responseContent || '',
        supportedFeatures: vuln.supportedFeatures || []
      }));
      
      const result = await ExportResultsToExcel(exportResults);
      setAlertMessage(`扫描结果已导出到Excel文件: ${result}`);
      setShowAlert(true);
    } catch (error) {
      console.error('导出Excel失败:', error);
      setAlertMessage('导出Excel失败: ' + (error as Error).message);
      setShowAlert(true);
    }
  };

  const handleClearResults = () => {
    if (results.length === 0) {
      return;
    }
    
    setConfirmMessage('确定要清除所有扫描结果吗？此操作不可撤销。');
    setConfirmCallback(() => () => {
      // 通知父组件清除结果
      if (onClearResults) {
        onClearResults();
      }
      setShowConfirm(false);
    });
    setShowConfirm(true);
  };

  const openVulnerabilityDetails = (vuln: Vulnerability) => {
    setSelectedVulnerability(vuln);
  };

  const closeVulnerabilityDetails = () => {
    setSelectedVulnerability(null);
  };

  return (
    <div className="results-section">
      <div className="results-header">
        <h2>扫描结果 ({results.length})</h2>
        <div className="results-actions">
          <button 
            className="export-btn" 
            onClick={handleExportToExcel}
            disabled={results.length === 0}
          >
            导出Excel
          </button>
          <button 
            className="clear-btn" 
            onClick={handleClearResults}
            disabled={results.length === 0}
          >
            清除结果
          </button>
        </div>
      </div>
      <div className="results-container">
        {results.length === 0 ? (
          <div className="no-results">暂无扫描结果，请开始扫描</div>
        ) : (
          <div className="results-list">
            {results.map((result, index) => (
              <div key={`${result.id}-${index}`} className="vulnerability-item-simple">
                <div className="vuln-summary">
                  <span className="vuln-target">{result.target}</span>
                  <span> 存在 </span>
                  <span className="vuln-type">{result.vulnerabilityType}</span>
                  <span> 漏洞 </span>
                  <span className={getSeverityClass(result.severity)}>{result.severity}</span>
                </div>
                <button 
                  className="detail-btn"
                  onClick={() => {
                    if (onVulnerabilitySelect) {
                      onVulnerabilitySelect(result);
                    }
                  }}
                >
                  详情
                </button>
              </div>
            ))}
          </div>
        )}
        
        {/* 漏洞详情模态框 - 现在在App组件中处理 */}
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
      
      {/* 自定义确认框 */}
      {showConfirm && (
        <div className="custom-alert-overlay">
          <div className="custom-alert">
            <div className="custom-alert-content">{confirmMessage}</div>
            <div className="custom-alert-actions">
              <button className="secondary-btn" onClick={() => setShowConfirm(false)}>取消</button>
              <button className="primary-btn" onClick={() => confirmCallback && confirmCallback()}>确定</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanResultsSection;
import React from 'react';
import '../App.css';

interface StatusBarProps {
  message: string;
  isScanning: boolean;
  isProxyEnabled?: boolean;
}

const StatusBar: React.FC<StatusBarProps> = ({ message, isScanning, isProxyEnabled }) => {
  return (
    <footer className="status-bar">
      <div className="status-message">
        {isScanning && <div className="scanning-indicator"></div>}
        <span>{message}</span>
      </div>
      <div className="status-info">
        {isProxyEnabled && (
          <span className="proxy-enabled-indicator">代理已启用</span>
        )}
        <span>漏洞扫描工具 v1.0</span>
      </div>
    </footer>
  );
};

export default StatusBar;
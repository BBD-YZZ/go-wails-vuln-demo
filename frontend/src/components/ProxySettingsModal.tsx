import React, { useState, useEffect } from 'react';
import '../App.css';

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

interface ProxySettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (config: ProxyConfig) => void;
  currentConfig: ProxyConfig;
  onTestConnection?: (target: string, proxy: ProxyConfig) => Promise<boolean>;
}

const ProxySettingsModal: React.FC<ProxySettingsModalProps> = ({ 
  isOpen, 
  onClose, 
  onSave, 
  currentConfig,
  onTestConnection
}) => {
  const [proxyConfig, setProxyConfig] = useState<ProxyConfig>(currentConfig);
  const [testTarget, setTestTarget] = useState<string>('https://www.baidu.com');
  const [testResult, setTestResult] = useState<string>('');
  const [errors, setErrors] = useState<{ [key: string]: string }>({});

  useEffect(() => {
    setProxyConfig(currentConfig);
    // 当代理被禁用时清空测试结果
    if (!currentConfig.enabled) {
      setTestResult('');
    }
    // 清空错误信息
    setErrors({});
  }, [currentConfig]);

  const validateForm = () => {
    const newErrors: { [key: string]: string } = {};
    
    // 只有在启用代理时才验证
    if (proxyConfig.enabled) {
      if (!proxyConfig.address || proxyConfig.address.trim() === '') {
        newErrors.address = '请填写此字段';
      }
      if (!proxyConfig.port || proxyConfig.port.trim() === '') {
        newErrors.port = '请填写此字段';
      }
    }
    
    setErrors(newErrors);
    
    // 自动清除错误信息
    if (Object.keys(newErrors).length > 0) {
      setTimeout(() => {
        setErrors({});
      }, 3000); // 3秒后自动清除
    }
    
    return Object.keys(newErrors).length === 0;
  };

  if (!isOpen) return null;

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    const checked = type === 'checkbox' ? (e.target as HTMLInputElement).checked : undefined;
    
    const newValue = type === 'checkbox' ? checked : value;
    
    // 清除对应字段的错误信息
    if (errors[name]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[name];
        return newErrors;
      });
    }
    
    setProxyConfig(prev => {
      const newConfig = {
        ...prev,
        [name]: newValue
      };
      
      // 如果启用了代理，清空测试结果
      if (name === 'enabled' && !newValue) {
        setTestResult('');
        // 当禁用代理时，清空所有错误信息
        setErrors({});
      }
      
      return newConfig;
    });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // 验证表单
    if (validateForm()) {
      onSave(proxyConfig);
      onClose();
    }
  };

  const handleTestConnection = async () => {
    if (onTestConnection) {
      // 验证表单
      if (!validateForm()) {
        return;
      }
      
      // 验证测试地址
      if (!testTarget || testTarget.trim() === '') {
        setErrors(prev => ({ ...prev, testTarget: '请填写此字段' }));
        // 自动清除测试地址错误信息
        setTimeout(() => {
          setErrors(prev => {
            const newErrors = { ...prev };
            delete newErrors.testTarget;
            return newErrors;
          });
        }, 3000); // 3秒后自动清除
        return;
      }
      
      try {
        const result = await onTestConnection(testTarget, proxyConfig);
        if (Array.isArray(result) && result.length >= 2) {
          const [success, message] = result;
          setTestResult(success ? '连接成功' : `连接失败: ${message}`);
        } else {
          // 如果结果不是数组，根据实际连接测试结果设置状态
          setTestResult(result ? '连接成功' : '连接失败');
        }
      } catch (error) {
        setTestResult(`连接失败: ${(error as Error).message}`);
      }
    }
  };

  return (
    // onClick={onClose}
    <div className="modal-overlay"> 
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>代理设置</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        
        <form onSubmit={handleSubmit} className="modal-form">
          {/* 启用代理和代理类型放在一行 */}
          <div className="form-row">
            <div className="form-group">
              <label className="label-inline-flex">
                <span>启用代理</span>
                <input
                  type="checkbox"
                  id="enabled"
                  name="enabled"
                  checked={proxyConfig.enabled}
                  onChange={handleChange}
                />
              </label>
            </div>
            <div className="form-group">
              <label className="label-inline-flex">
                <span>代理类型</span>
                <select
                  id="type"
                  name="type"
                  value={proxyConfig.type}
                  onChange={handleChange}
                >
                  <option value="http">HTTP</option>
                  <option value="socks5">SOCKS5</option>
                </select>
              </label>
            </div>
          </div>
          
          {/* 代理地址和代理端口放在一行 */}
          <div className="form-row">
            <div className="form-group" style={{ position: 'relative' }}>
              <label className="label-inline-flex">
                <span>代理地址</span>
                <input
                  type="text"
                  id="address"
                  name="address"
                  value={proxyConfig.address}
                  onChange={handleChange}
                  placeholder="例如: 127.0.0.1"
                  style={{ borderColor: errors.address ? '#ff3838' : '' }}
                />
              </label>
              {errors.address && (
                <div style={{
                  position: 'absolute',
                  top: '100%',
                  left: '80px',
                  backgroundColor: 'white',
                  color: '#333',
                  padding: '6px 10px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  zIndex: 1000,
                  boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
                  marginTop: '4px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <span style={{ 
                      marginRight: '8px', 
                      color: '#ff9800',
                      fontWeight: 'bold',
                      fontSize: '14px'
                    }}>⚠️</span>
                    {errors.address}
                  </div>
                  <div style={{
                    position: 'absolute',
                    top: '-4px',
                    left: '20px',
                    width: '0',
                    height: '0',
                    borderLeft: '4px solid transparent',
                    borderRight: '4px solid transparent',
                    borderBottom: '4px solid white'
                  }}></div>
                </div>
              )}
            </div>
            <div className="form-group" style={{ position: 'relative' }}>
              <label className="label-inline-flex">
                <span>代理端口</span>
                <input
                  type="text"
                  id="port"
                  name="port"
                  value={proxyConfig.port}
                  onChange={handleChange}
                  placeholder="例如: 8080"
                  style={{ borderColor: errors.port ? '#ff3838' : '' }}
                />
              </label>
              {errors.port && (
                <div style={{
                  position: 'absolute',
                  top: '100%',
                  left: '80px',
                  backgroundColor: 'white',
                  color: '#333',
                  padding: '6px 10px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  zIndex: 1000,
                  boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
                  marginTop: '4px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <span style={{ 
                      marginRight: '8px', 
                      color: '#ff9800',
                      fontWeight: 'bold',
                      fontSize: '14px'
                    }}>⚠️</span>
                    {errors.port}
                  </div>
                  <div style={{
                    position: 'absolute',
                    top: '-4px',
                    left: '20px',
                    width: '0',
                    height: '0',
                    borderLeft: '4px solid transparent',
                    borderRight: '4px solid transparent',
                    borderBottom: '4px solid white'
                  }}></div>
                </div>
              )}
            </div>
          </div>
          
          {/* 用户名和密码放在一行 */}
          <div className="form-row">
            <div className="form-group">
              <label className="label-inline-flex">
                <span>用户名称</span>
                <input
                  type="text"
                  id="username"
                  name="username"
                  value={proxyConfig.username || ''}
                  onChange={handleChange}
                  placeholder="用户名（可选）"
                />
              </label>
            </div>
            <div className="form-group">
              <label className="label-inline-flex">
                <span>用户密码</span>
                <input
                  type="password"
                  id="password"
                  name="password"
                  value={proxyConfig.password || ''}
                  onChange={handleChange}
                  placeholder="密码（可选）"
                />
              </label>
            </div>
          </div>

          {/* 代理测试区域 */}
          <div className="form-row">
            <div className="form-group" style={{ position: 'relative' }}>
              <label className="label-inline-flex">
                <span>测试地址</span>
                <input
                  type="text"
                  id="testTarget"
                  value={testTarget}
                  onChange={(e) => {
                    setTestTarget(e.target.value);
                    // 清除测试地址的错误信息
                    if (errors.testTarget) {
                      setErrors(prev => {
                        const newErrors = { ...prev };
                        delete newErrors.testTarget;
                        return newErrors;
                      });
                    }
                  }}
                  placeholder="输入测试目标地址"
                  style={{ borderColor: errors.testTarget ? '#ff3838' : '' }}
                />
              </label>
              {errors.testTarget && (
                <div style={{
                  position: 'absolute',
                  top: '100%',
                  left: '80px',
                  backgroundColor: 'white',
                  color: '#333',
                  padding: '6px 10px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  zIndex: 1000,
                  boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
                  marginTop: '4px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <span style={{ 
                      marginRight: '8px', 
                      color: '#ff9800',
                      fontWeight: 'bold',
                      fontSize: '14px'
                    }}>⚠️</span>
                    {errors.testTarget}
                  </div>
                  <div style={{
                    position: 'absolute',
                    top: '-4px',
                    left: '20px',
                    width: '0',
                    height: '0',
                    borderLeft: '4px solid transparent',
                    borderRight: '4px solid transparent',
                    borderBottom: '4px solid white'
                  }}></div>
                </div>
              )}
            </div>
            <div className="form-group">
              <label className="label-inline-flex">
                <span>测试结果</span>
                <input
                  type="text"
                  id="testResult"
                  value={testResult}
                  readOnly
                  placeholder="测试结果"
                  className="readonly-input"
                />
              </label>
            </div>
          </div>

          <div className="modal-actions-three-buttons">
            <button 
              type="button" 
              className="test-btn-style" 
              onClick={handleTestConnection}
              disabled={!onTestConnection || !proxyConfig.enabled}
            >
              {proxyConfig.enabled ? '测试连接' : '启用代理'}
            </button>
            {/* <button type="button" className="secondary-btn-style" onClick={onClose}>
              关闭窗口
            </button> */}
            <button type="submit" className="primary-btn-style">
              保存设置
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ProxySettingsModal;
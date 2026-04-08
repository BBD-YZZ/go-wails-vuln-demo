import React, { useState } from 'react';
import '../App.css';

interface CollapsiblePanelProps {
  title: string;
  children: React.ReactNode;
  defaultExpanded?: boolean;
  panelKey: string; // 用于标识面板的唯一键
}

const CollapsiblePanel: React.FC<CollapsiblePanelProps> = ({ 
  title, 
  children, 
  defaultExpanded = true,
  panelKey
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  
  const toggleExpanded = () => {
    setIsExpanded(!isExpanded);
  };

  return (
    <div className="collapsible-panel">
      <div className="panel-header" onClick={toggleExpanded}>
        <h3>{title}</h3>
        <span className={`expand-icon ${isExpanded ? 'expanded' : ''}`}>
          ▼
        </span>
      </div>
      {isExpanded && (
        <div className="panel-content">
          {children}
        </div>
      )}
    </div>
  );
};

export default CollapsiblePanel;
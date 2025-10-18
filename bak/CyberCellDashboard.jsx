import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Activity, Clock, Target, Zap, TrendingUp, CheckCircle, XCircle } from 'lucide-react';

const CyberCellDashboard = () => {
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState({
    tpr: 0,
    fpr: 0,
    mttd: 0,
    mttr: 0,
    activeThreats: 0,
    blocked: 0
  });
  const [attackTimeline, setAttackTimeline] = useState([]);
  const [isAttackRunning, setIsAttackRunning] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState('credential_stuffing');

  // Simulate real-time data updates
  useEffect(() => {
    const interval = setInterval(() => {
      if (isAttackRunning) {
        // Simulate new alert
        const newAlert = {
          id: Date.now(),
          timestamp: new Date().toISOString(),
          severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
          type: ['Anomaly Detected', 'Failed Login', 'Port Scan', 'C2 Communication'][Math.floor(Math.random() * 4)],
          source: `192.168.1.${Math.floor(Math.random() * 255)}`,
          confidence: (Math.random() * 0.4 + 0.6).toFixed(2),
          status: 'active'
        };
        
        setAlerts(prev => [newAlert, ...prev].slice(0, 10));
        
        // Update metrics
        setMetrics(prev => ({
          ...prev,
          tpr: Math.min(0.95, prev.tpr + 0.01).toFixed(2),
          fpr: Math.max(0.03, prev.fpr - 0.001).toFixed(2),
          mttd: Math.max(2.1, prev.mttd - 0.1).toFixed(1),
          activeThreats: prev.activeThreats + 1,
          blocked: Math.random() > 0.7 ? prev.blocked + 1 : prev.blocked
        }));

        // Add to timeline
        setAttackTimeline(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          event: newAlert.type,
          detected: Math.random() > 0.1
        }].slice(-20));
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [isAttackRunning]);

  const launchAttack = () => {
    setIsAttackRunning(true);
    setMetrics({
      tpr: 0.72,
      fpr: 0.08,
      mttd: 8.5,
      mttr: 12.3,
      activeThreats: 0,
      blocked: 0
    });
    setAttackTimeline([]);
    
    // API call would go here
    // fetch('/api/attack/run', { method: 'POST', body: JSON.stringify({ scenario: selectedScenario }) });
  };

  const stopAttack = () => {
    setIsAttackRunning(false);
  };

  const respondToAlert = (alertId) => {
    setAlerts(prev => prev.map(a => 
      a.id === alertId ? { ...a, status: 'responded' } : a
    ));
    setMetrics(prev => ({
      ...prev,
      mttr: (parseFloat(prev.mttr) - 0.5).toFixed(1),
      blocked: prev.blocked + 1
    }));
    
    // API call would go here
    // fetch('/api/respond', { method: 'POST', body: JSON.stringify({ alertId }) });
  };

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'bg-blue-500',
      medium: 'bg-yellow-500',
      high: 'bg-orange-500',
      critical: 'bg-red-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-cyan-400" />
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                CyberCell Defense Platform
              </h1>
              <p className="text-slate-400 text-sm">AI-Powered Red Team vs Blue Team Simulation</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className={`px-4 py-2 rounded-lg ${isAttackRunning ? 'bg-red-500/20 border border-red-500' : 'bg-green-500/20 border border-green-500'}`}>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${isAttackRunning ? 'bg-red-500 animate-pulse' : 'bg-green-500'}`}></div>
                <span className="text-sm font-medium">{isAttackRunning ? 'ATTACK IN PROGRESS' : 'SECURE'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-6 gap-4 mb-6">
        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Detection Rate</span>
            <TrendingUp className="w-4 h-4 text-green-400" />
          </div>
          <div className="text-2xl font-bold text-green-400">{(metrics.tpr * 100).toFixed(0)}%</div>
          <div className="text-xs text-slate-500">TPR</div>
        </div>

        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">False Positive</span>
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="text-2xl font-bold text-yellow-400">{(metrics.fpr * 100).toFixed(1)}%</div>
          <div className="text-xs text-slate-500">FPR</div>
        </div>

        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Time to Detect</span>
            <Clock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">{metrics.mttd}s</div>
          <div className="text-xs text-slate-500">MTTD</div>
        </div>

        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Time to Respond</span>
            <Zap className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400">{metrics.mttr}s</div>
          <div className="text-xs text-slate-500">MTTR</div>
        </div>

        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Active Threats</span>
            <Target className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400">{metrics.activeThreats}</div>
          <div className="text-xs text-slate-500">Live</div>
        </div>

        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Blocked</span>
            <Shield className="w-4 h-4 text-green-400" />
          </div>
          <div className="text-2xl font-bold text-green-400">{metrics.blocked}</div>
          <div className="text-xs text-slate-500">IPs/Hosts</div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-3 gap-6">
        {/* Left: Attack Control & Timeline */}
        <div className="space-y-6">
          {/* Attack Control */}
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Target className="w-5 h-5 text-red-400" />
              Red Team Control
            </h2>
            
            <div className="space-y-4">
              <div>
                <label className="text-sm text-slate-400 mb-2 block">Attack Scenario</label>
                <select 
                  value={selectedScenario}
                  onChange={(e) => setSelectedScenario(e.target.value)}
                  className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-sm"
                  disabled={isAttackRunning}
                >
                  <option value="credential_stuffing">Credential Stuffing</option>
                  <option value="sql_injection">SQL Injection</option>
                  <option value="port_scan">Port Scanning</option>
                  <option value="c2_communication">C2 Communication</option>
                  <option value="ransomware">Ransomware Simulation</option>
                </select>
              </div>

              <button
                onClick={isAttackRunning ? stopAttack : launchAttack}
                className={`w-full py-3 rounded-lg font-medium transition-all ${
                  isAttackRunning 
                    ? 'bg-red-500 hover:bg-red-600' 
                    : 'bg-gradient-to-r from-red-500 to-orange-500 hover:from-red-600 hover:to-orange-600'
                }`}
              >
                {isAttackRunning ? 'STOP ATTACK' : 'LAUNCH ATTACK'}
              </button>

              <div className="text-xs text-slate-500 text-center">
                Sandbox isolated • Non-destructive
              </div>
            </div>
          </div>

          {/* Attack Timeline */}
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              Attack Timeline
            </h2>
            
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {attackTimeline.length === 0 ? (
                <div className="text-center text-slate-500 text-sm py-8">
                  No active attacks
                </div>
              ) : (
                attackTimeline.map((item, idx) => (
                  <div key={idx} className="flex items-center gap-3 text-sm border-l-2 border-slate-600 pl-3 py-2">
                    {item.detected ? (
                      <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                    )}
                    <div className="flex-1">
                      <div className="text-white">{item.event}</div>
                      <div className="text-slate-500 text-xs">{item.time}</div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Center: Live Alerts */}
        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            Live Alerts
          </h2>
          
          <div className="space-y-3 max-h-[600px] overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="text-center text-slate-500 text-sm py-8">
                No alerts detected
              </div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} className="bg-slate-700/50 border border-slate-600 rounded-lg p-4 hover:border-slate-500 transition-colors">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${getSeverityColor(alert.severity)}`}></div>
                      <span className="font-medium text-sm">{alert.type}</span>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded ${
                      alert.status === 'responded' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {alert.status === 'responded' ? 'Responded' : 'Active'}
                    </span>
                  </div>
                  
                  <div className="text-xs text-slate-400 space-y-1 mb-3">
                    <div>Source: <span className="text-white">{alert.source}</span></div>
                    <div>Confidence: <span className="text-cyan-400">{(alert.confidence * 100).toFixed(0)}%</span></div>
                    <div>Time: <span className="text-white">{new Date(alert.timestamp).toLocaleTimeString()}</span></div>
                  </div>

                  {alert.status === 'active' && (
                    <button
                      onClick={() => respondToAlert(alert.id)}
                      className="w-full bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500 text-blue-400 text-xs py-2 rounded transition-colors"
                    >
                      Execute Response
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: ML Models & Status */}
        <div className="space-y-6">
          {/* ML Models */}
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Activity className="w-5 h-5 text-purple-400" />
              AI Models Status
            </h2>
            
            <div className="space-y-4">
              <div className="bg-slate-700/50 border border-slate-600 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Anomaly Detector</span>
                  <span className="text-xs px-2 py-1 rounded bg-green-500/20 text-green-400">Active</span>
                </div>
                <div className="text-xs text-slate-400 mb-3">Isolation Forest</div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Accuracy</span>
                  <span className="text-cyan-400 font-medium">94.2%</span>
                </div>
                <div className="w-full bg-slate-600 rounded-full h-1.5 mt-2">
                  <div className="bg-cyan-400 h-1.5 rounded-full" style={{width: '94.2%'}}></div>
                </div>
              </div>

              <div className="bg-slate-700/50 border border-slate-600 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Threat Forecaster</span>
                  <span className="text-xs px-2 py-1 rounded bg-green-500/20 text-green-400">Active</span>
                </div>
                <div className="text-xs text-slate-400 mb-3">LSTM Time-Series</div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Precision</span>
                  <span className="text-purple-400 font-medium">88.7%</span>
                </div>
                <div className="w-full bg-slate-600 rounded-full h-1.5 mt-2">
                  <div className="bg-purple-400 h-1.5 rounded-full" style={{width: '88.7%'}}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Automated Responses */}
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-yellow-400" />
              Recent Actions
            </h2>
            
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {metrics.blocked === 0 ? (
                <div className="text-center text-slate-500 text-sm py-4">
                  No actions taken
                </div>
              ) : (
                Array.from({length: Math.min(metrics.blocked, 5)}).map((_, idx) => (
                  <div key={idx} className="flex items-center gap-3 text-sm bg-slate-700/30 rounded p-3">
                    <Shield className="w-4 h-4 text-green-400" />
                    <div className="flex-1">
                      <div className="text-white text-xs">IP Blocked</div>
                      <div className="text-slate-500 text-xs">192.168.1.{Math.floor(Math.random() * 255)}</div>
                    </div>
                    <div className="text-xs text-slate-500">Just now</div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* System Info */}
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">System Status</h2>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Backend API</span>
                <span className="text-green-400">● Online</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Database</span>
                <span className="text-green-400">● Connected</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">ML Pipeline</span>
                <span className="text-green-400">● Running</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Sandbox</span>
                <span className="text-green-400">● Isolated</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CyberCellDashboard;

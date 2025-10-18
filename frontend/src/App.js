import React, { useState, useEffect, useCallback } from 'react';
import { Activity, Shield, AlertTriangle, Target, Zap, TrendingUp, Clock, CheckCircle } from 'lucide-react';

const API_URL = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws';

export default function SecurityDashboard() {
  const [alerts, setAlerts] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [metrics, setMetrics] = useState({
    total_alerts: 0,
    total_anomalies: 0,
    avg_mttd: 0,
    avg_mttr: 0,
    detection_rate: 0
  });
  const [riskScore, setRiskScore] = useState({ risk_score: 0, severity: 'low' });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [socReport, setSocReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [connected, setConnected] = useState(false);

  // WebSocket connection
  useEffect(() => {
    let ws;
    
    const connect = () => {
      ws = new WebSocket(WS_URL);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setConnected(true);
      };
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'new_alert') {
          fetchAlerts();
          fetchMetrics();
        } else if (data.type === 'action_executed') {
          console.log('Action executed:', data.data);
        }
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setConnected(false);
      };
      
      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setConnected(false);
        setTimeout(connect, 3000);
      };
    };
    
    connect();
    
    return () => {
      if (ws) ws.close();
    };
  }, []);

  // Fetch data functions
  const fetchAlerts = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/alerts?limit=50`);
      const data = await response.json();
      setAlerts(data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  }, []);

  const fetchAnomalies = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/anomalies?limit=20`);
      const data = await response.json();
      setAnomalies(data);
    } catch (error) {
      console.error('Error fetching anomalies:', error);
    }
  }, []);

  const fetchMetrics = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/health`);
      const data = await response.json();
      
      // Mock metrics for demo
      setMetrics({
        total_alerts: alerts.length,
        total_anomalies: anomalies.length,
        avg_mttd: 12.5,
        avg_mttr: 3.2,
        detection_rate: 95.8
      });
    } catch (error) {
      console.error('Error fetching metrics:', error);
    }
  }, [alerts.length, anomalies.length]);

  const fetchRiskScore = useCallback(async (host = 'juiceshop') => {
    try {
      const response = await fetch(`${API_URL}/risk?host=${host}`);
      const data = await response.json();
      setRiskScore(data);
    } catch (error) {
      console.error('Error fetching risk score:', error);
    }
  }, []);

  const fetchSOCReport = async (alertId) => {
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/soc/report/${alertId}`);
      const data = await response.json();
      setSocReport(data);
    } catch (error) {
      console.error('Error fetching SOC report:', error);
    } finally {
      setLoading(false);
    }
  };

  const executeResponse = async (action, target, alertId) => {
    try {
      await fetch(`${API_URL}/response/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, target, alert_id: alertId })
      });
      alert(`Action ${action} executed on ${target}`);
    } catch (error) {
      console.error('Error executing response:', error);
    }
  };

  const launchAttack = async (scenario) => {
    alert(`Launching ${scenario} attack scenario...`);
    // In production, this would trigger the attack script
    setTimeout(() => {
      fetchAlerts();
      fetchAnomalies();
      fetchRiskScore();
    }, 5000);
  };

  // Initial load
  useEffect(() => {
    fetchAlerts();
    fetchAnomalies();
    fetchMetrics();
    fetchRiskScore();
    
    const interval = setInterval(() => {
      fetchAlerts();
      fetchAnomalies();
      fetchRiskScore();
    }, 5000);
    
    return () => clearInterval(interval);
  }, [fetchAlerts, fetchAnomalies, fetchMetrics, fetchRiskScore]);

  const getSeverityColor = (severity) => {
    if (severity === 'critical' || severity >= 12) return 'bg-red-500';
    if (severity === 'high' || severity >= 8) return 'bg-orange-500';
    if (severity === 'medium' || severity >= 5) return 'bg-yellow-500';
    return 'bg-blue-500';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Shield className="w-10 h-10 text-cyan-400" />
            <div>
              <h1 className="text-3xl font-bold">Security AI Dashboard</h1>
              <p className="text-gray-400">Real-time Threat Detection & Response</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
            <span className="text-sm">{connected ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Risk Score</p>
              <p className="text-3xl font-bold">{riskScore.risk_score || 0}</p>
              <p className={`text-sm ${getSeverityColor(riskScore.severity)} inline-block px-2 py-1 rounded mt-1`}>
                {riskScore.severity?.toUpperCase() || 'LOW'}
              </p>
            </div>
            <Target className="w-10 h-10 text-red-400" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Alerts</p>
              <p className="text-3xl font-bold">{metrics.total_alerts}</p>
              <p className="text-sm text-gray-500">Last 24h</p>
            </div>
            <AlertTriangle className="w-10 h-10 text-orange-400" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Anomalies</p>
              <p className="text-3xl font-bold">{metrics.total_anomalies}</p>
              <p className="text-sm text-gray-500">ML Detected</p>
            </div>
            <Activity className="w-10 h-10 text-purple-400" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">MTTD</p>
              <p className="text-3xl font-bold">{metrics.avg_mttd.toFixed(1)}s</p>
              <p className="text-sm text-gray-500">Mean Time to Detect</p>
            </div>
            <Clock className="w-10 h-10 text-cyan-400" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Detection Rate</p>
              <p className="text-3xl font-bold">{metrics.detection_rate.toFixed(1)}%</p>
              <p className="text-sm text-gray-500">Accuracy</p>
            </div>
            <TrendingUp className="w-10 h-10 text-green-400" />
          </div>
        </div>
      </div>

      {/* Attack Launcher */}
      <div className="bg-gray-800 rounded-lg p-4 mb-8 border border-gray-700">
        <h3 className="text-xl font-bold mb-4 flex items-center">
          <Zap className="w-5 h-5 mr-2 text-yellow-400" />
          Launch Attack Scenario (Demo)
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {['sqli', 'brute', 'xss', 'scan', 'dos', 'combo'].map(scenario => (
            <button
              key={scenario}
              onClick={() => launchAttack(scenario)}
              className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded font-semibold transition"
            >
              {scenario.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts List */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-xl font-bold mb-4">Recent Alerts</h3>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {alerts.slice(0, 10).map((alert, idx) => (
              <div
                key={idx}
                onClick={() => {
                  setSelectedAlert(alert);
                  fetchSOCReport(alert.alert_id);
                }}
                className="bg-gray-700 rounded p-3 cursor-pointer hover:bg-gray-600 transition"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold">{alert.rule_description || 'Security Alert'}</span>
                  <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(alert.severity)}`}>
                    {alert.severity}
                  </span>
                </div>
                <div className="text-sm text-gray-400 space-y-1">
                  <div>Host: {alert.host}</div>
                  <div className="flex justify-between">
                    <span>Risk: {alert.risk_score?.toFixed(2) || '0.00'}</span>
                    <span>Anomaly: {alert.anomaly_score?.toFixed(3) || '0.000'}</span>
                  </div>
                </div>
              </div>
            ))}
            {alerts.length === 0 && (
              <div className="text-center text-gray-500 py-8">
                <CheckCircle className="w-12 h-12 mx-auto mb-2" />
                <p>No alerts detected. System is secure.</p>
              </div>
            )}
          </div>
        </div>

        {/* SOC Report */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-xl font-bold mb-4">SOC Analyst Report</h3>
          {loading ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto" />
              <p className="mt-4 text-gray-400">Generating AI report...</p>
            </div>
          ) : socReport ? (
            <div className="space-y-4 max-h-96 overflow-y-auto">
              <div>
                <h4 className="font-bold text-lg text-cyan-400">{socReport.title}</h4>
                <span className={`inline-block px-3 py-1 rounded mt-2 ${getSeverityColor(socReport.severity)}`}>
                  {socReport.severity?.toUpperCase()} - {socReport.confidence}% Confidence
                </span>
              </div>
              
              <div>
                <h5 className="font-semibold text-yellow-400 mb-2">Summary</h5>
                <p className="text-sm text-gray-300">{socReport.summary}</p>
              </div>
              
              <div>
                <h5 className="font-semibold text-yellow-400 mb-2">Evidence</h5>
                <div className="space-y-1 text-sm">
                  {Object.entries(socReport.evidence || {}).map(([key, value], idx) => (
                    <div key={idx} className="bg-gray-700 rounded px-2 py-1">
                      <span className="text-gray-400">{key}:</span> {JSON.stringify(value)}
                    </div>
                  ))}
                </div>
              </div>
              
              <div>
                <h5 className="font-semibold text-yellow-400 mb-2">Immediate Actions</h5>
                <ul className="list-disc list-inside text-sm space-y-1">
                  {(socReport.immediate_actions || []).map((action, idx) => (
                    <li key={idx} className="text-gray-300">{action}</li>
                  ))}
                </ul>
              </div>
              
              <div className="flex space-x-2 pt-4">
                <button
                  onClick={() => executeResponse('block_ip', selectedAlert?.host, selectedAlert?.alert_id)}
                  className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded flex-1 font-semibold"
                >
                  Block IP
                </button>
                <button
                  onClick={() => executeResponse('isolate_host', selectedAlert?.host, selectedAlert?.alert_id)}
                  className="bg-orange-600 hover:bg-orange-700 px-4 py-2 rounded flex-1 font-semibold"
                >
                  Isolate Host
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center text-gray-500 py-12">
              <AlertTriangle className="w-12 h-12 mx-auto mb-2" />
              <p>Select an alert to view AI-generated report</p>
            </div>
          )}
        </div>
      </div>

      {/* Anomalies Section */}
      <div className="bg-gray-800 rounded-lg p-4 mt-6 border border-gray-700">
        <h3 className="text-xl font-bold mb-4">Anomaly Detection Timeline</h3>
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {anomalies.slice(0, 10).map((anomaly, idx) => (
            <div
              key={idx}
              className={`rounded p-3 ${anomaly.is_anomaly ? 'bg-red-900 border border-red-600' : 'bg-gray-700'}`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-semibold">{anomaly.host}</span>
                  <span className="text-sm text-gray-400 ml-4">
                    Score: {anomaly.anomaly_score?.toFixed(3)}
                  </span>
                </div>
                {anomaly.is_anomaly && (
                  <span className="bg-red-600 px-2 py-1 rounded text-xs font-bold">ANOMALY</span>
                )}
              </div>
              {anomaly.top_features && (
                <div className="text-xs text-gray-400 mt-2">
                  Features: {Object.keys(anomaly.top_features).join(', ')}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import { Shield, Bot, Code, AlertTriangle, CheckCircle, Brain, FileCode, Activity, Zap, TrendingUp, AlertCircle, PlayCircle, RefreshCw, FileText } from 'lucide-react';

const API_URL = 'http://localhost:8000';

export default function AISecurityDashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [alerts, setAlerts] = useState([]);
  const [ruleRecommendations, setRuleRecommendations] = useState([]);
  const [incidentReports, setIncidentReports] = useState([]);
  const [auditReport, setAuditReport] = useState(null);
  const [stats, setStats] = useState({
    totalAlerts: 0,
    criticalAlerts: 0,
    rulesCreated: 0,
    vulnerabilitiesFound: 0,
    attacksValidated: 0
  });
  const [scanning, setScanning] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);

  useEffect(() => {
    fetchAlerts();
    fetchRuleRecommendations();
    fetchIncidentReports();
    fetchStats();
    fetchAuditResults();
    
    const interval = setInterval(() => {
      fetchAlerts();
      fetchRuleRecommendations();
      fetchIncidentReports();
      fetchStats();
      if (scanning) {
        fetchAuditResults();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [scanning]);

  const fetchAlerts = async () => {
    try {
      const response = await fetch(`${API_URL}/alerts?limit=20`);
      const data = await response.json();
      setAlerts(data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  };

  const fetchRuleRecommendations = async () => {
    try {
      const response = await fetch(`${API_URL}/soc/rule-recommendations`);
      const data = await response.json();
      setRuleRecommendations(data);
    } catch (error) {
      console.error('Error fetching recommendations:', error);
    }
  };

  const fetchIncidentReports = async () => {
    try {
      const response = await fetch(`${API_URL}/soc/incidents`);
      const data = await response.json();
      setIncidentReports(data);
    } catch (error) {
      console.error('Error fetching incident reports:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_URL}/stats`);
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchAuditResults = async () => {
    try {
      const response = await fetch(`${API_URL}/auditor/results`);
      const data = await response.json();
      if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        setAuditReport(data);
        if (scanning) {
          setScanning(false);
          setActiveTab('auditor');
        }
      }
    } catch (error) {
      console.error('Error fetching audit results:', error);
    }
  };

  const runSecurityAudit = async () => {
    setScanning(true);
    try {
      const response = await fetch(`${API_URL}/auditor/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: 'juiceshop', validate_attacks: true })
      });
      const data = await response.json();
      console.log('Scan started:', data);
      
      setTimeout(() => {
        fetchAuditResults();
      }, 15000);
    } catch (error) {
      console.error('Error running audit:', error);
      setScanning(false);
    }
  };

  const applyRuleRecommendation = async (recId) => {
    try {
      const response = await fetch(`${API_URL}/soc/apply-recommendation/${recId}`, {
        method: 'POST'
      });
      const result = await response.json();
      alert(`✓ Rule ${result.action} applied successfully!`);
      fetchRuleRecommendations();
      fetchStats();
    } catch (error) {
      console.error('Error applying recommendation:', error);
      alert('Error applying recommendation');
    }
  };

  const analyzeAlert = async (alertId) => {
    setAnalyzing(true);
    try {
      await fetch(`${API_URL}/soc/analyze/${alertId}`, {
        method: 'POST'
      });
      alert('✓ Analysis started! Check SOC Analyst tab in 10 seconds.');
      setTimeout(() => {
        fetchRuleRecommendations();
        fetchIncidentReports();
      }, 10000);
    } catch (error) {
      console.error('Error analyzing alert:', error);
    } finally {
      setAnalyzing(false);
    }
  };

  const getSeverityColor = (severity) => {
    const sev = typeof severity === 'string' ? severity.toLowerCase() : '';
    if (sev === 'critical' || severity >= 12) return 'bg-red-500';
    if (sev === 'high' || severity >= 8) return 'bg-orange-500';
    if (sev === 'medium' || severity >= 5) return 'bg-yellow-500';
    return 'bg-blue-500';
  };

  const getActionIcon = (action) => {
    if (action === 'CREATE') return <Zap className="w-4 h-4 text-green-400" />;
    if (action === 'MODIFY') return <RefreshCw className="w-4 h-4 text-blue-400" />;
    if (action === 'DISABLE') return <AlertCircle className="w-4 h-4 text-red-400" />;
    return null;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="bg-gray-800 border-b border-gray-700 p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Shield className="w-10 h-10 text-cyan-400" />
            <div>
              <h1 className="text-3xl font-bold">AI Security Operations Center</h1>
              <p className="text-gray-400">Intelligent Detection & Response Platform</p>
            </div>
          </div>
          <div className="flex space-x-3">
            <button
              onClick={runSecurityAudit}
              disabled={scanning}
              className="bg-purple-600 hover:bg-purple-700 px-6 py-3 rounded-lg font-semibold flex items-center space-x-2 disabled:opacity-50"
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <PlayCircle className="w-5 h-5" />
                  <span>Run Security Audit</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 p-6">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Alerts</p>
              <p className="text-3xl font-bold text-cyan-400">{stats.totalAlerts}</p>
            </div>
            <AlertTriangle className="w-10 h-10 text-cyan-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Critical Alerts</p>
              <p className="text-3xl font-bold text-red-400">{stats.criticalAlerts}</p>
            </div>
            <AlertCircle className="w-10 h-10 text-red-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Rules Created</p>
              <p className="text-3xl font-bold text-green-400">{stats.rulesCreated}</p>
            </div>
            <Brain className="w-10 h-10 text-green-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Vulnerabilities</p>
              <p className="text-3xl font-bold text-orange-400">{stats.vulnerabilitiesFound}</p>
            </div>
            <Code className="w-10 h-10 text-orange-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Attacks Validated</p>
              <p className="text-3xl font-bold text-purple-400">{stats.attacksValidated}</p>
            </div>
            <Activity className="w-10 h-10 text-purple-400 opacity-50" />
          </div>
        </div>
      </div>

      <div className="border-b border-gray-700 px-6">
        <div className="flex space-x-2">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'incidents', label: 'Incident Reports', icon: FileText },
            { id: 'soc', label: 'Rule Recommendations', icon: Bot },
            { id: 'auditor', label: 'Security Auditor', icon: FileCode },
            { id: 'alerts', label: 'Live Alerts', icon: AlertTriangle }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-6 py-3 border-b-2 transition ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <tab.icon className="w-5 h-5" />
              <span className="font-semibold">{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="p-6">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <AlertTriangle className="w-6 h-6 mr-2 text-cyan-400" />
                Recent Alerts
              </h3>
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {alerts.slice(0, 5).map((alert, idx) => (
                  <div key={idx} className="bg-gray-700 rounded p-3 hover:bg-gray-600 transition">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold">{alert.rule_description || 'Security Event'}</span>
                      <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </div>
                    <div className="text-sm text-gray-400">
                      <div>Host: {alert.host}</div>
                      <div>Time: {new Date(alert.timestamp).toLocaleString()}</div>
                    </div>
                  </div>
                ))}
                {alerts.length === 0 && (
                  <div className="text-center text-gray-500 py-8">
                    <CheckCircle className="w-12 h-12 mx-auto mb-2 opacity-50" />
                    <p>No alerts detected. System is secure.</p>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <Brain className="w-6 h-6 mr-2 text-green-400" />
                AI Rule Recommendations
              </h3>
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {ruleRecommendations.slice(0, 5).map((rec, idx) => (
                  <div key={idx} className="bg-gray-700 rounded p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        {getActionIcon(rec.action)}
                        <span className="font-semibold">{rec.action} Rule</span>
                      </div>
                      <span className="text-xs text-gray-400">{rec.confidence}% confidence</span>
                    </div>
                    <div className="text-sm text-gray-300 mb-2">{rec.rule_id}</div>
                    <div className="text-xs text-gray-400">{rec.reason.substring(0, 100)}...</div>
                  </div>
                ))}
                {ruleRecommendations.length === 0 && (
                  <div className="text-center text-gray-500 py-8">
                    <Bot className="w-12 h-12 mx-auto mb-2 opacity-50" />
                    <p>No recommendations yet. AI is learning...</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'incidents' && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-2xl font-bold mb-4 flex items-center">
                <FileText className="w-8 h-8 mr-3 text-cyan-400" />
                AI-Generated Incident Reports
              </h2>
              <p className="text-gray-400 mb-6">
                Comprehensive analysis of each security alert with false positive detection
              </p>

              <div className="space-y-4">
                {incidentReports.map((report, idx) => (
                  <div key={idx} className="bg-gray-700 rounded-lg p-5 border border-gray-600">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-lg font-bold text-white flex items-center">
                          {report.is_false_positive ? (
                            <AlertCircle className="w-5 h-5 mr-2 text-yellow-400" />
                          ) : (
                            <CheckCircle className="w-5 h-5 mr-2 text-green-400" />
                          )}
                          INC-{String(report.id).padStart(6, '0')}
                        </h3>
                        <p className="text-sm text-gray-400">
                          {report.attack_type} - {report.threat_level} Threat
                        </p>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className={`px-3 py-1 rounded text-sm ${getSeverityColor(report.severity)}`}>
                          {report.severity}
                        </span>
                        <button
                          onClick={() => setSelectedIncident(report)}
                          className="bg-cyan-600 hover:bg-cyan-700 px-4 py-2 rounded text-sm font-semibold"
                        >
                          View Full Report
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div>
                        <p className="text-xs text-gray-400">Source IP</p>
                        <p className="text-sm text-white">{report.source_ip}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400">Attack Pattern</p>
                        <p className="text-sm text-white">{report.attack_pattern}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400">Attack Success</p>
                        <p className="text-sm text-white">{report.attack_success}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400">Status</p>
                        <p className="text-sm text-white">
                          {report.is_false_positive ? '⚠️ False Positive' : '✓ True Positive'}
                        </p>
                      </div>
                    </div>

                    <div className="mb-4">
                      <p className="text-sm text-gray-400 mb-2">AI Analysis Summary:</p>
                      <p className="text-sm text-gray-200 bg-gray-800 p-3 rounded">
                        {report.analysis_summary}
                      </p>
                    </div>

                    <div>
                      <p className="text-sm text-gray-400 mb-2">Recommended Actions:</p>
                      <div className="space-y-1">
                        {report.recommended_actions && report.recommended_actions.map((action, i) => (
                          <div key={i} className="text-sm text-gray-300 flex items-start">
                            <span className="text-cyan-400 mr-2">{i + 1}.</span>
                            <span>{action}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="mt-3 text-xs text-gray-500">
                      Generated: {new Date(report.timestamp).toLocaleString()}
                    </div>
                  </div>
                ))}

                {incidentReports.length === 0 && (
                  <div className="text-center text-gray-500 py-12">
                    <FileText className="w-16 h-16 mx-auto mb-4 opacity-50" />
                    <p>No incident reports yet. Analyze alerts to generate reports.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'soc' && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-2xl font-bold mb-4 flex items-center">
                <Bot className="w-8 h-8 mr-3 text-cyan-400" />
                AI SOC Analyst - Rule Recommendations
              </h2>
              <p className="text-gray-400 mb-6">
                AI analyzes alerts and automatically recommends new rules, modifications, and optimizations
              </p>

              <div className="space-y-4">
                {ruleRecommendations.map((rec, idx) => (
                  <div key={idx} className="bg-gray-700 rounded-lg p-5 border border-gray-600">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        {getActionIcon(rec.action)}
                        <div>
                          <h3 className="text-lg font-bold text-white">{rec.action} RULE</h3>
                          <p className="text-sm text-gray-400">Rule ID: {rec.rule_id}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className="text-sm text-gray-400">
                          Confidence: <span className="text-cyan-400 font-bold">{rec.confidence}%</span>
                        </span>
                        <button
                          onClick={() => applyRuleRecommendation(rec.id)}
                          className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded text-sm font-semibold"
                        >
                          Apply
                        </button>
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div>
                        <p className="text-sm text-gray-400 mb-1">Reason:</p>
                        <p className="text-gray-200">{rec.reason}</p>
                      </div>

                      {rec.current_pattern && (
                        <div>
                          <p className="text-sm text-gray-400 mb-1">Current Pattern:</p>
                          <code className="block bg-gray-800 p-2 rounded text-red-400 text-sm">
                            {rec.current_pattern}
                          </code>
                        </div>
                      )}

                      {rec.suggested_pattern && (
                        <div>
                          <p className="text-sm text-gray-400 mb-1">Suggested Pattern:</p>
                          <code className="block bg-gray-800 p-2 rounded text-green-400 text-sm">
                            {rec.suggested_pattern}
                          </code>
                        </div>
                      )}

                      <div className="flex items-center space-x-4 text-xs text-gray-400">
                        <span>Severity: {rec.severity}</span>
                        <span>Evidence: {rec.evidence_count} similar attacks</span>
                        <span>Generated: {new Date(rec.timestamp).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                ))}

                {ruleRecommendations.length === 0 && (
                  <div className="text-center text-gray-500 py-12">
                    <Bot className="w-16 h-16 mx-auto mb-4 opacity-50" />
                    <p>No recommendations yet. Create alerts or run security audit to generate recommendations.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'auditor' && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-2xl font-bold mb-4 flex items-center">
                <FileCode className="w-8 h-8 mr-3 text-purple-400" />
                AI Security Auditor - Code Analysis & Attack Validation
              </h2>

              {auditReport ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-4 gap-4">
                    <div className="bg-gray-700 rounded p-4 text-center">
                      <p className="text-3xl font-bold text-purple-400">{auditReport.files_analyzed || 0}</p>
                      <p className="text-sm text-gray-400">Files Analyzed</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4 text-center">
                      <p className="text-3xl font-bold text-red-400">{auditReport.total_vulnerabilities || 0}</p>
                      <p className="text-sm text-gray-400">Vulnerabilities</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4 text-center">
                      <p className="text-3xl font-bold text-orange-400">
                        {auditReport.vulnerabilities?.filter(v => v.validated).length || 0}
                      </p>
                      <p className="text-sm text-gray-400">Validated</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4 text-center">
                      <p className="text-3xl font-bold text-cyan-400">{auditReport.cvss_avg?.toFixed(1) || 0}</p>
                      <p className="text-sm text-gray-400">Avg CVSS Score</p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    {auditReport.vulnerabilities?.map((vuln, idx) => (
                      <div key={idx} className="bg-gray-700 rounded-lg p-5 border border-gray-600">
                        <div className="flex items-start justify-between mb-4">
                          <div>
                            <h3 className="text-lg font-bold text-white flex items-center">
                              {vuln.type}
                              {vuln.validated && (
                                <CheckCircle className="w-5 h-5 ml-2 text-green-400" />
                              )}
                            </h3>
                            <p className="text-sm text-gray-400">{vuln.file}:{vuln.line}</p>
                          </div>
                          <span className={`px-3 py-1 rounded ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                        </div>

                        <div className="space-y-3">
                          <div>
                            <p className="text-sm text-gray-400 mb-1">Vulnerable Code:</p>
                            <code className="block bg-gray-800 p-3 rounded text-red-400 text-sm font-mono">
                              {vuln.code}
                            </code>
                          </div>

                          {vuln.validated && (
                            <div>
                              <p className="text-sm text-green-400 mb-1">✓ Attack Validated:</p>
                              <code className="block bg-gray-800 p-3 rounded text-yellow-400 text-sm">
                                Payload: {vuln.attack_payload}
                              </code>
                            </div>
                          )}

                          <div>
                            <p className="text-sm text-gray-400 mb-1">Remediation:</p>
                            <code className="block bg-gray-800 p-3 rounded text-green-400 text-sm font-mono">
                              {vuln.remediation}
                            </code>
                          </div>

                          <div className="flex items-center space-x-4 text-xs text-gray-400">
                            <span>CVSS: {vuln.cvss_score}</span>
                            <span>{vuln.cwe_id}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <FileCode className="w-16 h-16 mx-auto mb-4 text-purple-400 opacity-50" />
                  <p className="text-gray-400 mb-4">Click "Run Security Audit" to analyze code and validate vulnerabilities</p>
                  {scanning && (
                    <p className="text-cyan-400 animate-pulse">Scanning in progress... Results will appear shortly</p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'alerts' && (
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h2 className="text-2xl font-bold mb-4 flex items-center">
              <AlertTriangle className="w-8 h-8 mr-3 text-orange-400" />
              Live Security Alerts
            </h2>
            <div className="space-y-3">
              {alerts.map((alert, idx) => (
                <div key={idx} className="bg-gray-700 rounded-lg p-4 hover:bg-gray-600 transition">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`w-3 h-3 rounded-full ${getSeverityColor(alert.severity)}`}></span>
                      <span className="font-bold text-lg">{alert.rule_description || 'Security Event'}</span>
                    </div>
                    <button
                      onClick={() => analyzeAlert(alert.id)}
                      disabled={analyzing}
                      className="bg-cyan-600 hover:bg-cyan-700 px-4 py-2 rounded text-sm font-semibold disabled:opacity-50"
                    >
                      {analyzing ? 'Analyzing...' : 'Analyze with AI'}
                    </button>
                  </div>
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">Host:</span>
                      <span className="ml-2 text-white">{alert.host}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Rule ID:</span>
                      <span className="ml-2 text-white">{alert.rule_id}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Time:</span>
                      <span className="ml-2 text-white">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {selectedIncident && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50" onClick={() => setSelectedIncident(null)}>
          <div className="bg-gray-800 rounded-lg p-6 max-w-4xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-2xl font-bold">Full Incident Report</h3>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>
            <pre className="bg-gray-900 p-4 rounded text-sm text-green-400 font-mono whitespace-pre-wrap">
              {selectedIncident.full_report}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

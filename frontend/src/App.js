import React, { useState, useEffect } from 'react';
import { Shield, Bot, Code, AlertTriangle, CheckCircle, Brain, FileCode, Activity, Zap, TrendingUp, AlertCircle, PlayCircle, RefreshCw, FileText, Target, Sparkles, X, ChevronRight, Clock, MapPin } from 'lucide-react';

const API_URL = 'http://localhost:8000';

export default function ImprovedSecurityDashboard() {
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
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showIncidentModal, setShowIncidentModal] = useState(false);
  const [showMLModal, setShowMLModal] = useState(false);

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
      if (scanning) fetchAuditResults();
    }, 5000);
    return () => clearInterval(interval);
  }, [scanning]);

  const fetchAlerts = async () => {
    try {
      const response = await fetch(`${API_URL}/alerts?limit=50`);
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
      await fetch(`${API_URL}/auditor/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: 'juiceshop', validate_attacks: true })
      });
      setTimeout(() => fetchAuditResults(), 15000);
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
      alert('✓ ML Analysis started! Check results in 20 seconds.');
      setTimeout(() => {
        fetchRuleRecommendations();
        fetchIncidentReports();
      }, 20000);
    } catch (error) {
      console.error('Error analyzing alert:', error);
    } finally {
      setAnalyzing(false);
    }
  };

  const openAlertDetails = (alert) => {
    setSelectedAlert(alert);
  };

  const closeAlertDetails = () => {
    setSelectedAlert(null);
    setShowIncidentModal(false);
    setShowMLModal(false);
  };

  const getMLReportForAlert = (alertId) => {
    return incidentReports.find(r => r.alert_id === alertId);
  };

  const parseMLReport = (report) => {
    try {
      return typeof report === 'string' ? JSON.parse(report) : report;
    } catch {
      return null;
    }
  };

  const getSeverityColor = (severity) => {
    const sev = typeof severity === 'string' ? severity.toLowerCase() : '';
    if (sev === 'critical' || severity >= 12) return 'bg-red-500';
    if (sev === 'high' || severity >= 8) return 'bg-orange-500';
    if (sev === 'medium' || severity >= 5) return 'bg-yellow-500';
    return 'bg-blue-500';
  };

  const getSeverityBadge = (severity) => {
    const sev = typeof severity === 'string' ? severity.toLowerCase() : '';
    if (sev === 'critical' || severity >= 12) return { bg: 'bg-red-500', text: 'CRITICAL' };
    if (sev === 'high' || severity >= 8) return { bg: 'bg-orange-500', text: 'HIGH' };
    if (sev === 'medium' || severity >= 5) return { bg: 'bg-yellow-500', text: 'MEDIUM' };
    return { bg: 'bg-blue-500', text: 'LOW' };
  };

  const getActionIcon = (action) => {
    if (action === 'CREATE') return <Zap className="w-4 h-4 text-green-400" />;
    if (action === 'MODIFY') return <RefreshCw className="w-4 h-4 text-blue-400" />;
    if (action === 'DISABLE') return <AlertCircle className="w-4 h-4 text-red-400" />;
    return null;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="bg-gradient-to-r from-gray-800 to-gray-900 border-b border-gray-700 p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Shield className="w-10 h-10 text-cyan-400" />
              <Sparkles className="w-5 h-5 text-yellow-400 absolute -top-1 -right-1" />
            </div>
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                AI Security Operations Center
              </h1>
              <p className="text-gray-400">ML-Powered Threat Intelligence & Behavioral Analysis</p>
            </div>
          </div>
          <button
            onClick={runSecurityAudit}
            disabled={scanning}
            className="bg-purple-600 hover:bg-purple-700 px-6 py-3 rounded-lg font-semibold flex items-center space-x-2 disabled:opacity-50 transition"
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

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 p-6">
        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg p-4 border border-cyan-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Alerts</p>
              <p className="text-3xl font-bold text-cyan-400">{stats.totalAlerts}</p>
            </div>
            <AlertTriangle className="w-10 h-10 text-cyan-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg p-4 border border-red-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Critical</p>
              <p className="text-3xl font-bold text-red-400">{stats.criticalAlerts}</p>
            </div>
            <AlertCircle className="w-10 h-10 text-red-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg p-4 border border-green-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Rules Created</p>
              <p className="text-3xl font-bold text-green-400">{stats.rulesCreated}</p>
            </div>
            <Brain className="w-10 h-10 text-green-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg p-4 border border-orange-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Vulnerabilities</p>
              <p className="text-3xl font-bold text-orange-400">{stats.vulnerabilitiesFound}</p>
            </div>
            <Code className="w-10 h-10 text-orange-400 opacity-50" />
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg p-4 border border-purple-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Validated</p>
              <p className="text-3xl font-bold text-purple-400">{stats.attacksValidated}</p>
            </div>
            <Activity className="w-10 h-10 text-purple-400 opacity-50" />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-700 px-6">
        <div className="flex space-x-2 overflow-x-auto">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'alerts', label: 'Live Alerts', icon: AlertTriangle },
            { id: 'soc', label: 'Rule Recommendations', icon: Bot },
            { id: 'auditor', label: 'Security Auditor', icon: FileCode }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-6 py-3 border-b-2 transition whitespace-nowrap ${
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

      {/* Tab Content */}
      <div className="p-6">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Recent Alerts */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <AlertTriangle className="w-6 h-6 mr-2 text-cyan-400" />
                Recent Alerts
              </h3>
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {alerts.slice(0, 10).map((alert, idx) => {
                  const badge = getSeverityBadge(alert.severity);
                  return (
                    <div 
                      key={idx} 
                      className="bg-gray-700 rounded p-3 hover:bg-gray-600 transition cursor-pointer"
                      onClick={() => openAlertDetails(alert)}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold">{alert.rule_description || 'Security Event'}</span>
                        <span className={`px-2 py-1 rounded text-xs ${badge.bg}`}>
                          {badge.text}
                        </span>
                      </div>
                      <div className="text-sm text-gray-400">
                        <div className="flex items-center space-x-4">
                          <span className="flex items-center">
                            <MapPin className="w-3 h-3 mr-1" />
                            {alert.host}
                          </span>
                          <span className="flex items-center">
                            <Clock className="w-3 h-3 mr-1" />
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
                {alerts.length === 0 && (
                  <div className="text-center text-gray-500 py-8">
                    <CheckCircle className="w-12 h-12 mx-auto mb-2 opacity-50" />
                    <p>No alerts detected. System is secure.</p>
                  </div>
                )}
              </div>
            </div>

            {/* System Health */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <Activity className="w-6 h-6 mr-2 text-green-400" />
                System Health
              </h3>
              <div className="space-y-4">
                <div className="bg-gradient-to-r from-cyan-900/30 to-blue-900/30 rounded-lg p-4 border border-cyan-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <Brain className="w-5 h-5 text-cyan-400" />
                    <span className="font-semibold text-cyan-400">ML Analysis Engine</span>
                  </div>
                  <p className="text-sm text-gray-300">
                    Behavioral anomaly detection active. {incidentReports.length} analyses completed.
                  </p>
                </div>
                
                <div className="bg-gradient-to-r from-purple-900/30 to-pink-900/30 rounded-lg p-4 border border-purple-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <Target className="w-5 h-5 text-purple-400" />
                    <span className="font-semibold text-purple-400">Threat Intelligence</span>
                  </div>
                  <p className="text-sm text-gray-300">
                    {ruleRecommendations.length} recommendations pending review.
                  </p>
                </div>
                
                <div className="bg-gradient-to-r from-green-900/30 to-emerald-900/30 rounded-lg p-4 border border-green-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <Code className="w-5 h-5 text-green-400" />
                    <span className="font-semibold text-green-400">Security Auditor</span>
                  </div>
                  <p className="text-sm text-gray-300">
                    {auditReport ? `${auditReport.total_vulnerabilities} vulnerabilities found` : 'Ready to scan'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'alerts' && (
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h2 className="text-2xl font-bold mb-4 flex items-center">
              <AlertTriangle className="w-8 h-8 mr-3 text-orange-400" />
              Live Security Alerts ({alerts.length})
            </h2>
            <div className="space-y-3">
              {alerts.map((alert, idx) => {
                const badge = getSeverityBadge(alert.severity);
                const mlReport = getMLReportForAlert(alert.id);
                
                return (
                  <div key={idx} className="bg-gray-700 rounded-lg p-4 hover:bg-gray-600 transition">
                    <div className="flex items-center justify-between mb-3">
                      <div 
                        className="flex items-center space-x-3 flex-1 cursor-pointer"
                        onClick={() => openAlertDetails(alert)}
                      >
                        <span className={`w-3 h-3 rounded-full ${getSeverityColor(alert.severity)}`}></span>
                        <div className="flex-1">
                          <span className="font-bold text-lg">{alert.rule_description || 'Security Event'}</span>
                          <div className="text-sm text-gray-400 mt-1">
                            Alert #{alert.id} • {alert.rule_id} • {alert.host}
                          </div>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-400" />
                      </div>
                      <div className="flex items-center space-x-2 ml-4">
                        {mlReport && (
                          <span className="text-xs bg-cyan-600 px-2 py-1 rounded flex items-center">
                            <Sparkles className="w-3 h-3 mr-1" />
                            ML Analyzed
                          </span>
                        )}
                        <button
                          onClick={() => analyzeAlert(alert.id)}
                          disabled={analyzing}
                          className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 px-4 py-2 rounded text-sm font-semibold disabled:opacity-50 transition flex items-center space-x-2"
                        >
                          <Sparkles className="w-4 h-4" />
                          <span>{analyzing ? 'Analyzing...' : 'ML Analyze'}</span>
                        </button>
                      </div>
                    </div>
                    <div className="flex items-center space-x-6 text-sm text-gray-400">
                      <span className="flex items-center">
                        <Clock className="w-4 h-4 mr-1" />
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                      {alert.raw_data?.source_ip && (
                        <span>IP: {alert.raw_data.source_ip}</span>
                      )}
                      <span className={`px-2 py-1 rounded text-xs ${badge.bg}`}>
                        {badge.text}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activeTab === 'soc' && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-2xl font-bold mb-4 flex items-center">
                <Bot className="w-8 h-8 mr-3 text-cyan-400" />
                Rule Recommendations ({ruleRecommendations.length})
              </h2>
              <p className="text-gray-400 mb-6">
                AI-generated detection rules from pattern analysis and ML behavioral insights
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
                          {(rec.rule_id.includes('ANOMALY') || rec.rule_id.includes('ML')) && (
                            <span className="text-xs bg-cyan-600 px-2 py-1 rounded mt-1 inline-block">
                              ML Generated
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className="text-sm text-gray-400">
                          Confidence: <span className="text-cyan-400 font-bold">{rec.confidence}%</span>
                        </span>
                        <button
                          onClick={() => applyRuleRecommendation(rec.id)}
                          className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded text-sm font-semibold transition"
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
                    <p>No recommendations yet. Analyze alerts to generate recommendations.</p>
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
                      <p className="text-sm text-gray-400">Avg CVSS</p>
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
      </div>

      {/* Alert Details Modal */}
      {selectedAlert && !showIncidentModal && !showMLModal && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50" onClick={closeAlertDetails}>
          <div className="bg-gray-800 rounded-lg p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-start mb-6">
              <div>
                <h3 className="text-2xl font-bold flex items-center">
                  <AlertTriangle className="w-6 h-6 mr-2 text-orange-400" />
                  {selectedAlert.rule_description || 'Security Event'}
                </h3>
                <p className="text-gray-400 mt-1">Alert #{selectedAlert.id} • {selectedAlert.rule_id}</p>
              </div>
              <button
                onClick={closeAlertDetails}
                className="text-gray-400 hover:text-white text-2xl"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Alert Details */}
            <div className="space-y-4 mb-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-700 rounded p-4">
                  <p className="text-sm text-gray-400 mb-1">Severity</p>
                  <span className={`px-3 py-1 rounded text-sm ${getSeverityColor(selectedAlert.severity)}`}>
                    {getSeverityBadge(selectedAlert.severity).text}
                  </span>
                </div>
                <div className="bg-gray-700 rounded p-4">
                  <p className="text-sm text-gray-400 mb-1">Host</p>
                  <p className="text-white font-semibold">{selectedAlert.host}</p>
                </div>
                <div className="bg-gray-700 rounded p-4">
                  <p className="text-sm text-gray-400 mb-1">Timestamp</p>
                  <p className="text-white">{new Date(selectedAlert.timestamp).toLocaleString()}</p>
                </div>
                <div className="bg-gray-700 rounded p-4">
                  <p className="text-sm text-gray-400 mb-1">Source IP</p>
                  <p className="text-white">{selectedAlert.raw_data?.source_ip || 'Unknown'}</p>
                </div>
              </div>

              {/* Raw Data */}
              {selectedAlert.raw_data?.log && (
                <div className="bg-gray-700 rounded p-4">
                  <p className="text-sm text-gray-400 mb-2">Log Data:</p>
                  <code className="block bg-gray-800 p-3 rounded text-cyan-400 text-sm font-mono whitespace-pre-wrap">
                    {selectedAlert.raw_data.log}
                  </code>
                </div>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex space-x-3">
              <button
                onClick={() => {
                  const report = getMLReportForAlert(selectedAlert.id);
                  if (report) {
                    setShowMLModal(true);
                  } else {
                    alert('No ML analysis available for this alert. Click "ML Analyze" to generate one.');
                  }
                }}
                className="flex-1 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 px-6 py-3 rounded-lg font-semibold flex items-center justify-center space-x-2"
              >
                <Sparkles className="w-5 h-5" />
                <span>View ML Analysis</span>
              </button>
              
              <button
                onClick={() => setShowIncidentModal(true)}
                className="flex-1 bg-purple-600 hover:bg-purple-700 px-6 py-3 rounded-lg font-semibold flex items-center justify-center space-x-2"
              >
                <FileText className="w-5 h-5" />
                <span>Incident Report</span>
              </button>

              <button
                onClick={() => analyzeAlert(selectedAlert.id)}
                disabled={analyzing}
                className="flex-1 bg-green-600 hover:bg-green-700 px-6 py-3 rounded-lg font-semibold disabled:opacity-50 flex items-center justify-center space-x-2"
              >
                <Brain className="w-5 h-5" />
                <span>{analyzing ? 'Analyzing...' : 'Run Analysis'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ML Analysis Modal */}
      {selectedAlert && showMLModal && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50" onClick={() => setShowMLModal(false)}>
          <div className="bg-gray-800 rounded-lg p-6 max-w-6xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-2xl font-bold flex items-center">
                <Sparkles className="w-6 h-6 mr-2 text-yellow-400" />
                ML Cyber Consultant Analysis
              </h3>
              <button
                onClick={() => setShowMLModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {(() => {
              const report = getMLReportForAlert(selectedAlert.id);
              if (!report) {
                return (
                  <div className="text-center py-12">
                    <Sparkles className="w-16 h-16 mx-auto mb-4 text-yellow-400 opacity-50" />
                    <p className="text-gray-400 mb-4">No ML analysis available for this alert</p>
                    <button
                      onClick={() => {
                        setShowMLModal(false);
                        analyzeAlert(selectedAlert.id);
                      }}
                      className="bg-cyan-600 hover:bg-cyan-700 px-6 py-3 rounded-lg font-semibold"
                    >
                      Run ML Analysis
                    </button>
                  </div>
                );
              }

              const mlReport = parseMLReport(report.full_report);
              if (!mlReport) {
                return <div className="text-center text-gray-400 py-8">Unable to parse ML report</div>;
              }

              return (
                <div className="space-y-6">
                  {/* Alert Info */}
                  <div className="bg-gray-700 rounded-lg p-4">
                    <h4 className="font-semibold text-white mb-2">Alert: {mlReport.alert_name || selectedAlert.rule_description}</h4>
                    <div className="flex items-center space-x-4 text-sm text-gray-400">
                      <span>Alert #{selectedAlert.id}</span>
                      <span>•</span>
                      <span>{report.severity}</span>
                      <span>•</span>
                      <span>{new Date(report.timestamp).toLocaleString()}</span>
                    </div>
                  </div>

                  {/* Behavioral Analysis */}
                  {mlReport.behavioral_analysis && (
                    <div className={`rounded-lg p-4 border ${
                      mlReport.behavioral_analysis.is_anomalous 
                        ? 'bg-red-900/20 border-red-500/30' 
                        : 'bg-cyan-900/20 border-cyan-500/30'
                    }`}>
                      <h4 className={`font-semibold mb-3 flex items-center ${
                        mlReport.behavioral_analysis.is_anomalous ? 'text-red-400' : 'text-cyan-400'
                      }`}>
                        <Brain className="w-5 h-5 mr-2" />
                        Behavioral Analysis (ML)
                      </h4>
                      
                      {mlReport.behavioral_analysis.is_anomalous ? (
                        <div>
                          <p className="text-yellow-400 font-semibold mb-2 flex items-center">
                            <AlertTriangle className="w-4 h-4 mr-1" />
                            ANOMALY DETECTED
                          </p>
                          <p className="text-sm text-gray-300 mb-3">
                            {mlReport.behavioral_analysis.interpretation}
                          </p>
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div className="bg-gray-800 rounded p-3">
                              <p className="text-gray-400 mb-1">Anomaly Score</p>
                              <p className="text-white font-bold">
                                {mlReport.behavioral_analysis.anomaly_score?.toFixed(3)}
                              </p>
                            </div>
                            <div className="bg-gray-800 rounded p-3">
                              <p className="text-gray-400 mb-1">Outlier Factors</p>
                              <p className="text-white font-bold">
                                {mlReport.behavioral_analysis.outlier_count || 0}
                              </p>
                            </div>
                          </div>
                          
                          {/* Deviations */}
                          {mlReport.behavioral_analysis.deviations && (
                            <div className="mt-4">
                              <p className="text-sm text-gray-400 mb-2">Statistical Deviations:</p>
                              <div className="grid grid-cols-2 gap-2">
                                {Object.entries(mlReport.behavioral_analysis.deviations).map(([key, value]) => (
                                  value.is_outlier && (
                                    <div key={key} className="bg-gray-800 rounded p-2 text-xs">
                                      <p className="text-red-400 font-semibold">{key.replace(/_/g, ' ').toUpperCase()}</p>
                                      <p className="text-gray-300">Z-Score: {value.z_score?.toFixed(2)}</p>
                                    </div>
                                  )
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <p className="text-sm text-green-400 flex items-center">
                          <CheckCircle className="w-4 h-4 mr-2" />
                          Behavior consistent with baseline. No anomalies detected.
                        </p>
                      )}
                    </div>
                  )}

                  {/* Risk Assessment */}
                  {mlReport.risk_assessment && (
                    <div className="bg-red-900/20 rounded-lg p-4 border border-red-500/30">
                      <h4 className="font-semibold text-red-400 mb-3 flex items-center">
                        <AlertTriangle className="w-5 h-5 mr-2" />
                        Risk Assessment
                      </h4>
                      <div className="grid grid-cols-3 gap-4 mb-4">
                        <div className="bg-gray-800 rounded p-3">
                          <p className="text-xs text-gray-400 mb-1">Risk Level</p>
                          <p className="text-lg font-bold text-white">
                            {mlReport.risk_assessment.color_indicator} {mlReport.risk_assessment.risk_level}
                          </p>
                        </div>
                        <div className="bg-gray-800 rounded p-3">
                          <p className="text-xs text-gray-400 mb-1">Risk Score</p>
                          <p className="text-lg font-bold text-white">
                            {mlReport.risk_assessment.total_score}/100
                          </p>
                        </div>
                        <div className="bg-gray-800 rounded p-3">
                          <p className="text-xs text-gray-400 mb-1">Response SLA</p>
                          <p className="text-sm text-white">
                            {mlReport.risk_assessment.recommended_response_time}
                          </p>
                        </div>
                      </div>
                      <p className="text-sm text-gray-300">
                        {mlReport.risk_assessment.business_impact}
                      </p>
                    </div>
                  )}

                  {/* Threat Predictions */}
                  {mlReport.threat_predictions?.predictions?.length > 0 && (
                    <div className="bg-purple-900/20 rounded-lg p-4 border border-purple-500/30">
                      <h4 className="font-semibold text-purple-400 mb-3 flex items-center">
                        <Target className="w-5 h-5 mr-2" />
                        Threat Predictions
                      </h4>
                      <div className="space-y-3">
                        {mlReport.threat_predictions.predictions.map((pred, i) => (
                          <div key={i} className="bg-gray-800 rounded p-3">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-sm font-semibold text-white">{pred.threat}</span>
                              <span className="text-xs text-purple-400 bg-purple-900/50 px-2 py-1 rounded">
                                {pred.probability}
                              </span>
                            </div>
                            <p className="text-xs text-gray-400 mb-2">{pred.reasoning}</p>
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-gray-500">Timeframe: {pred.timeframe}</span>
                              <span className="text-cyan-400">{pred.recommended_action}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Strategic Recommendations */}
                  {mlReport.strategic_recommendations?.length > 0 && (
                    <div className="bg-green-900/20 rounded-lg p-4 border border-green-500/30">
                      <h4 className="font-semibold text-green-400 mb-3 flex items-center">
                        <TrendingUp className="w-5 h-5 mr-2" />
                        Strategic Recommendations
                      </h4>
                      <div className="space-y-3">
                        {mlReport.strategic_recommendations.map((rec, i) => (
                          <div key={i} className="bg-gray-800 rounded p-3">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-sm font-semibold text-white">{rec.title}</span>
                              <span className={`text-xs px-2 py-1 rounded ${
                                rec.priority === 'Critical' ? 'bg-red-500' :
                                rec.priority === 'High' ? 'bg-orange-500' : 'bg-yellow-500'
                              }`}>
                                {rec.priority}
                              </span>
                            </div>
                            {rec.details?.length > 0 && (
                              <ul className="text-xs text-gray-400 mb-2 space-y-1">
                                {rec.details.map((detail, j) => (
                                  <li key={j}>• {detail}</li>
                                ))}
                              </ul>
                            )}
                            <p className="text-xs text-gray-500">
                              Implementation: {rec.implementation_time}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Executive Summary */}
                  {mlReport.consultation_summary && (
                    <div className="bg-gray-700 rounded-lg p-4">
                      <h4 className="font-semibold text-white mb-3">Executive Summary</h4>
                      <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
                        {mlReport.consultation_summary}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* Incident Report Modal */}
      {selectedAlert && showIncidentModal && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50" onClick={() => setShowIncidentModal(false)}>
          <div className="bg-gray-800 rounded-lg p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-2xl font-bold flex items-center">
                <FileText className="w-6 h-6 mr-2 text-purple-400" />
                Incident Report
              </h3>
              <button
                onClick={() => setShowIncidentModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {(() => {
              const report = getMLReportForAlert(selectedAlert.id);
              if (!report) {
                return (
                  <div className="text-center text-gray-400 py-8">
                    <FileText className="w-16 h-16 mx-auto mb-4 opacity-50" />
                    <p>No incident report available. Run ML analysis first.</p>
                  </div>
                );
              }

              return (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Incident ID</p>
                      <p className="text-white font-bold">INC-{report.id}</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Alert ID</p>
                      <p className="text-white font-bold">#{report.alert_id}</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Severity</p>
                      <span className={`px-3 py-1 rounded ${getSeverityColor(report.severity)}`}>
                        {report.severity}
                      </span>
                    </div>
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Threat Level</p>
                      <p className="text-white font-bold">{report.threat_level}</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Attack Type</p>
                      <p className="text-white">{report.attack_type}</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Source IP</p>
                      <p className="text-white">{report.source_ip}</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Affected Host</p>
                      <p className="text-white">{report.affected_host}</p>
                    </div>
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-1">Classification</p>
                      <p className="text-white">
                        {report.is_true_positive ? '✓ True Positive' : '✗ False Positive'}
                      </p>
                    </div>
                  </div>

                  {report.analysis_summary && (
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-2">Analysis Summary:</p>
                      <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
                        {report.analysis_summary}
                      </pre>
                    </div>
                  )}

                  {report.recommended_actions && (
                    <div className="bg-gray-700 rounded p-4">
                      <p className="text-sm text-gray-400 mb-3">Recommended Actions:</p>
                      <div className="space-y-2">
                        {report.recommended_actions.map((action, i) => (
                          <div key={i} className="bg-gray-800 rounded p-3">
                            <p className="text-white font-semibold mb-1">{action.title}</p>
                            {action.details && (
                              <p className="text-sm text-gray-400">{action.details[0]}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
}

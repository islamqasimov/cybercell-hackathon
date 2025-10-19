import React, { useState, useEffect } from 'react';
import { Shield, Bot, Code, AlertTriangle, CheckCircle, Brain, FileCode, Activity, Zap, TrendingUp, AlertCircle, PlayCircle, RefreshCw, FileText, Target, Sparkles } from 'lucide-react';

const API_URL = 'http://localhost:8000';

export default function MLEnhancedSecurityDashboard() {
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
      alert('✓ ML Analysis started! Check Cyber Consultant tab in 15 seconds.');
      setTimeout(() => {
        fetchRuleRecommendations();
        fetchIncidentReports();
        setActiveTab('consultant');
      }, 15000);
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

  const parseMLReport = (report) => {
    try {
      return typeof report === 'string' ? JSON.parse(report) : report;
    } catch {
      return null;
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
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
          <div className="flex space-x-3">
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
      </div>

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
              <p className="text-gray-400 text-sm">Critical Alerts</p>
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
              <p className="text-gray-400 text-sm">Attacks Validated</p>
              <p className="text-3xl font-bold text-purple-400">{stats.attacksValidated}</p>
            </div>
            <Activity className="w-10 h-10 text-purple-400 opacity-50" />
          </div>
        </div>
      </div>

      <div className="border-b border-gray-700 px-6">
        <div className="flex space-x-2 overflow-x-auto">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'consultant', label: 'ML Cyber Consultant', icon: Sparkles },
            { id: 'soc', label: 'Rule Recommendations', icon: Bot },
            { id: 'auditor', label: 'Security Auditor', icon: FileCode },
            { id: 'alerts', label: 'Live Alerts', icon: AlertTriangle }
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
                <Sparkles className="w-6 h-6 mr-2 text-yellow-400" />
                ML Intelligence Preview
              </h3>
              <div className="space-y-4">
                <div className="bg-gradient-to-r from-cyan-900/30 to-blue-900/30 rounded-lg p-4 border border-cyan-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <Brain className="w-5 h-5 text-cyan-400" />
                    <span className="font-semibold text-cyan-400">Behavioral Analysis</span>
                  </div>
                  <p className="text-sm text-gray-300">
                    ML models continuously analyze behavior patterns to detect anomalies without predefined rules.
                  </p>
                </div>
                
                <div className="bg-gradient-to-r from-purple-900/30 to-pink-900/30 rounded-lg p-4 border border-purple-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <Target className="w-5 h-5 text-purple-400" />
                    <span className="font-semibold text-purple-400">Threat Prediction</span>
                  </div>
                  <p className="text-sm text-gray-300">
                    Predictive intelligence forecasts future attack stages and provides proactive recommendations.
                  </p>
                </div>
                
                <div className="bg-gradient-to-r from-green-900/30 to-emerald-900/30 rounded-lg p-4 border border-green-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <TrendingUp className="w-5 h-5 text-green-400" />
                    <span className="font-semibold text-green-400">Risk Scoring</span>
                  </div>
                  <p className="text-sm text-gray-300">
                    Multi-factor risk assessment translates technical threats into business impact metrics.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'consultant' && (
          <div className="space-y-6">
            <div className="bg-gradient-to-r from-gray-800 to-gray-900 rounded-lg p-6 border border-cyan-500/30">
              <div className="flex items-center space-x-3 mb-4">
                <Sparkles className="w-8 h-8 text-yellow-400" />
                <div>
                  <h2 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                    ML Cyber Consultant
                  </h2>
                  <p className="text-gray-400">
                    Advanced behavioral analysis, threat prediction, and strategic intelligence
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-gray-700/50 rounded-lg p-4 border border-cyan-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <Brain className="w-5 h-5 text-cyan-400" />
                    <span className="text-sm font-semibold text-cyan-400">Behavioral Analysis</span>
                  </div>
                  <p className="text-xs text-gray-400">Detects anomalies using ML without predefined rules</p>
                </div>
                
                <div className="bg-gray-700/50 rounded-lg p-4 border border-purple-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <Target className="w-5 h-5 text-purple-400" />
                    <span className="text-sm font-semibold text-purple-400">Threat Prediction</span>
                  </div>
                  <p className="text-xs text-gray-400">Forecasts future attack stages and risks</p>
                </div>
                
                <div className="bg-gray-700/50 rounded-lg p-4 border border-green-500/30">
                  <div className="flex items-center space-x-2 mb-2">
                    <TrendingUp className="w-5 h-5 text-green-400" />
                    <span className="text-sm font-semibold text-green-400">Risk Scoring</span>
                  </div>
                  <p className="text-xs text-gray-400">Translates technical risks to business impact</p>
                </div>
              </div>

              <div className="space-y-4">
                {incidentReports.map((report, idx) => {
                  const mlReport = parseMLReport(report.full_report);
                  
                  if (!mlReport) return null;

                  return (
                    <div key={idx} className="bg-gray-700 rounded-lg p-5 border border-gray-600">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <h3 className="text-lg font-bold text-white flex items-center">
                            {report.is_false_positive ? (
                              <AlertCircle className="w-5 h-5 mr-2 text-yellow-400" />
                            ) : (
                              <CheckCircle className="w-5 h-5 mr-2 text-green-400" />
                            )}
                            Alert #{report.alert_id} - ML Analysis
                          </h3>
                          <p className="text-sm text-gray-400">
                            {report.attack_type} - {report.threat_level} Threat
                          </p>
                        </div>
                        <span className={`px-3 py-1 rounded text-sm ${getSeverityColor(report.severity)}`}>
                          {report.severity}
                        </span>
                      </div>

                      {/* Behavioral Analysis */}
                      {mlReport.behavioral_analysis && (
                        <div className="mb-4 bg-cyan-900/20 rounded-lg p-4 border border-cyan-500/30">
                          <h4 className="font-semibold text-cyan-400 mb-2 flex items-center">
                            <Brain className="w-4 h-4 mr-2" />
                            Behavioral Analysis (ML)
                          </h4>
                          {mlReport.behavioral_analysis.is_anomalous ? (
                            <div>
                              <p className="text-sm text-yellow-400 font-semibold mb-2">
                                ⚠️ ANOMALY DETECTED
                              </p>
                              <p className="text-sm text-gray-300 mb-2">
                                {mlReport.behavioral_analysis.interpretation}
                              </p>
                              <div className="text-xs text-gray-400">
                                Anomaly Score: {mlReport.behavioral_analysis.anomaly_score?.toFixed(3)}
                              </div>
                            </div>
                          ) : (
                            <p className="text-sm text-green-400">
                              ✓ Behavior consistent with baseline
                            </p>
                          )}
                        </div>
                      )}

                      {/* Risk Assessment */}
                      {mlReport.risk_assessment && (
                        <div className="mb-4 bg-red-900/20 rounded-lg p-4 border border-red-500/30">
                          <h4 className="font-semibold text-red-400 mb-2 flex items-center">
                            <AlertTriangle className="w-4 h-4 mr-2" />
                            Risk Assessment
                          </h4>
                          <div className="grid grid-cols-2 gap-4 mb-3">
                            <div>
                              <p className="text-xs text-gray-400">Risk Level</p>
                              <p className="text-lg font-bold text-white">
                                {mlReport.risk_assessment.color_indicator} {mlReport.risk_assessment.risk_level}
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-gray-400">Risk Score</p>
                              <p className="text-lg font-bold text-white">
                                {mlReport.risk_assessment.total_score}/100
                              </p>
                            </div>
                          </div>
                          <p className="text-sm text-gray-300">
                            {mlReport.risk_assessment.business_impact}
                          </p>
                        </div>
                      )}

                      {/* Threat Predictions */}
                      {mlReport.threat_predictions && mlReport.threat_predictions.predictions?.length > 0 && (
                        <div className="mb-4 bg-purple-900/20 rounded-lg p-4 border border-purple-500/30">
                          <h4 className="font-semibold text-purple-400 mb-2 flex items-center">
                            <Target className="w-4 h-4 mr-2" />
                            Threat Predictions
                          </h4>
                          <div className="space-y-2">
                            {mlReport.threat_predictions.predictions.slice(0, 3).map((pred, i) => (
                              <div key={i} className="bg-gray-800 rounded p-3">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-sm font-semibold text-white">{pred.threat}</span>
                                  <span className="text-xs text-purple-400">{pred.probability}</span>
                                </div>
                                <p className="text-xs text-gray-400 mb-1">{pred.reasoning}</p>
                                <p className="text-xs text-gray-500">Timeframe: {pred.timeframe}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Strategic Recommendations */}
                      {mlReport.strategic_recommendations && mlReport.strategic_recommendations.length > 0 && (
                        <div className="bg-green-900/20 rounded-lg p-4 border border-green-500/30">
                          <h4 className="font-semibold text-green-400 mb-2 flex items-center">
                            <TrendingUp className="w-4 h-4 mr-2" />
                            Strategic Recommendations
                          </h4>
                          <div className="space-y-2">
                            {mlReport.strategic_recommendations.slice(0, 5).map((rec, i) => (
                              <div key={i} className="bg-gray-800 rounded p-3">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-sm font-semibold text-white">{rec.title}</span>
                                  <span className={`text-xs px-2 py-1 rounded ${
                                    rec.priority === 'Critical' ? 'bg-red-500' :
                                    rec.priority === 'High' ? 'bg-orange-500' : 'bg-yellow-500'
                                  }`}>
                                    {rec.priority}
                                  </span>
                                </div>
                                {rec.details && rec.details.length > 0 && (
                                  <p className="text-xs text-gray-400">{rec.details[0]}</p>
                                )}
                                <p className="text-xs text-gray-500 mt-1">
                                  Implementation: {rec.implementation_time}
                                </p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <button
                        onClick={() => setSelectedIncident(report)}
                        className="mt-4 w-full bg-cyan-600 hover:bg-cyan-700 px-4 py-2 rounded text-sm font-semibold transition"
                      >
                        View Full ML Report
                      </button>
                    </div>
                  );
                })}

                {incidentReports.length === 0 && (
                  <div className="text-center text-gray-500 py-12">
                    <Sparkles className="w-16 h-16 mx-auto mb-4 opacity-50" />
                    <p className="text-lg mb-2">No ML analyses yet</p>
                    <p className="text-sm">Analyze alerts to see ML-powered insights</p>
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
                Rule Recommendations (Traditional + ML)
              </h2>
              <p className="text-gray-400 mb-6">
                Combining pattern-based rules with ML-generated behavioral and predictive rules
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
                          {rec.rule_id.includes('ANOMALY') && (
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
                      className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 px-4 py-2 rounded text-sm font-semibold disabled:opacity-50 transition flex items-center space-x-2"
                    >
                      <Sparkles className="w-4 h-4" />
                      <span>{analyzing ? 'Analyzing...' : 'ML Analyze'}</span>
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
              <h3 className="text-2xl font-bold flex items-center">
                <Sparkles className="w-6 h-6 mr-2 text-yellow-400" />
                Full ML Analysis Report
              </h3>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>
            <pre className="bg-gray-900 p-4 rounded text-sm text-green-400 font-mono whitespace-pre-wrap">
              {selectedIncident.analysis_summary || selectedIncident.full_report}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

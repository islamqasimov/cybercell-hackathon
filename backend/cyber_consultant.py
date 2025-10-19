"""
AI Cyber Consultant - Advanced ML-based Security Intelligence
Goes beyond rules: Behavioral analysis, anomaly detection, predictive threats
"""
import os
import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, Counter
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import re

from main import SessionLocal, Alert, DetectionRule
from ai_engine import AIEngine


class CyberConsultant:
    """
    ML-Powered Cyber Security Consultant
    
    Capabilities:
    1. Behavioral anomaly detection (no rules needed)
    2. Threat prediction based on patterns
    3. Risk scoring with business context
    4. Strategic security recommendations
    5. Attack chain reconstruction
    """
    
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42
        )
        self.scaler = StandardScaler()
        self.baseline_behaviors = {}
        self.threat_intelligence = ThreatIntelligence()
        
    async def analyze_alert_holistically(self, alert: Alert, db) -> Dict:
        """
        Comprehensive analysis beyond simple pattern matching
        """
        print(f"\n{'='*70}")
        print(f"🧠 AI CYBER CONSULTANT - Deep Analysis of Alert #{alert.id}")
        print(f"{'='*70}")
        
        # 1. Behavioral Analysis (ML-based)
        behavioral_score = await self._analyze_behavior(alert, db)
        
        # 2. Context Gathering
        context = await self._gather_threat_context(alert, db)
        
        # 3. Attack Chain Reconstruction
        attack_chain = await self._reconstruct_attack_chain(alert, db)
        
        # 4. Risk Assessment
        risk_assessment = await self._calculate_risk_score(alert, context, attack_chain)
        
        # 5. Predictive Threat Analysis
        predictions = await self._predict_future_threats(alert, context, db)
        
        # 6. Strategic Recommendations (AI-powered)
        recommendations = await self._generate_strategic_recommendations(
            alert, context, attack_chain, risk_assessment, predictions
        )
        
        # 7. Compile comprehensive report
        report = {
            "alert_id": alert.id,
            "timestamp": datetime.utcnow().isoformat(),
            "behavioral_analysis": behavioral_score,
            "threat_context": context,
            "attack_chain": attack_chain,
            "risk_assessment": risk_assessment,
            "threat_predictions": predictions,
            "strategic_recommendations": recommendations,
            "consultation_summary": await self._generate_executive_summary(
                alert, behavioral_score, context, attack_chain, risk_assessment
            )
        }
        
        return report
    
    async def _analyze_behavior(self, alert: Alert, db) -> Dict:
        """
        ML-based behavioral anomaly detection (no rules needed)
        """
        print("  🔍 Analyzing behavioral patterns...")
        
        # Get historical behavior for this host
        recent_cutoff = datetime.utcnow() - timedelta(days=7)
        historical_alerts = db.query(Alert).filter(
            Alert.host == alert.host,
            Alert.timestamp >= recent_cutoff
        ).all()
        
        if len(historical_alerts) < 5:
            return {
                "status": "insufficient_data",
                "anomaly_score": 0.5,
                "message": "Not enough historical data for baseline",
                "is_anomalous": False
            }
        
        # Extract behavioral features
        current_features = self._extract_behavioral_features(alert)
        historical_features = [
            self._extract_behavioral_features(a) for a in historical_alerts
        ]
        
        # Detect anomalies using Isolation Forest
        try:
            X_train = np.array(historical_features)
            X_current = np.array([current_features])
            
            # Fit on historical data
            self.anomaly_detector.fit(X_train)
            
            # Predict anomaly score
            anomaly_score = self.anomaly_detector.score_samples(X_current)[0]
            is_anomalous = self.anomaly_detector.predict(X_current)[0] == -1
            
            # Calculate deviation metrics
            feature_names = ['severity', 'hour_of_day', 'request_length', 
                           'special_char_count', 'numeric_density']
            deviations = {}
            
            for i, name in enumerate(feature_names):
                hist_mean = np.mean([f[i] for f in historical_features])
                hist_std = np.std([f[i] for f in historical_features])
                current_val = current_features[i]
                
                if hist_std > 0:
                    z_score = abs((current_val - hist_mean) / hist_std)
                    deviations[name] = {
                        "current": float(current_val),
                        "baseline_mean": float(hist_mean),
                        "z_score": float(z_score),
                        "is_outlier": z_score > 2.0
                    }
            
            return {
                "status": "analyzed",
                "anomaly_score": float(anomaly_score),
                "is_anomalous": bool(is_anomalous),
                "deviations": deviations,
                "baseline_samples": len(historical_alerts),
                "interpretation": self._interpret_behavioral_anomaly(
                    is_anomalous, anomaly_score, deviations
                )
            }
            
        except Exception as e:
            print(f"  ⚠️  Behavioral analysis error: {e}")
            return {
                "status": "error",
                "anomaly_score": 0.5,
                "message": str(e),
                "is_anomalous": False
            }
    
    def _extract_behavioral_features(self, alert: Alert) -> List[float]:
        """Extract numerical features for ML analysis"""
        raw_data = alert.raw_data or {}
        log = raw_data.get('log', '')
        
        return [
            float(alert.severity),
            float(alert.timestamp.hour),  # Time of day
            float(len(log)),  # Request length
            float(len(re.findall(r'[^\w\s]', log))),  # Special chars
            float(sum(c.isdigit() for c in log)) / max(len(log), 1)  # Numeric density
        ]
    
    def _interpret_behavioral_anomaly(self, is_anomalous: bool, 
                                     score: float, deviations: Dict) -> str:
        """Human-readable interpretation"""
        if not is_anomalous:
            return "Behavior consistent with baseline. No anomalies detected."
        
        outlier_features = [k for k, v in deviations.items() if v.get('is_outlier')]
        
        if not outlier_features:
            return "Minor behavioral deviation detected, but within acceptable range."
        
        interpretation = f"⚠️ ANOMALOUS BEHAVIOR: Significant deviations in {', '.join(outlier_features)}. "
        
        if 'request_length' in outlier_features:
            interpretation += "Unusually long/short requests may indicate data exfiltration or scanning. "
        
        if 'special_char_count' in outlier_features:
            interpretation += "High special character density suggests injection attempts. "
        
        if 'hour_of_day' in outlier_features:
            interpretation += "Activity during unusual hours may indicate automated attacks or insider threats. "
        
        return interpretation
    
    async def _gather_threat_context(self, alert: Alert, db) -> Dict:
        """
        Gather contextual intelligence about the threat
        """
        print("  🌐 Gathering threat intelligence context...")
        
        raw_data = alert.raw_data or {}
        source_ip = raw_data.get('source_ip', 'unknown')
        
        # Analyze attacker profile
        attacker_alerts = db.query(Alert).filter(
            Alert.raw_data['source_ip'].astext == source_ip
        ).all() if source_ip != 'unknown' else []
        
        # Check if this is part of a campaign
        similar_pattern_alerts = db.query(Alert).filter(
            Alert.rule_id == alert.rule_id,
            Alert.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).all()
        
        # Analyze attack sophistication
        sophistication = self._assess_attack_sophistication(alert)
        
        # Check threat intelligence feeds
        threat_intel = await self.threat_intelligence.lookup_threat(alert)
        
        return {
            "attacker_profile": {
                "source_ip": source_ip,
                "previous_attacks": len(attacker_alerts),
                "attack_types": list(set(a.rule_id for a in attacker_alerts)),
                "first_seen": min([a.timestamp for a in attacker_alerts]).isoformat() 
                             if attacker_alerts else alert.timestamp.isoformat(),
                "is_persistent_threat": len(attacker_alerts) > 5
            },
            "campaign_indicators": {
                "similar_attacks_24h": len(similar_pattern_alerts),
                "is_coordinated": len(similar_pattern_alerts) > 10,
                "attack_frequency": len(similar_pattern_alerts) / 24.0  # per hour
            },
            "attack_sophistication": sophistication,
            "threat_intelligence": threat_intel,
            "target_value": self._assess_target_value(alert)
        }
    
    def _assess_attack_sophistication(self, alert: Alert) -> Dict:
        """
        Assess how sophisticated the attack is
        """
        raw_data = alert.raw_data or {}
        log = raw_data.get('log', '').lower()
        
        sophistication_score = 0
        indicators = []
        
        # Check for evasion techniques
        if any(technique in log for technique in ['encoding', 'obfuscation', 'base64']):
            sophistication_score += 2
            indicators.append("Uses encoding/obfuscation")
        
        # Check for automation
        user_agent = raw_data.get('user_agent', '').lower()
        if any(tool in user_agent for tool in ['sqlmap', 'nikto', 'nmap', 'metasploit']):
            sophistication_score += 1
            indicators.append("Automated tooling detected")
        
        # Check for advanced techniques
        if 'union' in log and 'select' in log:
            sophistication_score += 2
            indicators.append("Advanced SQL injection (UNION-based)")
        
        # Check for polymorphic patterns
        if re.search(r'[\x00-\x1f\x7f-\x9f]', log):
            sophistication_score += 3
            indicators.append("Non-printable characters (evasion)")
        
        level = "Low"
        if sophistication_score >= 5:
            level = "High"
        elif sophistication_score >= 3:
            level = "Medium"
        
        return {
            "level": level,
            "score": sophistication_score,
            "indicators": indicators,
            "interpretation": f"Attack shows {level.lower()} sophistication with {len(indicators)} advanced indicators"
        }
    
    def _assess_target_value(self, alert: Alert) -> Dict:
        """
        Assess the business value/criticality of the target
        """
        high_value_endpoints = ['login', 'admin', 'payment', 'api', 'database']
        
        raw_data = alert.raw_data or {}
        log = raw_data.get('log', '').lower()
        
        value_score = 5  # Base value
        
        for endpoint in high_value_endpoints:
            if endpoint in log or endpoint in alert.host:
                value_score += 2
        
        if value_score >= 10:
            criticality = "Critical"
        elif value_score >= 7:
            criticality = "High"
        else:
            criticality = "Medium"
        
        return {
            "criticality": criticality,
            "value_score": value_score,
            "reasoning": f"Target assessed as {criticality} value based on endpoint analysis"
        }
    
    async def _reconstruct_attack_chain(self, alert: Alert, db) -> Dict:
        """
        Reconstruct the complete attack chain (MITRE ATT&CK-style)
        """
        print("  🔗 Reconstructing attack chain...")
        
        # Get alerts from same source in time window
        raw_data = alert.raw_data or {}
        source_ip = raw_data.get('source_ip', 'unknown')
        
        time_window_start = alert.timestamp - timedelta(hours=1)
        time_window_end = alert.timestamp + timedelta(hours=1)
        
        related_alerts = db.query(Alert).filter(
            Alert.raw_data['source_ip'].astext == source_ip,
            Alert.timestamp >= time_window_start,
            Alert.timestamp <= time_window_end
        ).order_by(Alert.timestamp).all() if source_ip != 'unknown' else [alert]
        
        # Map to MITRE ATT&CK stages
        attack_stages = []
        
        for a in related_alerts:
            stage = self._map_to_attack_stage(a)
            if stage:
                attack_stages.append({
                    "timestamp": a.timestamp.isoformat(),
                    "stage": stage['stage'],
                    "technique": stage['technique'],
                    "description": stage['description'],
                    "alert_id": a.id
                })
        
        # Detect attack progression
        progression = self._analyze_attack_progression(attack_stages)
        
        return {
            "stages": attack_stages,
            "progression": progression,
            "is_multi_stage": len(set(s['stage'] for s in attack_stages)) > 1,
            "timeline_span_minutes": (related_alerts[-1].timestamp - related_alerts[0].timestamp).seconds / 60
                                     if len(related_alerts) > 1 else 0,
            "interpretation": self._interpret_attack_chain(attack_stages, progression)
        }
    
    def _map_to_attack_stage(self, alert: Alert) -> Optional[Dict]:
        """Map alert to MITRE ATT&CK stage"""
        rule_id = alert.rule_id.upper()
        
        if 'SCAN' in rule_id or 'RECON' in rule_id:
            return {
                "stage": "Reconnaissance",
                "technique": "T1595 - Active Scanning",
                "description": "Attacker scanning for vulnerabilities"
            }
        
        if 'SQLI' in rule_id or 'XSS' in rule_id or 'PATH' in rule_id:
            return {
                "stage": "Initial Access",
                "technique": "T1190 - Exploit Public-Facing Application",
                "description": "Attempting to exploit web vulnerabilities"
            }
        
        if 'AUTH' in rule_id or 'BRUTE' in rule_id:
            return {
                "stage": "Credential Access",
                "technique": "T1110 - Brute Force",
                "description": "Attempting to gain credentials"
            }
        
        if 'COMMAND' in rule_id or 'EXEC' in rule_id:
            return {
                "stage": "Execution",
                "technique": "T1059 - Command Injection",
                "description": "Executing malicious commands"
            }
        
        return {
            "stage": "Unknown",
            "technique": "N/A",
            "description": "Attack stage unclear"
        }
    
    def _analyze_attack_progression(self, stages: List[Dict]) -> str:
        """Analyze if attack is progressing through stages"""
        if len(stages) <= 1:
            return "Single-stage attack"
        
        stage_order = ["Reconnaissance", "Initial Access", "Credential Access", "Execution"]
        
        observed_stages = [s['stage'] for s in stages]
        
        if all(s in stage_order for s in observed_stages):
            return "⚠️ MULTI-STAGE ATTACK DETECTED: Attacker progressing through attack chain"
        
        return "Multiple attempts at same stage"
    
    def _interpret_attack_chain(self, stages: List[Dict], progression: str) -> str:
        """Human-readable attack chain interpretation"""
        if not stages:
            return "Unable to reconstruct attack chain"
        
        unique_stages = set(s['stage'] for s in stages)
        
        interpretation = f"Attack involves {len(unique_stages)} distinct stages: {', '.join(unique_stages)}. "
        
        if "MULTI-STAGE" in progression:
            interpretation += "⚠️ This is a sophisticated, multi-stage attack indicating a determined attacker. "
            interpretation += "Immediate containment and incident response recommended. "
        else:
            interpretation += "Appears to be focused attempt at single attack vector. "
        
        return interpretation
    
    async def _calculate_risk_score(self, alert: Alert, context: Dict, 
                                    attack_chain: Dict) -> Dict:
        """
        Calculate comprehensive risk score with business context
        """
        print("  📊 Calculating risk score...")
        
        risk_factors = {}
        
        # Factor 1: Technical severity (0-25 points)
        risk_factors['technical_severity'] = min(alert.severity * 2, 25)
        
        # Factor 2: Target criticality (0-25 points)
        target_value = context['target_value']['value_score']
        risk_factors['target_criticality'] = min(target_value * 2.5, 25)
        
        # Factor 3: Attack sophistication (0-20 points)
        soph_score = context['attack_sophistication']['score']
        risk_factors['attack_sophistication'] = min(soph_score * 4, 20)
        
        # Factor 4: Persistence/Campaign (0-15 points)
        campaign_score = min(context['campaign_indicators']['similar_attacks_24h'], 15)
        risk_factors['campaign_persistence'] = campaign_score
        
        # Factor 5: Multi-stage attack (0-15 points)
        risk_factors['multi_stage_attack'] = 15 if attack_chain['is_multi_stage'] else 0
        
        total_risk_score = sum(risk_factors.values())
        
        # Risk level classification
        if total_risk_score >= 80:
            risk_level = "CRITICAL"
            color = "🔴"
        elif total_risk_score >= 60:
            risk_level = "HIGH"
            color = "🟠"
        elif total_risk_score >= 40:
            risk_level = "MEDIUM"
            color = "🟡"
        else:
            risk_level = "LOW"
            color = "🟢"
        
        return {
            "total_score": total_risk_score,
            "max_score": 100,
            "risk_level": risk_level,
            "color_indicator": color,
            "risk_factors": risk_factors,
            "business_impact": self._assess_business_impact(total_risk_score, context),
            "recommended_response_time": self._calculate_response_sla(risk_level)
        }
    
    def _assess_business_impact(self, risk_score: float, context: Dict) -> str:
        """Translate technical risk to business impact"""
        target_crit = context['target_value']['criticality']
        
        if risk_score >= 80:
            return f"SEVERE: {target_crit}-value system at immediate risk. Potential data breach, service disruption, or compliance violation."
        elif risk_score >= 60:
            return f"HIGH: {target_crit}-value system threatened. May lead to unauthorized access or data exposure."
        elif risk_score >= 40:
            return f"MODERATE: Security posture weakened. Could escalate to more serious incident if not addressed."
        else:
            return "LOW: Minimal business impact. Standard security monitoring sufficient."
    
    def _calculate_response_sla(self, risk_level: str) -> str:
        """Recommended response time SLA"""
        slas = {
            "CRITICAL": "Immediate response required (< 15 minutes)",
            "HIGH": "Urgent response (< 1 hour)",
            "MEDIUM": "Standard response (< 4 hours)",
            "LOW": "Normal processing (< 24 hours)"
        }
        return slas.get(risk_level, "Standard response")
    
    async def _predict_future_threats(self, alert: Alert, context: Dict, db) -> Dict:
        """
        Predict what might happen next based on patterns
        """
        print("  🔮 Predicting future threats...")
        
        predictions = []
        
        # Prediction 1: Escalation risk
        if context['attacker_profile']['is_persistent_threat']:
            predictions.append({
                "threat": "Attack Escalation",
                "probability": "High (75%)",
                "reasoning": "Persistent attacker likely to try alternative methods or escalate to more sophisticated attacks",
                "timeframe": "Next 24 hours",
                "recommended_action": "Enable enhanced monitoring, implement additional access controls"
            })
        
        # Prediction 2: Lateral movement
        if 'Initial Access' in str(context.get('attack_chain', {})):
            predictions.append({
                "threat": "Lateral Movement Attempt",
                "probability": "Medium (50%)",
                "reasoning": "If initial access succeeds, attacker will likely attempt to move laterally within network",
                "timeframe": "Next 6-12 hours",
                "recommended_action": "Monitor internal network traffic, segment network access"
            })
        
        # Prediction 3: Data exfiltration
        if alert.severity >= 10 and 'database' in alert.host.lower():
            predictions.append({
                "threat": "Data Exfiltration",
                "probability": "Medium (60%)",
                "reasoning": "High-severity attack on database system suggests data theft motivation",
                "timeframe": "Immediate to 2 hours",
                "recommended_action": "Monitor outbound traffic, enable DLP controls, review database access logs"
            })
        
        # Prediction 4: Attack spread
        if context['campaign_indicators']['is_coordinated']:
            predictions.append({
                "threat": "Attack Spread to Other Systems",
                "probability": "High (70%)",
                "reasoning": "Coordinated campaign suggests attacker has multiple targets",
                "timeframe": "Next 12-48 hours",
                "recommended_action": "Scan all similar systems, apply patches urgently, isolate vulnerable hosts"
            })
        
        return {
            "predictions": predictions,
            "overall_threat_trajectory": "Escalating" if len(predictions) >= 3 else "Stable",
            "confidence": "High" if context['attacker_profile']['previous_attacks'] > 3 else "Medium"
        }
    
    async def _generate_strategic_recommendations(self, alert: Alert, context: Dict,
                                                 attack_chain: Dict, risk_assessment: Dict,
                                                 predictions: Dict) -> List[Dict]:
        """
        Generate strategic, actionable recommendations using AI
        """
        print("  💡 Generating strategic recommendations...")
        
        # Prepare context for AI
        ai_context = f"""
        Alert Analysis Summary:
        - Severity: {alert.severity}
        - Target: {alert.host}
        - Attack Type: {alert.rule_description}
        - Risk Level: {risk_assessment['risk_level']}
        - Business Impact: {risk_assessment['business_impact']}
        - Attack Sophistication: {context['attack_sophistication']['level']}
        - Is Persistent Threat: {context['attacker_profile']['is_persistent_threat']}
        - Multi-Stage Attack: {attack_chain['is_multi_stage']}
        - Predicted Threats: {len(predictions['predictions'])} future threats identified
        
        Provide 5-7 strategic recommendations covering:
        1. Immediate response actions
        2. Technical remediation steps
        3. Long-term security improvements
        4. Organizational/process changes
        5. Compliance considerations
        """
        
        try:
            # Get AI recommendations
            response = await AIEngine._call_llm(ai_context)
            
            # Parse and structure
            recommendations = self._parse_ai_recommendations(response)
            
        except Exception as e:
            print(f"  ⚠️  AI recommendation error: {e}")
            # Fallback to rule-based recommendations
            recommendations = self._generate_fallback_recommendations(
                alert, context, risk_assessment
            )
        
        return recommendations
    
    def _parse_ai_recommendations(self, ai_response: str) -> List[Dict]:
        """Parse AI response into structured recommendations"""
        recommendations = []
        
        lines = ai_response.split('\n')
        current_rec = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                if current_rec:
                    recommendations.append(current_rec)
                    current_rec = {}
                continue
            
            if line[0].isdigit() and '.' in line[:3]:
                if current_rec:
                    recommendations.append(current_rec)
                current_rec = {
                    "title": line.split('.', 1)[1].strip() if '.' in line else line,
                    "details": []
                }
            elif current_rec:
                current_rec['details'].append(line)
        
        if current_rec:
            recommendations.append(current_rec)
        
        # Add metadata
        for rec in recommendations:
            rec['priority'] = self._assess_recommendation_priority(rec['title'])
            rec['implementation_time'] = self._estimate_implementation_time(rec['title'])
        
        return recommendations
    
    def _generate_fallback_recommendations(self, alert: Alert, context: Dict,
                                          risk: Dict) -> List[Dict]:
        """Fallback recommendations if AI fails"""
        recommendations = [
            {
                "title": "Block Malicious Source IP",
                "details": [f"Immediately block {context['attacker_profile']['source_ip']} at firewall"],
                "priority": "Critical",
                "implementation_time": "< 5 minutes"
            },
            {
                "title": "Review and Patch Vulnerable Endpoint",
                "details": [
                    f"Audit {alert.host} for vulnerabilities",
                    "Apply latest security patches",
                    "Review access controls"
                ],
                "priority": "High",
                "implementation_time": "< 1 hour"
            },
            {
                "title": "Enhance Monitoring",
                "details": [
                    "Enable verbose logging on affected system",
                    "Set up real-time alerts for similar patterns",
                    "Monitor for signs of compromise"
                ],
                "priority": "High",
                "implementation_time": "< 2 hours"
            }
        ]
        
        if risk['risk_level'] == "CRITICAL":
            recommendations.insert(0, {
                "title": "Activate Incident Response Team",
                "details": [
                    "Notify CISO and security team immediately",
                    "Initiate incident response playbook",
                    "Consider isolating affected systems"
                ],
                "priority": "Critical",
                "implementation_time": "Immediate"
            })
        
        return recommendations
    
    def _assess_recommendation_priority(self, title: str) -> str:
        """Determine recommendation priority"""
        critical_keywords = ['immediate', 'block', 'isolate', 'emergency']
        high_keywords = ['patch', 'review', 'audit', 'monitor']
        
        title_lower = title.lower()
        
        if any(kw in title_lower for kw in critical_keywords):
            return "Critical"
        elif any(kw in title_lower for kw in high_keywords):
            return "High"
        else:
            return "Medium"
    
    def _estimate_implementation_time(self, title: str) -> str:
        """Estimate implementation time"""
        title_lower = title.lower()
        
        if any(kw in title_lower for kw in ['block', 'disable', 'isolate']):
            return "< 15 minutes"
        elif any(kw in title_lower for kw in ['patch', 'update', 'configure']):
            return "1-4 hours"
        elif any(kw in title_lower for kw in ['implement', 'deploy', 'establish']):
            return "1-3 days"
        else:
            return "Variable"
    
    async def _generate_executive_summary(self, alert: Alert, behavioral: Dict,
                                         context: Dict, attack_chain: Dict,
                                         risk: Dict) -> str:
        """
        Generate executive summary for C-level reporting
        """
        summary = f"""
╔══════════════════════════════════════════════════════════════════╗
║              AI CYBER CONSULTANT - EXECUTIVE SUMMARY             ║
╚══════════════════════════════════════════════════════════════════╝

INCIDENT OVERVIEW
─────────────────────────────────────────────────────────────────
Alert ID: {alert.id}
Risk Level: {risk['color_indicator']} {risk['risk_level']} ({risk['total_score']}/100)
Response SLA: {risk['recommended_response_time']}

WHAT HAPPENED
─────────────────────────────────────────────────────────────────
{alert.rule_description} detected on {alert.host}
{behavioral.get('interpretation', 'Behavioral analysis unavailable')}

BUSINESS IMPACT
─────────────────────────────────────────────────────────────────
{risk['business_impact']}

THREAT INTELLIGENCE
─────────────────────────────────────────────────────────────────
Attack Sophistication: {context['attack_sophistication']['level']}
Attacker Profile: {"Persistent threat actor" if context['attacker_profile']['is_persistent_threat'] else "Opportunistic attacker"}
Attack Chain: {attack_chain.get('interpretation', 'Single-stage attack')}

KEY CONCERNS
─────────────────────────────────────────────────────────────────
"""
        
        # Add top concerns
        if context['attacker_profile']['is_persistent_threat']:
            summary += "• Persistent attacker with multiple previous attempts\n"
        
        if attack_chain['is_multi_stage']:
            summary += "• Multi-stage attack indicating sophisticated adversary\n"
        
        if context['attack_sophistication']['level'] == "High":
            summary += "• Advanced evasion techniques detected\n"
        
        if risk['total_score'] >= 80:
            summary += "• Critical systems at immediate risk\n"
        
        summary += """
BOTTOM LINE
─────────────────────────────────────────────────────────────────
"""
        
        if risk['total_score'] >= 80:
            summary += "⚠️  CRITICAL SITUATION: Immediate executive attention required.\n"
            summary += "Recommend emergency security response and possible system isolation.\n"
        elif risk['total_score'] >= 60:
            summary += "⚠️  SERIOUS THREAT: Requires urgent security team intervention.\n"
            summary += "Potential for data breach or service disruption if not addressed.\n"
        else:
            summary += "Manageable security incident requiring standard response procedures.\n"
        
        summary += """
══════════════════════════════════════════════════════════════════
Report Generated: """ + datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC') + """
Consultant: AI Cyber Security Advisor
══════════════════════════════════════════════════════════════════
"""
        
        return summary


class ThreatIntelligence:
    """
    Mock threat intelligence lookup
    In production, integrate with real threat feeds
    """
    
    async def lookup_threat(self, alert: Alert) -> Dict:
        """Look up threat in intelligence databases"""
        raw_data = alert.raw_data or {}
        source_ip = raw_data.get('source_ip', 'unknown')
        
        # Mock threat intelligence
        known_threats = {
            '10.0.0.100': {
                'reputation': 'malicious',
                'category': 'known_attacker',
                'last_seen': '2024-01-15',
                'threat_feeds': ['AbuseIPDB', 'AlienVault']
            }
        }
        
        if source_ip in known_threats:
            return {
                'is_known_threat': True,
                'details': known_threats[source_ip]
            }
        
        return {
            'is_known_threat': False,
            'details': None
        }


# Integration functions
async def run_cyber_consultant_analysis(alert_id: int):
    """
    Main entry point for Cyber Consultant analysis
    """
    db = SessionLocal()
    try:
        alert = db.query(Alert).get(alert_id)
        if not alert:
            print(f"Alert {alert_id} not found")
            return None
        
        consultant = CyberConsultant()
        report = await consultant.analyze_alert_holistically(alert, db)
        
        # Save comprehensive report to database
        from main import IncidentReport
        
        incident = IncidentReport(
            alert_id=alert.id,
            severity=report['risk_assessment']['risk_level'],
            attack_type=alert.rule_description,
            attack_pattern=alert.raw_data.get('log', '')[:200],
            is_false_positive=report['behavioral_analysis'].get('is_anomalous', False) == False,
            is_true_positive=report['behavioral_analysis'].get('is_anomalous', False) == True,
            threat_level=report['risk_assessment']['risk_level'],
            source_ip=alert.raw_data.get('source_ip', 'unknown'),
            affected_host=alert.host,
            attack_success=report['threat_context']['attack_sophistication']['level'],
            evidence=json.dumps(report['threat_context']),
            analysis_summary=report['consultation_summary'],
            recommended_actions=report['strategic_recommendations'],
            full_report=json.dumps(report, indent=2)
        )
        
        db.add(incident)
        db.commit()
        
        print("\n" + "="*70)
        print("✓ CYBER CONSULTANT ANALYSIS COMPLETE")
        print("="*70)
        print(f"\nRisk Level: {report['risk_assessment']['risk_level']}")
        print(f"Risk Score: {report['risk_assessment']['total_score']}/100")
        print(f"Behavioral Anomaly: {report['behavioral_analysis'].get('is_anomalous', False)}")
        print(f"Predictions: {len(report['threat_predictions']['predictions'])} future threats")
        print(f"Recommendations: {len(report['strategic_recommendations'])} strategic actions")
        print("\n" + report['consultation_summary'])
        
        return report
        
    except Exception as e:
        print(f"Error in cyber consultant analysis: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        db.close()


async def generate_security_posture_report(db) -> Dict:
    """
    Generate overall security posture assessment
    """
    print("\n" + "="*70)
    print("📊 GENERATING SECURITY POSTURE REPORT")
    print("="*70)
    
    # Analyze last 7 days
    cutoff = datetime.utcnow() - timedelta(days=7)
    recent_alerts = db.query(Alert).filter(Alert.timestamp >= cutoff).all()
    
    if not recent_alerts:
        return {
            "status": "healthy",
            "message": "No security incidents in last 7 days"
        }
    
    # Calculate metrics
    total_alerts = len(recent_alerts)
    critical_alerts = len([a for a in recent_alerts if a.severity >= 10])
    unique_attackers = len(set(a.raw_data.get('source_ip', 'unknown') for a in recent_alerts))
    
    # Trend analysis
    daily_counts = defaultdict(int)
    for alert in recent_alerts:
        date_key = alert.timestamp.date()
        daily_counts[date_key] += 1
    
    trend = "increasing" if list(daily_counts.values())[-1] > list(daily_counts.values())[0] else "decreasing"
    
    # Top attack types
    attack_types = Counter(a.rule_id for a in recent_alerts)
    top_attacks = attack_types.most_common(5)
    
    # Generate recommendations
    recommendations = []
    
    if critical_alerts > 10:
        recommendations.append({
            "priority": "High",
            "recommendation": "High number of critical alerts detected. Conduct security audit.",
            "impact": "Reduce attack surface and prevent potential breaches"
        })
    
    if unique_attackers > 5:
        recommendations.append({
            "priority": "High",
            "recommendation": "Multiple distinct attackers detected. Implement IP reputation filtering.",
            "impact": "Block known malicious sources automatically"
        })
    
    if trend == "increasing":
        recommendations.append({
            "priority": "Medium",
            "recommendation": "Attack frequency is increasing. Review and strengthen defenses.",
            "impact": "Prevent future attack escalation"
        })
    
    report = {
        "period": "Last 7 days",
        "summary": {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "unique_attackers": unique_attackers,
            "trend": trend
        },
        "top_attack_types": [{"type": attack, "count": count} for attack, count in top_attacks],
        "security_posture": "Poor" if critical_alerts > 20 else "Fair" if critical_alerts > 10 else "Good",
        "recommendations": recommendations
    }
    
    print(f"\nSecurity Posture: {report['security_posture']}")
    print(f"Total Alerts: {total_alerts}")
    print(f"Critical Alerts: {critical_alerts}")
    print(f"Trend: {trend}")
    print(f"\nTop Attack Types:")
    for attack_type in report['top_attack_types']:
        print(f"  • {attack_type['type']}: {attack_type['count']} incidents")
    
    return report

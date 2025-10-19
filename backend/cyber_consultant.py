"""
FIXED: AI Cyber Consultant - Advanced ML-based Security Intelligence
Improvements:
1. Better anomaly detection scoring
2. Fixed analysis return values
3. More accurate risk assessment
4. Better handling of edge cases
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
    """ML-Powered Cyber Security Consultant with improved accuracy"""
    
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.15,  # Increased sensitivity
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.baseline_behaviors = {}
        
    async def analyze_alert_holistically(self, alert: Alert, db) -> Dict:
        """Comprehensive analysis with better error handling"""
        print(f"\n{'='*70}")
        print(f"🧠 AI CYBER CONSULTANT - Deep Analysis")
        print(f"   Alert #{alert.id}: {alert.rule_description}")
        print(f"{'='*70}")
        
        try:
            # 1. Behavioral Analysis
            behavioral_score = await self._analyze_behavior(alert, db)
            
            # 2. Context Gathering
            context = await self._gather_threat_context(alert, db)
            
            # 3. Attack Chain
            attack_chain = await self._reconstruct_attack_chain(alert, db)
            
            # 4. Risk Assessment
            risk_assessment = await self._calculate_risk_score(alert, context, attack_chain)
            
            # 5. Predictions
            predictions = await self._predict_future_threats(alert, context, db)
            
            # 6. Recommendations
            recommendations = await self._generate_strategic_recommendations(
                alert, context, attack_chain, risk_assessment, predictions
            )
            
            # 7. Executive Summary
            summary = await self._generate_executive_summary(
                alert, behavioral_score, context, attack_chain, risk_assessment
            )
            
            report = {
                "alert_id": alert.id,
                "alert_name": alert.rule_description,  # FIXED: Include alert name
                "timestamp": datetime.utcnow().isoformat(),
                "behavioral_analysis": behavioral_score,
                "threat_context": context,
                "attack_chain": attack_chain,
                "risk_assessment": risk_assessment,
                "threat_predictions": predictions,
                "strategic_recommendations": recommendations,
                "consultation_summary": summary
            }
            
            print(f"\n✓ Analysis Complete")
            print(f"  Risk Level: {risk_assessment['risk_level']}")
            print(f"  Anomaly: {behavioral_score.get('is_anomalous', False)}")
            
            return report
            
        except Exception as e:
            print(f"❌ Error in ML analysis: {e}")
            import traceback
            traceback.print_exc()
            
            # Return minimal valid report instead of None
            return {
                "alert_id": alert.id,
                "alert_name": alert.rule_description,
                "timestamp": datetime.utcnow().isoformat(),
                "behavioral_analysis": {
                    "status": "error",
                    "anomaly_score": 0.5,
                    "is_anomalous": False,
                    "message": f"Analysis error: {str(e)}"
                },
                "threat_context": self._get_fallback_context(alert),
                "attack_chain": {"stages": [], "progression": "error"},
                "risk_assessment": self._get_fallback_risk(alert),
                "threat_predictions": {"predictions": [], "overall_threat_trajectory": "unknown"},
                "strategic_recommendations": self._get_fallback_recommendations(alert),
                "consultation_summary": f"Analysis encountered errors for alert #{alert.id}"
            }
    
    async def _analyze_behavior(self, alert: Alert, db) -> Dict:
        """FIXED: Better anomaly detection with proper scoring"""
        print("  🔍 Analyzing behavioral patterns...")
        
        try:
            # Get historical behavior
            recent_cutoff = datetime.utcnow() - timedelta(days=7)
            historical_alerts = db.query(Alert).filter(
                Alert.host == alert.host,
                Alert.timestamp >= recent_cutoff,
                Alert.id != alert.id  # Exclude current alert
            ).all()
            
            # Need at least 10 samples for good baseline
            if len(historical_alerts) < 10:
                print(f"  ⚠️  Only {len(historical_alerts)} baseline samples (need 10+)")
                return {
                    "status": "insufficient_data",
                    "anomaly_score": 0.5,
                    "message": f"Only {len(historical_alerts)} baseline samples available",
                    "is_anomalous": False,
                    "baseline_samples": len(historical_alerts)
                }
            
            # Extract features
            current_features = self._extract_behavioral_features(alert)
            historical_features = [
                self._extract_behavioral_features(a) for a in historical_alerts
            ]
            
            # ML anomaly detection
            X_train = np.array(historical_features)
            X_current = np.array([current_features])
            
            # Normalize features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_current_scaled = self.scaler.transform(X_current)
            
            # Fit and predict
            self.anomaly_detector.fit(X_train_scaled)
            anomaly_score = self.anomaly_detector.score_samples(X_current_scaled)[0]
            is_anomalous = self.anomaly_detector.predict(X_current_scaled)[0] == -1
            
            # Calculate deviations
            feature_names = ['severity', 'hour_of_day', 'request_length', 
                           'special_char_count', 'numeric_density']
            deviations = {}
            
            for i, name in enumerate(feature_names):
                hist_values = [f[i] for f in historical_features]
                hist_mean = np.mean(hist_values)
                hist_std = np.std(hist_values)
                current_val = current_features[i]
                
                if hist_std > 0:
                    z_score = abs((current_val - hist_mean) / hist_std)
                    deviations[name] = {
                        "current": float(current_val),
                        "baseline_mean": float(hist_mean),
                        "baseline_std": float(hist_std),
                        "z_score": float(z_score),
                        "is_outlier": z_score > 2.5  # More strict threshold
                    }
            
            # FIXED: Better severity classification
            outlier_count = sum(1 for d in deviations.values() if d.get('is_outlier'))
            severity_multiplier = 1.0
            
            if outlier_count >= 3:
                severity_multiplier = 1.5
                is_anomalous = True
            elif outlier_count >= 2:
                severity_multiplier = 1.2
                is_anomalous = True
            
            # Adjust anomaly score
            adjusted_score = anomaly_score * severity_multiplier
            
            interpretation = self._interpret_behavioral_anomaly(
                is_anomalous, adjusted_score, deviations, outlier_count
            )
            
            result = {
                "status": "analyzed",
                "anomaly_score": float(adjusted_score),
                "is_anomalous": bool(is_anomalous),
                "outlier_count": outlier_count,
                "deviations": deviations,
                "baseline_samples": len(historical_alerts),
                "interpretation": interpretation
            }
            
            print(f"  {'⚠️  ANOMALY' if is_anomalous else '✓ Normal'} (score: {adjusted_score:.3f}, outliers: {outlier_count})")
            
            return result
            
        except Exception as e:
            print(f"  ❌ Behavioral analysis error: {e}")
            return {
                "status": "error",
                "anomaly_score": 0.5,
                "message": str(e),
                "is_anomalous": False
            }
    
    def _extract_behavioral_features(self, alert: Alert) -> List[float]:
        """Extract features with better normalization"""
        raw_data = alert.raw_data or {}
        log = raw_data.get('log', '')
        
        return [
            float(alert.severity) / 12.0,  # Normalize 0-1
            float(alert.timestamp.hour) / 24.0,  # Normalize 0-1
            min(float(len(log)) / 1000.0, 1.0),  # Cap at 1000 chars
            min(float(len(re.findall(r'[^\w\s]', log))) / 50.0, 1.0),  # Cap at 50
            float(sum(c.isdigit() for c in log)) / max(len(log), 1)
        ]
    
    def _interpret_behavioral_anomaly(self, is_anomalous: bool, 
                                     score: float, deviations: Dict,
                                     outlier_count: int) -> str:
        """FIXED: Better interpretation with severity levels"""
        
        if not is_anomalous:
            return "✓ Behavior consistent with baseline. No anomalies detected."
        
        # CRITICAL ANOMALY
        if outlier_count >= 3:
            outlier_features = [k for k, v in deviations.items() if v.get('is_outlier')]
            interpretation = f"🚨 CRITICAL ANOMALY: {outlier_count} significant deviations detected in {', '.join(outlier_features)}. "
            
            if 'request_length' in outlier_features:
                interpretation += "Unusually long requests may indicate buffer overflow, data exfiltration, or DoS attempts. "
            
            if 'special_char_count' in outlier_features:
                interpretation += "High special character density strongly suggests injection attack or encoding evasion. "
            
            if 'hour_of_day' in outlier_features:
                interpretation += "Activity during unusual hours indicates automated attack or insider threat. "
            
            return interpretation
        
        # HIGH ANOMALY
        elif outlier_count == 2:
            outlier_features = [k for k, v in deviations.items() if v.get('is_outlier')]
            return f"⚠️  HIGH ANOMALY: Multiple deviations in {', '.join(outlier_features)}. Likely attack pattern variation or reconnaissance."
        
        # MEDIUM ANOMALY
        elif outlier_count == 1:
            outlier_features = [k for k, v in deviations.items() if v.get('is_outlier')]
            return f"⚠️  MEDIUM ANOMALY: Deviation in {outlier_features[0]}. May indicate attack experimentation or legitimate unusual activity."
        
        return "Minor behavioral deviation detected, within acceptable range."
    
    async def _gather_threat_context(self, alert: Alert, db) -> Dict:
        """Gather threat intelligence with better defaults"""
        print("  🌐 Gathering threat context...")
        
        try:
            raw_data = alert.raw_data or {}
            source_ip = raw_data.get('source_ip', 'unknown')
            
            # Analyze attacker profile
            attacker_alerts = []
            if source_ip != 'unknown':
                attacker_alerts = db.query(Alert).filter(
                    Alert.raw_data['source_ip'].astext == source_ip
                ).all()
            
            # Check for campaign
            similar_pattern_alerts = db.query(Alert).filter(
                Alert.rule_id == alert.rule_id,
                Alert.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).all()
            
            sophistication = self._assess_attack_sophistication(alert)
            
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
                    "attack_frequency": len(similar_pattern_alerts) / 24.0
                },
                "attack_sophistication": sophistication,
                "target_value": self._assess_target_value(alert)
            }
        except Exception as e:
            print(f"  ❌ Context gathering error: {e}")
            return self._get_fallback_context(alert)
    
    def _assess_attack_sophistication(self, alert: Alert) -> Dict:
        """Better sophistication assessment"""
        raw_data = alert.raw_data or {}
        log = raw_data.get('log', '').lower()
        
        sophistication_score = 0
        indicators = []
        
        # Check for evasion
        if any(tech in log for tech in ['base64', 'hex', 'unicode', 'encode', '%']):
            sophistication_score += 3
            indicators.append("Encoding/obfuscation detected")
        
        # Check for automation
        user_agent = raw_data.get('user_agent', '').lower()
        if any(tool in user_agent for tool in ['sqlmap', 'nikto', 'nmap', 'burp', 'metasploit']):
            sophistication_score += 2
            indicators.append("Professional tools detected")
        
        # Advanced techniques
        if 'union' in log and 'select' in log:
            sophistication_score += 3
            indicators.append("Advanced SQL injection (UNION)")
        
        if re.search(r'sleep\(|waitfor|benchmark', log):
            sophistication_score += 2
            indicators.append("Time-based blind injection")
        
        # Polymorphic patterns
        if re.search(r'[\x00-\x1f\x7f-\x9f]', log):
            sophistication_score += 4
            indicators.append("Non-printable character evasion")
        
        level = "Low"
        if sophistication_score >= 7:
            level = "High"
        elif sophistication_score >= 4:
            level = "Medium"
        
        return {
            "level": level,
            "score": sophistication_score,
            "indicators": indicators,
            "interpretation": f"Attack shows {level.lower()} sophistication with {len(indicators)} advanced techniques"
        }
    
    def _assess_target_value(self, alert: Alert) -> Dict:
        """Assess target criticality"""
        high_value_endpoints = ['login', 'admin', 'payment', 'api', 'database', 'user', 'auth']
        
        raw_data = alert.raw_data or {}
        log = raw_data.get('log', '').lower()
        
        value_score = 5
        
        for endpoint in high_value_endpoints:
            if endpoint in log or endpoint in alert.host.lower():
                value_score += 2
        
        if value_score >= 11:
            criticality = "Critical"
        elif value_score >= 8:
            criticality = "High"
        else:
            criticality = "Medium"
        
        return {
            "criticality": criticality,
            "value_score": value_score,
            "reasoning": f"Target assessed as {criticality} value based on endpoint analysis"
        }
    
    async def _reconstruct_attack_chain(self, alert: Alert, db) -> Dict:
        """Reconstruct attack progression"""
        print("  🔗 Reconstructing attack chain...")
        
        try:
            raw_data = alert.raw_data or {}
            source_ip = raw_data.get('source_ip', 'unknown')
            
            time_window_start = alert.timestamp - timedelta(hours=1)
            time_window_end = alert.timestamp + timedelta(hours=1)
            
            related_alerts = []
            if source_ip != 'unknown':
                related_alerts = db.query(Alert).filter(
                    Alert.raw_data['source_ip'].astext == source_ip,
                    Alert.timestamp >= time_window_start,
                    Alert.timestamp <= time_window_end
                ).order_by(Alert.timestamp).all()
            else:
                related_alerts = [alert]
            
            attack_stages = []
            for a in related_alerts:
                stage = self._map_to_attack_stage(a)
                if stage:
                    attack_stages.append({
                        "timestamp": a.timestamp.isoformat(),
                        "stage": stage['stage'],
                        "technique": stage['technique'],
                        "description": stage['description'],
                        "alert_id": a.id,
                        "alert_name": a.rule_description
                    })
            
            progression = self._analyze_attack_progression(attack_stages)
            
            return {
                "stages": attack_stages,
                "progression": progression,
                "is_multi_stage": len(set(s['stage'] for s in attack_stages)) > 1,
                "timeline_span_minutes": (related_alerts[-1].timestamp - related_alerts[0].timestamp).seconds / 60
                                         if len(related_alerts) > 1 else 0,
                "interpretation": self._interpret_attack_chain(attack_stages, progression)
            }
        except Exception as e:
            print(f"  ❌ Attack chain error: {e}")
            return {"stages": [], "progression": "error", "is_multi_stage": False}
    
    def _map_to_attack_stage(self, alert: Alert) -> Optional[Dict]:
        """Map alert to MITRE ATT&CK"""
        rule_id = alert.rule_id.upper()
        
        if 'SCAN' in rule_id or 'RECON' in rule_id:
            return {
                "stage": "Reconnaissance",
                "technique": "T1595",
                "description": "Active Scanning"
            }
        
        if 'SQLI' in rule_id or 'XSS' in rule_id or 'PATH' in rule_id:
            return {
                "stage": "Initial Access",
                "technique": "T1190",
                "description": "Exploit Public-Facing Application"
            }
        
        if 'AUTH' in rule_id or 'BRUTE' in rule_id:
            return {
                "stage": "Credential Access",
                "technique": "T1110",
                "description": "Brute Force"
            }
        
        if 'COMMAND' in rule_id or 'EXEC' in rule_id:
            return {
                "stage": "Execution",
                "technique": "T1059",
                "description": "Command Injection"
            }
        
        return {
            "stage": "Unknown",
            "technique": "N/A",
            "description": "Unclassified attack"
        }
    
    def _analyze_attack_progression(self, stages: List[Dict]) -> str:
        """Analyze attack progression"""
        if len(stages) <= 1:
            return "Single-stage attack"
        
        stage_order = ["Reconnaissance", "Initial Access", "Credential Access", "Execution"]
        observed_stages = [s['stage'] for s in stages]
        
        if all(s in stage_order for s in observed_stages):
            return "⚠️  MULTI-STAGE ATTACK: Attacker progressing through kill chain"
        
        return "Multiple attempts at same stage"
    
    def _interpret_attack_chain(self, stages: List[Dict], progression: str) -> str:
        """Interpret attack chain"""
        if not stages:
            return "Unable to reconstruct attack chain"
        
        unique_stages = set(s['stage'] for s in stages)
        
        interpretation = f"Attack involves {len(unique_stages)} distinct stages: {', '.join(unique_stages)}. "
        
        if "MULTI-STAGE" in progression:
            interpretation += "🚨 Sophisticated multi-stage attack by determined adversary. Immediate containment required."
        else:
            interpretation += "Focused attempt at single attack vector."
        
        return interpretation
    
    async def _calculate_risk_score(self, alert: Alert, context: Dict, 
                                    attack_chain: Dict) -> Dict:
        """Calculate comprehensive risk score"""
        print("  📊 Calculating risk score...")
        
        risk_factors = {}
        
        # Factor 1: Technical severity
        risk_factors['technical_severity'] = min(alert.severity * 2, 25)
        
        # Factor 2: Target criticality
        target_value = context['target_value']['value_score']
        risk_factors['target_criticality'] = min(target_value * 2.5, 25)
        
        # Factor 3: Attack sophistication
        soph_score = context['attack_sophistication']['score']
        risk_factors['attack_sophistication'] = min(soph_score * 4, 20)
        
        # Factor 4: Campaign persistence
        campaign_score = min(context['campaign_indicators']['similar_attacks_24h'], 15)
        risk_factors['campaign_persistence'] = campaign_score
        
        # Factor 5: Multi-stage attack
        risk_factors['multi_stage_attack'] = 15 if attack_chain['is_multi_stage'] else 0
        
        total_risk_score = sum(risk_factors.values())
        
        # Risk level
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
            return f"SEVERE: {target_crit}-value system at immediate risk. Potential data breach, service disruption."
        elif risk_score >= 60:
            return f"HIGH: {target_crit}-value system threatened. May lead to unauthorized access."
        elif risk_score >= 40:
            return f"MODERATE: Security posture weakened. Could escalate if not addressed."
        else:
            return "LOW: Minimal business impact. Standard monitoring sufficient."
    
    def _calculate_response_sla(self, risk_level: str) -> str:
        """Response time SLA"""
        slas = {
            "CRITICAL": "Immediate response (< 15 min)",
            "HIGH": "Urgent response (< 1 hour)",
            "MEDIUM": "Standard response (< 4 hours)",
            "LOW": "Normal processing (< 24 hours)"
        }
        return slas.get(risk_level, "Standard response")
    
    async def _predict_future_threats(self, alert: Alert, context: Dict, db) -> Dict:
        """Predict future threats"""
        print("  🔮 Predicting future threats...")
        
        predictions = []
        
        if context['attacker_profile']['is_persistent_threat']:
            predictions.append({
                "threat": "Attack Escalation",
                "probability": "High (75%)",
                "reasoning": "Persistent attacker will try alternative methods",
                "timeframe": "Next 24 hours",
                "recommended_action": "Enable enhanced monitoring"
            })
        
        if alert.severity >= 10:
            predictions.append({
                "threat": "Data Exfiltration",
                "probability": "Medium (60%)",
                "reasoning": "High-severity attack on critical system suggests data theft motivation",
                "timeframe": "Immediate to 2 hours",
                "recommended_action": "Monitor outbound traffic, enable DLP"
            })
        
        if context['campaign_indicators']['is_coordinated']:
            predictions.append({
                "threat": "Attack Spread to Other Systems",
                "probability": "High (70%)",
                "reasoning": "Coordinated campaign indicates multiple targets",
                "timeframe": "Next 12-48 hours",
                "recommended_action": "Scan all systems, apply patches"
            })
        
        return {
            "predictions": predictions,
            "overall_threat_trajectory": "Escalating" if len(predictions) >= 2 else "Stable",
            "confidence": "High" if context['attacker_profile']['previous_attacks'] > 3 else "Medium"
        }
    
    async def _generate_strategic_recommendations(self, alert: Alert, context: Dict,
                                                 attack_chain: Dict, risk: Dict,
                                                 predictions: Dict) -> List[Dict]:
        """Generate strategic recommendations"""
        print("  💡 Generating recommendations...")
        
        recommendations = []
        
        # Block malicious IP
        source_ip = alert.raw_data.get('source_ip', 'unknown')
        if source_ip != 'unknown':
            recommendations.append({
                "title": "Block Malicious Source IP",
                "details": [f"Block {source_ip} at firewall immediately"],
                "priority": "Critical",
                "implementation_time": "< 5 minutes"
            })
        
        # Patch vulnerability
        recommendations.append({
            "title": "Review and Patch Vulnerable Endpoint",
            "details": [
                f"Audit {alert.host} for vulnerabilities",
                "Apply latest security patches"
            ],
            "priority": "High",
            "implementation_time": "< 1 hour"
        })
        
        # Enhanced monitoring
        if risk['risk_level'] in ["CRITICAL", "HIGH"]:
            recommendations.append({
                "title": "Enable Enhanced Monitoring",
                "details": [
                    "Verbose logging on affected system",
                    "Real-time alerting for similar patterns"
                ],
                "priority": "High",
                "implementation_time": "< 30 minutes"
            })
        
        return recommendations
    
    async def _generate_executive_summary(self, alert: Alert, behavioral: Dict,
                                         context: Dict, attack_chain: Dict,
                                         risk: Dict) -> str:
        """Generate executive summary"""
        
        summary = f"""
╔══════════════════════════════════════════════════════════════════╗
║              AI CYBER CONSULTANT - EXECUTIVE SUMMARY             ║
╚══════════════════════════════════════════════════════════════════╝

INCIDENT: {alert.rule_description}
Alert ID: {alert.id}
Risk Level: {risk['color_indicator']} {risk['risk_level']} ({risk['total_score']}/100)
Response SLA: {risk['recommended_response_time']}

BEHAVIORAL ANALYSIS
─────────────────────────────────────────────────────────────────
{behavioral.get('interpretation', 'Analysis unavailable')}

BUSINESS IMPACT
─────────────────────────────────────────────────────────────────
{risk['business_impact']}

THREAT INTELLIGENCE
─────────────────────────────────────────────────────────────────
Attack Sophistication: {context['attack_sophistication']['level']}
Attacker Profile: {"Persistent threat" if context['attacker_profile']['is_persistent_threat'] else "Opportunistic"}
Attack Chain: {attack_chain.get('interpretation', 'Single-stage')}

BOTTOM LINE
─────────────────────────────────────────────────────────────────
"""
        
        if risk['total_score'] >= 80:
            summary += "🚨 CRITICAL: Immediate executive attention required.\n"
        elif risk['total_score'] >= 60:
            summary += "⚠️  SERIOUS: Urgent security team intervention needed.\n"
        else:
            summary += "Manageable incident requiring standard response.\n"
        
        summary += f"""
══════════════════════════════════════════════════════════════════
Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
══════════════════════════════════════════════════════════════════
"""
        
        return summary
    
    # Fallback methods
    def _get_fallback_context(self, alert: Alert) -> Dict:
        """Fallback context"""
        return {
            "attacker_profile": {
                "source_ip": alert.raw_data.get('source_ip', 'unknown'),
                "previous_attacks": 0,
                "attack_types": [],
                "is_persistent_threat": False
            },
            "campaign_indicators": {
                "similar_attacks_24h": 0,
                "is_coordinated": False
            },
            "attack_sophistication": {
                "level": "Unknown",
                "score": 0,
                "indicators": []
            },
            "target_value": {
                "criticality": "Medium",
                "value_score": 5
            }
        }
    
    def _get_fallback_risk(self, alert: Alert) -> Dict:
        """Fallback risk assessment"""
        return {
            "total_score": alert.severity * 5,
            "max_score": 100,
            "risk_level": "MEDIUM",
            "color_indicator": "🟡",
            "risk_factors": {},
            "business_impact": "Impact assessment unavailable",
            "recommended_response_time": "Standard response"
        }
    
    def _get_fallback_recommendations(self, alert: Alert) -> List[Dict]:
        """Fallback recommendations"""
        return [{
            "title": "Investigate Alert",
            "details": [f"Review alert #{alert.id} manually"],
            "priority": "Medium",
            "implementation_time": "< 1 hour"
        }]


# Integration function
async def run_cyber_consultant_analysis(alert_id: int):
    """Main entry point"""
    db = SessionLocal()
    try:
        alert = db.query(Alert).get(alert_id)
        if not alert:
            print(f"Alert {alert_id} not found")
            return None
        
        consultant = CyberConsultant()
        report = await consultant.analyze_alert_holistically(alert, db)
        
        if not report:
            print(f"❌ No report generated for alert {alert_id}")
            return None
        
        # Save to database
        from main import IncidentReport
        
        incident = IncidentReport(
            alert_id=alert.id,
            severity=report['risk_assessment']['risk_level'],
            attack_type=alert.rule_description,
            attack_pattern=alert.raw_data.get('log', '')[:200],
            is_false_positive=not report['behavioral_analysis'].get('is_anomalous', False),
            is_true_positive=report['behavioral_analysis'].get('is_anomalous', False),
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
        print("✓ CYBER CONSULTANT ANALYSIS SAVED")
        print("="*70)
        
        return report
        
    except Exception as e:
        print(f"❌ Error in cyber consultant: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        db.close()

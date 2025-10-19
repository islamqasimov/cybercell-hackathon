"""
Enhanced SOC Analyst - Now with ML-powered Cyber Consultant
Combines rule-based detection with behavioral analysis and predictive intelligence
"""
from sqlalchemy.orm import Session
from main import SessionLocal, Alert, RuleRecommendation, DetectionRule
from datetime import timedelta, datetime
import re
from collections import Counter
from ai_engine import AIEngine
import json

# Import the new Cyber Consultant
from cyber_consultant import CyberConsultant, run_cyber_consultant_analysis


async def analyze_and_recommend(alert_id: int):
    """
    Enhanced analysis combining traditional SIEM with ML-powered Cyber Consultant
    
    Two-tier approach:
    1. Traditional rule-based analysis (fast, for known patterns)
    2. ML Cyber Consultant (deep, for unknown threats and strategic guidance)
    """
    db = SessionLocal()
    try:
        alert = db.query(Alert).get(alert_id)
        if not alert:
            print(f"Alert {alert_id} not found")
            return
        
        print(f"\n{'='*70}")
        print(f"🤖 ENHANCED SOC ANALYST - Analyzing Alert #{alert_id}")
        print(f"{'='*70}")
        
        # TIER 1: Quick rule-based analysis (original functionality)
        print("\n[TIER 1] Quick Pattern Matching...")
        traditional_analysis = await perform_traditional_analysis(alert, db)
        
        # TIER 2: Deep ML-powered Cyber Consultant analysis
        print("\n[TIER 2] Deep ML Analysis with Cyber Consultant...")
        consultant_report = await run_cyber_consultant_analysis(alert_id)
        
        # Combine insights
        if consultant_report:
            print("\n" + "="*70)
            print("✓ ANALYSIS COMPLETE - Two-Tier Intelligence Generated")
            print("="*70)
            
            # Show key findings
            print(f"\n📊 Risk Assessment:")
            print(f"   Level: {consultant_report['risk_assessment']['risk_level']}")
            print(f"   Score: {consultant_report['risk_assessment']['total_score']}/100")
            print(f"   Business Impact: {consultant_report['risk_assessment']['business_impact'][:100]}...")
            
            print(f"\n🧠 Behavioral Analysis:")
            behavioral = consultant_report['behavioral_analysis']
            if behavioral.get('is_anomalous'):
                print(f"   ⚠️  ANOMALY DETECTED")
                print(f"   Anomaly Score: {behavioral.get('anomaly_score', 0):.3f}")
                print(f"   {behavioral.get('interpretation', 'Unknown')[:150]}...")
            else:
                print(f"   ✓ Behavior within baseline")
            
            print(f"\n🔮 Threat Predictions:")
            predictions = consultant_report['threat_predictions']['predictions']
            for pred in predictions[:3]:
                print(f"   • {pred['threat']} ({pred['probability']})")
            
            print(f"\n💡 Strategic Recommendations: {len(consultant_report['strategic_recommendations'])} actions")
            for i, rec in enumerate(consultant_report['strategic_recommendations'][:3], 1):
                print(f"   {i}. [{rec['priority']}] {rec['title']}")
        
        # Generate rule recommendations from both analyses
        await generate_combined_recommendations(
            alert, traditional_analysis, consultant_report, db
        )
        
        print(f"\n{'='*70}\n")
        
    except Exception as e:
        print(f"Error analyzing alert {alert_id}: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()


async def perform_traditional_analysis(alert: Alert, db) -> dict:
    """
    Traditional SIEM-style rule-based analysis
    Fast pattern matching for known attack signatures
    """
    alert_data = {
        'id': alert.id,
        'rule_id': alert.rule_id,
        'rule_description': alert.rule_description,
        'host': alert.host,
        'severity': alert.severity,
        'timestamp': alert.timestamp.isoformat(),
        'raw_data': alert.raw_data or {}
    }
    
    # Get historical context
    recent_cutoff = datetime.utcnow() - timedelta(hours=24)
    similar_alerts = db.query(Alert).filter(
        Alert.rule_id == alert.rule_id,
        Alert.timestamp >= recent_cutoff
    ).all()
    
    alert_data['similar_count'] = len(similar_alerts)
    
    # Try AI-powered analysis first
    try:
        analysis = await AIEngine.analyze_alert_with_llm(alert_data)
    except Exception as e:
        print(f"  AI analysis unavailable, using pattern-based: {e}")
        analysis = generate_fallback_analysis(alert_data, similar_alerts)
    
    return analysis


async def generate_combined_recommendations(alert: Alert, traditional: dict, 
                                          consultant: dict, db):
    """
    Combine recommendations from both traditional SIEM and ML Cyber Consultant
    Provides both tactical (rules) and strategic (process) recommendations
    """
    print("\n🎯 Generating Combined Recommendations...")
    
    created_count = 0
    
    # 1. Traditional rule recommendations (tactical)
    if traditional and 'recommendations' in traditional:
        print("  → Processing tactical rule recommendations...")
        for rec_data in traditional['recommendations']:
            if await create_rule_recommendation(rec_data, alert, db):
                created_count += 1
    
    # 2. ML-based strategic recommendations
    if consultant and 'strategic_recommendations' in consultant:
        print("  → Processing strategic ML recommendations...")
        
        # Convert strategic recommendations to actionable rules
        strategic_rules = await convert_strategic_to_rules(
            consultant['strategic_recommendations'],
            consultant['behavioral_analysis'],
            consultant['threat_predictions'],
            alert
        )
        
        for rule_rec in strategic_rules:
            if await create_rule_recommendation(rule_rec, alert, db):
                created_count += 1
    
    # 3. Behavioral anomaly recommendations
    if consultant and consultant['behavioral_analysis'].get('is_anomalous'):
        print("  → Generating anomaly-based recommendations...")
        anomaly_rules = await generate_anomaly_rules(
            alert, consultant['behavioral_analysis'], db
        )
        
        for rule_rec in anomaly_rules:
            if await create_rule_recommendation(rule_rec, alert, db):
                created_count += 1
    
    db.commit()
    print(f"\n  ✓ Created {created_count} new recommendations")


async def create_rule_recommendation(rec_data: dict, alert: Alert, db) -> bool:
    """
    Create a rule recommendation in database (with deduplication)
    """
    rule_id = rec_data['rule_id']
    action = rec_data['action']
    
    # Check for duplicates
    existing = db.query(RuleRecommendation).filter(
        RuleRecommendation.rule_id == rule_id,
        RuleRecommendation.action == action,
        RuleRecommendation.applied == False
    ).first()
    
    if existing:
        # Update confidence and evidence
        existing.confidence = max(existing.confidence, rec_data.get('confidence', 85))
        existing.evidence_count += 1
        return False
    
    # Check if rule already exists (for CREATE action)
    if action == "CREATE":
        existing_rule = db.query(DetectionRule).filter(
            DetectionRule.rule_id == rule_id
        ).first()
        if existing_rule:
            return False
    
    # Create new recommendation
    rec = RuleRecommendation(
        action=action,
        rule_id=rule_id,
        reason=rec_data.get('reason', 'ML-generated recommendation'),
        current_pattern=rec_data.get('current_pattern'),
        suggested_pattern=rec_data.get('suggested_pattern', '.*'),
        severity=rec_data.get('severity', 'medium'),
        confidence=rec_data.get('confidence', 85),
        evidence_count=1
    )
    db.add(rec)
    return True


async def convert_strategic_to_rules(strategic_recs: list, behavioral: dict, 
                                    predictions: dict, alert: Alert) -> list:
    """
    Convert high-level strategic recommendations into concrete detection rules
    
    This is the innovation: translating business/security strategy into technical rules
    """
    rules = []
    
    for rec in strategic_recs:
        title = rec['title'].lower()
        
        # Block malicious sources
        if 'block' in title and 'ip' in title:
            source_ip = alert.raw_data.get('source_ip', 'unknown')
            if source_ip != 'unknown':
                rules.append({
                    'action': 'CREATE',
                    'rule_id': f'BLOCK-IP-{source_ip.replace(".", "-")}',
                    'reason': f'ML Consultant: {rec["title"]} - {rec.get("details", [""])[0] if rec.get("details") else ""}',
                    'suggested_pattern': f'source_ip:{source_ip}',
                    'severity': 'critical',
                    'confidence': 95
                })
        
        # Enhanced monitoring
        elif 'monitor' in title or 'logging' in title:
            rules.append({
                'action': 'CREATE',
                'rule_id': f'MONITOR-ENHANCED-{alert.host.upper()}',
                'reason': f'ML Consultant: Behavioral anomaly detected. {behavioral.get("interpretation", "")}',
                'suggested_pattern': f'host:{alert.host}.*anomaly',
                'severity': 'medium',
                'confidence': 80
            })
        
        # Patch vulnerabilities
        elif 'patch' in title or 'vulnerability' in title:
            rules.append({
                'action': 'MODIFY',
                'rule_id': alert.rule_id,
                'reason': f'ML Consultant: Strengthen detection for vulnerable endpoint. Risk score: {predictions.get("overall_threat_trajectory", "unknown")}',
                'current_pattern': '.*',
                'suggested_pattern': f'({alert.rule_id}|similar_pattern).*{alert.host}',
                'severity': 'high',
                'confidence': 85
            })
        
        # Predictive rules based on future threats
        elif 'prevent' in title or 'proactive' in title:
            for pred in predictions.get('predictions', [])[:2]:
                threat_type = pred['threat'].lower().replace(' ', '_')
                rules.append({
                    'action': 'CREATE',
                    'rule_id': f'PREDICT-{threat_type.upper()}-001',
                    'reason': f'ML Prediction ({pred["probability"]}): {pred["reasoning"]}',
                    'suggested_pattern': f'.*({threat_type}|related_pattern).*',
                    'severity': 'high',
                    'confidence': 75
                })
    
    return rules


async def generate_anomaly_rules(alert: Alert, behavioral: dict, db) -> list:
    """
    Generate rules specifically for detected behavioral anomalies
    
    This catches zero-day threats that don't match any existing rules
    """
    rules = []
    
    if not behavioral.get('is_anomalous'):
        return rules
    
    deviations = behavioral.get('deviations', {})
    
    # Rule for unusual request length
    if 'request_length' in deviations and deviations['request_length'].get('is_outlier'):
        z_score = deviations['request_length']['z_score']
        rules.append({
            'action': 'CREATE',
            'rule_id': f'ANOMALY-LENGTH-{alert.host.upper()}',
            'reason': f'ML Anomaly Detection: Request length {z_score:.1f} standard deviations from baseline. May indicate data exfiltration or buffer overflow attempts.',
            'suggested_pattern': f'request_size:(>{deviations["request_length"]["current"]}|unusual)',
            'severity': 'high',
            'confidence': 88
        })
    
    # Rule for unusual timing
    if 'hour_of_day' in deviations and deviations['hour_of_day'].get('is_outlier'):
        rules.append({
            'action': 'CREATE',
            'rule_id': f'ANOMALY-TIMING-{alert.host.upper()}',
            'reason': 'ML Anomaly Detection: Activity during unusual hours. Potential insider threat or automated attack.',
            'suggested_pattern': f'time:(off_hours).*host:{alert.host}',
            'severity': 'medium',
            'confidence': 75
        })
    
    # Rule for unusual character patterns
    if 'special_char_count' in deviations and deviations['special_char_count'].get('is_outlier'):
        rules.append({
            'action': 'CREATE',
            'rule_id': f'ANOMALY-CHARS-{alert.rule_id}',
            'reason': 'ML Anomaly Detection: Unusual special character density. Possible injection attempt or encoding evasion.',
            'suggested_pattern': r'[^\w\s]{10,}',  # 10+ special chars
            'severity': 'high',
            'confidence': 82
        })
    
    return rules


def generate_fallback_analysis(alert_data: dict, similar_alerts: list) -> dict:
    """
    Fallback pattern-based analysis (original functionality)
    """
    rule_id = alert_data.get('rule_id', '')
    rule_desc = alert_data.get('rule_description', '').lower()
    raw_data = alert_data.get('raw_data', {})
    log = raw_data.get('log', '')
    
    recommendations = []
    attack_analysis = "Pattern-based analysis performed. "
    
    # SQL Injection patterns
    if 'sql' in rule_desc or 'injection' in rule_desc:
        attack_analysis += "SQL injection attack detected. "
        
        if '--' in log:
            recommendations.append({
                "action": "CREATE",
                "rule_id": "SQLI-COMMENT-001",
                "reason": "SQL comment injection detected (--). Common authentication bypass technique.",
                "suggested_pattern": r"['\"]--",
                "severity": "high",
                "confidence": 85
            })
        
        if 'union' in log.lower():
            recommendations.append({
                "action": "CREATE",
                "rule_id": "SQLI-UNION-001",
                "reason": "SQL UNION attack for data exfiltration detected.",
                "suggested_pattern": r"union\s+(all\s+)?select",
                "severity": "critical",
                "confidence": 90
            })
    
    # XSS patterns
    elif 'xss' in rule_desc or 'script' in rule_desc:
        attack_analysis += "Cross-site scripting (XSS) attack detected. "
        
        if '<script' in log.lower():
            recommendations.append({
                "action": "CREATE",
                "rule_id": "XSS-SCRIPT-001",
                "reason": "Script tag injection can lead to session hijacking.",
                "suggested_pattern": r"<script[^>]*>",
                "severity": "medium",
                "confidence": 85
            })
    
    # Path Traversal
    elif 'path' in rule_desc or 'traversal' in rule_desc:
        attack_analysis += "Path traversal attack detected. "
        
        recommendations.append({
            "action": "CREATE",
            "rule_id": "PATH-DOTDOT-001",
            "reason": "Directory traversal can expose sensitive files.",
            "suggested_pattern": r"\.\./|\.\.\\",
            "severity": "high",
            "confidence": 90
        })
    
    # High frequency = possible false positive
    if len(similar_alerts) > 50:
        recommendations.append({
            "action": "DISABLE",
            "rule_id": rule_id,
            "reason": f"Rule triggered {len(similar_alerts)} times in 24h. High false positive rate.",
            "severity": "low",
            "confidence": 85
        })
    
    return {
        "attack_analysis": attack_analysis,
        "recommendations": recommendations
    }

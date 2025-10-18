from sqlalchemy.orm import Session
from main import SessionLocal, Alert, RuleRecommendation, DetectionRule
import re
from collections import Counter

async def analyze_and_recommend(alert_id: int):
    """AI SOC Analyst - analyzes alert and recommends rules"""
    db = SessionLocal()
    try:
        alert = db.query(Alert).get(alert_id)
        if not alert:
            return
        
        # Get recent similar alerts
        similar_alerts = db.query(Alert).filter(
            Alert.rule_id == alert.rule_id,
            Alert.timestamp >= alert.timestamp - timedelta(hours=24)
        ).all()
        
        # Analyze patterns
        patterns = extract_attack_patterns(alert, similar_alerts)
        
        # Generate recommendations
        for pattern in patterns:
            # Check if pattern covered by existing rules
            existing = db.query(DetectionRule).filter(
                DetectionRule.pattern.contains(pattern['pattern'])
            ).first()
            
            if not existing and pattern['confidence'] > 70:
                # CREATE new rule
                rec = RuleRecommendation(
                    action="CREATE",
                    rule_id=f"{pattern['type']}-{pattern['id']}",
                    reason=f"New {pattern['type']} pattern detected. Not covered by existing rules. "
                           f"Observed in {len(similar_alerts)} attacks.",
                    suggested_pattern=pattern['pattern'],
                    severity=pattern['severity'],
                    confidence=pattern['confidence'],
                    evidence_count=len(similar_alerts)
                )
                db.add(rec)
            
            elif existing and pattern['improved']:
                # MODIFY existing rule
                rec = RuleRecommendation(
                    action="MODIFY",
                    rule_id=existing.rule_id,
                    reason=f"Current rule misses {pattern['variant']} variants. "
                           f"Detected {pattern['missed_count']} bypasses.",
                    current_pattern=existing.pattern,
                    suggested_pattern=pattern['improved_pattern'],
                    severity=existing.severity,
                    confidence=85,
                    evidence_count=pattern['missed_count']
                )
                db.add(rec)
        
        # Check for false positives
        fp_rules = check_false_positives(db)
        for rule_id, fp_count in fp_rules.items():
            if fp_count > 20:
                rec = RuleRecommendation(
                    action="DISABLE",
                    rule_id=rule_id,
                    reason=f"{fp_count} false positives in last 24 hours. "
                           f"Rule triggers on legitimate traffic.",
                    severity="low",
                    confidence=90,
                    evidence_count=fp_count
                )
                db.add(rec)
        
        db.commit()
    finally:
        db.close()

def extract_attack_patterns(alert: Alert, similar_alerts: list) -> list:
    """Extract attack patterns from alerts"""
    patterns = []
    
    # SQL Injection patterns
    if 'sql' in alert.rule_description.lower() or 'injection' in alert.rule_description.lower():
        sqli_patterns = [
            r"admin['\"]--",
            r"' or '1'='1",
            r"union.*select",
            r"' or 1=1--"
        ]
        
        for i, pattern in enumerate(sqli_patterns):
            patterns.append({
                'type': 'SQLI',
                'id': f'AUTH-{i+1:03d}',
                'pattern': pattern,
                'severity': 'high',
                'confidence': 95,
                'improved': False
            })
    
    # XSS patterns
    if 'xss' in alert.rule_description.lower() or 'script' in alert.rule_description.lower():
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'onerror\s*=',
            r'<img[^>]+onerror'
        ]
        
        for i, pattern in enumerate(xss_patterns):
            patterns.append({
                'type': 'XSS',
                'id': f'INJECT-{i+1:03d}',
                'pattern': pattern,
                'severity': 'medium',
                'confidence': 88,
                'improved': False
            })
    
    # Path traversal
    if 'path' in alert.rule_description.lower() or 'directory' in alert.rule_description.lower():
        patterns.append({
            'type': 'PATH',
            'id': 'TRAVERSAL-001',
            'pattern': r'\.\./|\.\.\\',
            'severity': 'high',
            'confidence': 92,
            'improved': False
        })
    
    return patterns

def check_false_positives(db: Session) -> dict:
    """Check rules with high false positive rate"""
    from datetime import timedelta
    
    # Mock implementation - in reality would check alert feedback
    fp_candidates = {}
    
    rules = db.query(DetectionRule).all()
    for rule in rules:
        recent_alerts = db.query(Alert).filter(
            Alert.rule_id == rule.rule_id,
            Alert.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        # Heuristic: if same rule fires > 50 times, might be FP
        if recent_alerts > 50:
            fp_candidates[rule.rule_id] = recent_alerts
    
    return fp_candidates

from datetime import timedelta, datetime


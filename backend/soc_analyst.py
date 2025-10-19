from sqlalchemy.orm import Session
from main import SessionLocal, Alert, RuleRecommendation, DetectionRule
from datetime import timedelta, datetime
import re
from collections import Counter
from ai_engine import AIEngine
import json

async def analyze_and_recommend(alert_id: int):
    """AI SOC Analyst - analyzes alert and recommends rules"""
    db = SessionLocal()
    try:
        alert = db.query(Alert).get(alert_id)
        if not alert:
            print(f"Alert {alert_id} not found")
            return
        
        print(f"\n{'='*60}")
        print(f"AI SOC ANALYST - Analyzing Alert #{alert_id}")
        print(f"{'='*60}")
        
        # Prepare alert data for AI
        alert_data = {
            'id': alert.id,
            'rule_id': alert.rule_id,
            'rule_description': alert.rule_description,
            'host': alert.host,
            'severity': alert.severity,
            'timestamp': alert.timestamp.isoformat(),
            'raw_data': alert.raw_data or {}
        }
        
        # Get recent similar alerts for context
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        similar_alerts = db.query(Alert).filter(
            Alert.rule_id == alert.rule_id,
            Alert.timestamp >= recent_cutoff
        ).all()
        
        alert_data['similar_count'] = len(similar_alerts)
        
        # Get existing rules for context
        existing_rules = db.query(DetectionRule).all()
        existing_patterns = [r.pattern for r in existing_rules]
        
        print(f"Context: {len(similar_alerts)} similar alerts in last 24h")
        print(f"Context: {len(existing_rules)} existing detection rules")
        
        # Call AI for analysis
        try:
            print("Calling AI for analysis...")
            analysis = await AIEngine.analyze_alert_with_llm(alert_data)
            print(f"AI analysis complete: {len(analysis.get('recommendations', []))} recommendations")
        except Exception as e:
            print(f"AI analysis failed, using fallback: {e}")
            analysis = generate_fallback_analysis(alert_data, similar_alerts)
        
        # Generate comprehensive incident report
        incident_report = generate_incident_report(
            alert, 
            analysis, 
            similar_alerts,
            existing_rules
        )
        
        # Save incident report
        from main import IncidentReport
        report_entry = IncidentReport(
            alert_id=alert.id,
            severity=get_severity_label(alert.severity),
            attack_type=extract_attack_type(alert),
            attack_pattern=extract_attack_pattern(alert),
            is_false_positive=is_likely_false_positive(alert, similar_alerts),
            is_true_positive=not is_likely_false_positive(alert, similar_alerts),
            threat_level=calculate_threat_level(alert, similar_alerts),
            source_ip=alert.raw_data.get('source_ip', 'unknown'),
            affected_host=alert.host,
            attack_success=determine_attack_success(alert),
            evidence=json.dumps(alert.raw_data),
            analysis_summary=analysis.get('attack_analysis', 'No analysis available'),
            recommended_actions=generate_recommended_actions(alert, analysis),
            full_report=incident_report
        )
        db.add(report_entry)
        
        print("\n" + "="*60)
        print("INCIDENT REPORT GENERATED")
        print("="*60)
        print(incident_report[:500] + "...\n")
        
        # Process rule recommendations (avoid duplicates)
        print("\nProcessing Rule Recommendations...")
        recommendations_created = 0
        
        for rec_data in analysis.get('recommendations', []):
            rule_id = rec_data['rule_id']
            action = rec_data['action']
            
            # Check if this exact recommendation already exists
            existing_rec = db.query(RuleRecommendation).filter(
                RuleRecommendation.rule_id == rule_id,
                RuleRecommendation.action == action,
                RuleRecommendation.applied == False
            ).first()
            
            if existing_rec:
                # Update confidence if higher
                if rec_data.get('confidence', 0) > existing_rec.confidence:
                    existing_rec.confidence = rec_data['confidence']
                    existing_rec.evidence_count += 1
                    print(f"  ↻ Updated: {rule_id} (confidence: {existing_rec.confidence}%)")
                else:
                    print(f"  ⊘ Skipped: {rule_id} (already exists)")
                continue
            
            # For CREATE action, check if rule already exists
            if action == "CREATE":
                existing_rule = db.query(DetectionRule).filter(
                    DetectionRule.rule_id == rule_id
                ).first()
                
                if existing_rule:
                    print(f"  ⊘ Skipped: {rule_id} (rule already exists)")
                    continue
                
                # Check if pattern already covered
                suggested_pattern = rec_data.get('suggested_pattern', '')
                if any(suggested_pattern in ep for ep in existing_patterns):
                    print(f"  ⊘ Skipped: {rule_id} (pattern already covered)")
                    continue
            
            # Create new recommendation
            rec = RuleRecommendation(
                action=action,
                rule_id=rule_id,
                reason=rec_data['reason'],
                current_pattern=rec_data.get('current_pattern'),
                suggested_pattern=rec_data.get('suggested_pattern'),
                severity=rec_data.get('severity', 'medium'),
                confidence=rec_data.get('confidence', 85),
                evidence_count=alert_data.get('similar_count', 1)
            )
            db.add(rec)
            recommendations_created += 1
            print(f"  ✓ Created: {action} {rule_id} (confidence: {rec.confidence}%)")
        
        # Additional heuristic checks
        await check_pattern_coverage(db, alert, existing_patterns)
        await check_false_positives(db, alert)
        
        db.commit()
        
        print(f"\n{'='*60}")
        print(f"Analysis Complete!")
        print(f"  - Incident Report: Generated")
        print(f"  - New Recommendations: {recommendations_created}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"Error analyzing alert {alert_id}: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()


def generate_incident_report(alert, analysis, similar_alerts, existing_rules):
    """Generate comprehensive incident report"""
    
    severity_map = {12: "CRITICAL", 9: "HIGH", 6: "MEDIUM", 3: "LOW"}
    severity_label = severity_map.get(alert.severity, "MEDIUM")
    
    # Determine if false positive
    is_fp = is_likely_false_positive(alert, similar_alerts)
    fp_status = "⚠️  LIKELY FALSE POSITIVE" if is_fp else "✓ LIKELY TRUE POSITIVE"
    
    # Extract attack details
    attack_pattern = extract_attack_pattern(alert)
    source_ip = alert.raw_data.get('source_ip', 'unknown')
    user_agent = alert.raw_data.get('user_agent', 'unknown')
    
    report = f"""
╔═══════════════════════════════════════════════════════════════╗
║           AI SOC ANALYST - INCIDENT REPORT                   ║
╚═══════════════════════════════════════════════════════════════╝

INCIDENT ID: INC-{alert.id:06d}
TIMESTAMP: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
SEVERITY: {severity_label}
STATUS: {fp_status}

─────────────────────────────────────────────────────────────────
ALERT DETAILS
─────────────────────────────────────────────────────────────────
Rule Triggered: {alert.rule_id} - {alert.rule_description}
Target Host: {alert.host}
Source IP: {source_ip}
User Agent: {user_agent}

─────────────────────────────────────────────────────────────────
ATTACK ANALYSIS
─────────────────────────────────────────────────────────────────
{analysis.get('attack_analysis', 'Attack pattern analysis in progress...')}

Attack Pattern Detected: {attack_pattern}
Attack Type: {extract_attack_type(alert)}
Success Probability: {determine_attack_success(alert)}

─────────────────────────────────────────────────────────────────
THREAT CONTEXT
─────────────────────────────────────────────────────────────────
Similar Attacks (24h): {len(similar_alerts)}
Attack Frequency: {"High" if len(similar_alerts) > 10 else "Medium" if len(similar_alerts) > 3 else "Low"}
Threat Level: {calculate_threat_level(alert, similar_alerts)}

Historical Pattern:
"""
    
    # Add timeline of similar attacks
    if similar_alerts:
        report += f"  - First seen: {min(a.timestamp for a in similar_alerts).strftime('%H:%M:%S')}\n"
        report += f"  - Last seen: {max(a.timestamp for a in similar_alerts).strftime('%H:%M:%S')}\n"
        report += f"  - Total occurrences: {len(similar_alerts)}\n"
    else:
        report += "  - This is the FIRST occurrence of this pattern (NEW ATTACK)\n"
    
    report += f"""
─────────────────────────────────────────────────────────────────
FALSE POSITIVE ANALYSIS
─────────────────────────────────────────────────────────────────
"""
    
    if is_fp:
        report += f"""⚠️  This alert is LIKELY a FALSE POSITIVE because:
  - Rule {alert.rule_id} has triggered {len(similar_alerts)} times in 24h
  - High-frequency alerts often indicate overly broad patterns
  - No confirmed malicious indicators in payload
  
RECOMMENDATION: Review and tune rule {alert.rule_id} or disable it
"""
    else:
        report += f"""✓ This appears to be a TRUE POSITIVE because:
  - Attack pattern matches known malicious signatures
  - Low occurrence rate suggests targeted attack
  - Payload contains suspicious indicators
  
RECOMMENDATION: Investigate immediately and apply suggested rules
"""
    
    report += f"""
─────────────────────────────────────────────────────────────────
DETECTION COVERAGE
─────────────────────────────────────────────────────────────────
Current Rules: {len(existing_rules)} detection rules active
Coverage Gaps: {"Yes - new patterns detected" if analysis.get('recommendations') else "No gaps found"}
"""
    
    if analysis.get('recommendations'):
        report += f"\nAI recommends {len(analysis['recommendations'])} rule changes to improve detection:\n"
        for i, rec in enumerate(analysis['recommendations'][:3], 1):
            report += f"  {i}. {rec['action']} {rec['rule_id']}: {rec['reason'][:60]}...\n"
    
    report += f"""
─────────────────────────────────────────────────────────────────
RECOMMENDED ACTIONS
─────────────────────────────────────────────────────────────────
"""
    
    actions = generate_recommended_actions(alert, analysis)
    for i, action in enumerate(actions, 1):
        report += f"  {i}. {action}\n"
    
    report += f"""
─────────────────────────────────────────────────────────────────
RAW EVIDENCE
─────────────────────────────────────────────────────────────────
{json.dumps(alert.raw_data, indent=2)}

═══════════════════════════════════════════════════════════════════
Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Analyst: AI SOC Agent v1.0
═══════════════════════════════════════════════════════════════════
"""
    
    return report


def is_likely_false_positive(alert, similar_alerts):
    """Determine if alert is likely a false positive"""
    # If rule fires more than 50 times in 24h, likely FP
    if len(similar_alerts) > 50:
        return True
    
    # If severity is low and frequent, likely FP
    if alert.severity < 6 and len(similar_alerts) > 20:
        return True
    
    return False


def get_severity_label(severity_int):
    """Convert severity integer to label"""
    if severity_int >= 12:
        return "CRITICAL"
    elif severity_int >= 9:
        return "HIGH"
    elif severity_int >= 6:
        return "MEDIUM"
    else:
        return "LOW"


def extract_attack_type(alert):
    """Extract attack type from alert"""
    rule_desc = alert.rule_description.lower()
    
    if 'sql' in rule_desc or 'injection' in rule_desc:
        return "SQL Injection"
    elif 'xss' in rule_desc or 'script' in rule_desc:
        return "Cross-Site Scripting (XSS)"
    elif 'path' in rule_desc or 'traversal' in rule_desc:
        return "Path Traversal"
    elif 'brute' in rule_desc:
        return "Brute Force"
    elif 'command' in rule_desc:
        return "Command Injection"
    else:
        return "Unknown Attack Type"


def extract_attack_pattern(alert):
    """Extract specific attack pattern from alert data"""
    raw_data = alert.raw_data or {}
    log = raw_data.get('log', '')
    
    # Try to extract pattern from log
    if "'" in log or '"' in log:
        # SQL injection patterns
        if '--' in log:
            return "SQL Comment Injection (--)"
        elif 'union' in log.lower():
            return "SQL UNION Attack"
        elif 'or' in log.lower() and '=' in log:
            return "SQL Boolean Injection"
    
    if '<script' in log.lower():
        return "Script Tag Injection"
    elif 'javascript:' in log.lower():
        return "JavaScript Protocol XSS"
    elif 'onerror' in log.lower():
        return "Event Handler XSS"
    
    if '../' in log or '..\\' in log:
        return "Directory Traversal"
    
    return "Pattern detection in progress"


def calculate_threat_level(alert, similar_alerts):
    """Calculate overall threat level"""
    score = 0
    
    # Severity contribution
    score += alert.severity
    
    # Frequency penalty (too many = likely FP)
    if len(similar_alerts) > 50:
        score -= 5
    elif len(similar_alerts) < 3:
        score += 3  # Rare = more concerning
    
    # Classify
    if score >= 12:
        return "CRITICAL"
    elif score >= 9:
        return "HIGH"
    elif score >= 6:
        return "MEDIUM"
    else:
        return "LOW"


def determine_attack_success(alert):
    """Determine if attack likely succeeded"""
    raw_data = alert.raw_data or {}
    log = raw_data.get('log', '')
    
    # Heuristics
    if 'error' in log.lower() or '500' in log:
        return "Likely Failed (Error Response)"
    elif 'success' in log.lower() or '200' in log:
        return "Possibly Succeeded (Success Response)"
    else:
        return "Unknown"


def generate_recommended_actions(alert, analysis):
    """Generate list of recommended actions"""
    actions = []
    
    # Immediate actions
    if alert.severity >= 10:
        actions.append(f"🚨 IMMEDIATE: Block source IP {alert.raw_data.get('source_ip', 'unknown')}")
        actions.append(f"🔍 IMMEDIATE: Review {alert.host} logs for lateral movement")
    
    # Rule actions
    if analysis.get('recommendations'):
        actions.append(f"✓ Apply {len(analysis['recommendations'])} AI-recommended rule changes")
    
    # Investigation actions
    actions.append(f"📊 Review all alerts from rule {alert.rule_id} in last 24h")
    actions.append(f"🔐 Verify {alert.host} security configuration")
    
    # Follow-up
    if alert.severity >= 6:
        actions.append("📝 Create security incident ticket")
        actions.append("👥 Notify security team")
    
    return actions


async def check_pattern_coverage(db: Session, alert: Alert, existing_patterns: list):
    """Check if attack patterns are adequately covered"""
    
    raw_data = alert.raw_data or {}
    log_text = raw_data.get('log', '')
    
    if not log_text:
        return
    
    uncovered_patterns = []
    
    # SQL Injection variants
    sqli_patterns = [
        (r"admin['\"]--", "SQL comment injection", "SQLI"),
        (r"' or '1'='1", "SQL boolean bypass", "SQLI"),
        (r"union\s+select", "SQL UNION attack", "SQLI"),
        (r";\s*drop\s+table", "SQL DROP table", "SQLI"),
    ]
    
    # XSS variants
    xss_patterns = [
        (r"<script[^>]*>", "Script tag XSS", "XSS"),
        (r"javascript:", "JavaScript protocol XSS", "XSS"),
        (r"onerror\s*=", "Event handler XSS", "XSS"),
        (r"<iframe[^>]*>", "Iframe injection", "XSS"),
    ]
    
    # Path traversal
    path_patterns = [
        (r"\.\./", "Directory traversal", "PATH"),
        (r"\.\.\\", "Windows path traversal", "PATH"),
    ]
    
    all_patterns = sqli_patterns + xss_patterns + path_patterns
    
    for pattern, description, rule_type in all_patterns:
        if re.search(pattern, log_text, re.IGNORECASE):
            # Check if covered
            if not any(pattern in ep for ep in existing_patterns):
                uncovered_patterns.append((pattern, description, rule_type))
    
    # Create recommendations for uncovered patterns
    for pattern, description, rule_type in uncovered_patterns:
        rule_id = f"{rule_type}-AUTO-{abs(hash(pattern)) % 1000:03d}"
        
        existing_rec = db.query(RuleRecommendation).filter(
            RuleRecommendation.rule_id == rule_id,
            RuleRecommendation.applied == False
        ).first()
        
        if not existing_rec:
            rec = RuleRecommendation(
                action="CREATE",
                rule_id=rule_id,
                reason=f"Detected {description} but no existing rule covers this pattern",
                suggested_pattern=pattern,
                severity="high",
                confidence=80,
                evidence_count=1
            )
            db.add(rec)
            print(f"  ✓ Coverage gap found: {rule_id}")


async def check_false_positives(db: Session, alert: Alert):
    """Identify rules with high false positive rates"""
    
    recent_cutoff = datetime.utcnow() - timedelta(hours=24)
    recent_alerts = db.query(Alert).filter(
        Alert.rule_id == alert.rule_id,
        Alert.timestamp >= recent_cutoff
    ).count()
    
    # If rule fires > 50 times, likely FP
    if recent_alerts > 50:
        existing = db.query(RuleRecommendation).filter(
            RuleRecommendation.rule_id == alert.rule_id,
            RuleRecommendation.action == "DISABLE",
            RuleRecommendation.applied == False
        ).first()
        
        if not existing:
            rec = RuleRecommendation(
                action="DISABLE",
                rule_id=alert.rule_id,
                reason=f"Rule fired {recent_alerts} times in last 24 hours. "
                       f"High frequency suggests false positives. Consider tuning or disabling.",
                severity="low",
                confidence=85,
                evidence_count=recent_alerts
            )
            db.add(rec)
            print(f"  ⚠️  False positive detected: {alert.rule_id}")


def generate_fallback_analysis(alert_data: dict, similar_alerts: list) -> dict:
    """Enhanced fallback analysis when AI is unavailable"""
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
                "reason": "SQL comment injection pattern detected (--). This pattern is commonly used for authentication bypass.",
                "suggested_pattern": r"['\"]--",
                "severity": "high",
                "confidence": 85
            })
        
        if 'union' in log.lower():
            recommendations.append({
                "action": "CREATE",
                "rule_id": "SQLI-UNION-001",
                "reason": "SQL UNION attack pattern detected. Commonly used for data exfiltration.",
                "suggested_pattern": r"union\s+(all\s+)?select",
                "severity": "critical",
                "confidence": 90
            })
        
        if re.search(r"or.*1\s*=\s*1", log, re.IGNORECASE):
            recommendations.append({
                "action": "CREATE",
                "rule_id": "SQLI-BOOLEAN-001",
                "reason": "Boolean-based SQL injection detected (OR 1=1). Authentication bypass attempt.",
                "suggested_pattern": r"or\s+\d+\s*=\s*\d+",
                "severity": "high",
                "confidence": 88
            })
    
    # XSS patterns
    elif 'xss' in rule_desc or 'script' in rule_desc:
        attack_analysis += "Cross-site scripting (XSS) attack detected. "
        
        if '<script' in log.lower():
            recommendations.append({
                "action": "CREATE",
                "rule_id": "XSS-SCRIPT-001",
                "reason": "Script tag injection detected. Can lead to session hijacking and data theft.",
                "suggested_pattern": r"<script[^>]*>",
                "severity": "medium",
                "confidence": 85
            })
        
        if 'onerror' in log.lower() or 'onload' in log.lower():
            recommendations.append({
                "action": "CREATE",
                "rule_id": "XSS-EVENT-001",
                "reason": "Event handler XSS detected. Bypasses some WAF filters.",
                "suggested_pattern": r"on\w+\s*=",
                "severity": "medium",
                "confidence": 82
            })
    
    # Path Traversal
    elif 'path' in rule_desc or 'traversal' in rule_desc:
        attack_analysis += "Path traversal attack detected. "
        
        recommendations.append({
            "action": "CREATE",
            "rule_id": "PATH-DOTDOT-001",
            "reason": "Directory traversal pattern detected. Can expose sensitive files.",
            "suggested_pattern": r"\.\./|\.\.\\",
            "severity": "high",
            "confidence": 90
        })
    
    # Command Injection
    elif 'command' in rule_desc:
        attack_analysis += "Command injection attack detected. "
        
        recommendations.append({
            "action": "CREATE",
            "rule_id": "CMDI-SHELL-001",
            "reason": "Shell command injection detected. Critical risk of remote code execution.",
            "suggested_pattern": r"[;&|]\s*(cat|ls|whoami|id|nc|bash)",
            "severity": "critical",
            "confidence": 92
        })
    
    # Generic recommendation if none matched
    if not recommendations:
        recommendations.append({
            "action": "CREATE",
            "rule_id": f"{rule_id}-ENHANCED-001",
            "reason": f"Alert pattern detected but not fully covered. Consider creating more specific rule for {rule_desc}.",
            "suggested_pattern": ".*suspicious.*",
            "severity": "medium",
            "confidence": 70
        })
        attack_analysis += "Generic attack pattern detected. Manual review recommended."
    
    # Check for high frequency (false positive indicator)
    if len(similar_alerts) > 50:
        recommendations.append({
            "action": "DISABLE",
            "rule_id": rule_id,
            "reason": f"Rule has triggered {len(similar_alerts)} times in 24 hours. High false positive rate detected.",
            "severity": "low",
            "confidence": 85
        })
        attack_analysis += f" Note: This rule has high frequency ({len(similar_alerts)} alerts), may indicate false positives."
    
    return {
        "attack_analysis": attack_analysis,
        "recommendations": recommendations
    }

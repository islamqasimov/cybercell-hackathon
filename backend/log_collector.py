import re
import asyncio
from datetime import datetime
from main import SessionLocal, Alert, DetectionRule

async def collect_and_analyze_logs():
    """Simple log collector and rule engine"""
    while True:
        try:
            # Read Juice Shop logs
            logs = read_juiceshop_logs()
            
            # Apply detection rules
            for log_line in logs:
                await check_rules(log_line)
            
            await asyncio.sleep(5)
        except Exception as e:
            print(f"Log collection error: {e}")
            await asyncio.sleep(5)

def read_juiceshop_logs():
    """Read logs from Juice Shop container"""
    # For Docker, logs go to stdout - capture via docker logs
    # For now, mock log lines
    return []

async def check_rules(log_line: str):
    """Apply detection rules to log line"""
    db = SessionLocal()
    try:
        rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
        
        for rule in rules:
            if re.search(rule.pattern, log_line, re.IGNORECASE):
                # Rule matched - create alert
                alert = Alert(
                    rule_id=rule.rule_id,
                    rule_description=rule.name,
                    host='juiceshop',
                    severity=get_severity_level(rule.severity),
                    raw_data={'log': log_line, 'matched_rule': rule.rule_id}
                )
                db.add(alert)
                db.commit()
                print(f"Alert created: {rule.rule_id}")
    finally:
        db.close()

def get_severity_level(severity_str: str) -> int:
    """Convert severity string to numeric level"""
    mapping = {
        'low': 3,
        'medium': 6,
        'high': 9,
        'critical': 12
    }
    return mapping.get(severity_str.lower(), 5)

# Initialize default rules
def init_default_rules():
    """Initialize with some default detection rules"""
    db = SessionLocal()
    try:
        if db.query(DetectionRule).count() == 0:
            default_rules = [
                {
                    'rule_id': 'SQLI-001',
                    'name': 'SQL Injection - Basic',
                    'pattern': r"(union.*select|or\s+1\s*=\s*1|'\s+or\s+'1'\s*=\s*'1)",
                    'severity': 'high',
                    'auto_generated': False
                },
                {
                    'rule_id': 'XSS-001',
                    'name': 'XSS - Script Tag',
                    'pattern': r'<script[^>]*>.*?</script>',
                    'severity': 'medium',
                    'auto_generated': False
                },
                {
                    'rule_id': 'PATH-001',
                    'name': 'Path Traversal',
                    'pattern': r'\.\./|\.\.\\',
                    'severity': 'high',
                    'auto_generated': False
                },
                {
                    'rule_id': 'BRUTE-001',
                    'name': 'Brute Force Login',
                    'pattern': r'(login|auth).*fail.*(\d{3,})',
                    'severity': 'medium',
                    'auto_generated': False
                }
            ]
            
            for rule_data in default_rules:
                rule = DetectionRule(**rule_data)
                db.add(rule)
            
            db.commit()
            print("Default rules initialized")
    finally:
        db.close()

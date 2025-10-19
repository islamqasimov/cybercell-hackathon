#!/bin/bash
# Quick Attack Generator - Creates diverse alerts for ML training

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

# Scenario 1: SQL Injection
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
sql_injection

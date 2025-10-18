#!/bin/bash
# Automated Demo Script - Showcases both AI agents

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

API_URL="http://localhost:8000"

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║           AI SECURITY PLATFORM - DEMO SCRIPT             ║
║                                                           ║
║   Demonstrating Two AI Agents Working Together          ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

pause() {
    echo -e "\n${YELLOW}Press ENTER to continue...${NC}"
    read
}

# Scene 1: Show Current State
echo -e "${CYAN}═══ SCENE 1: Current System State ═══${NC}\n"
echo -e "${YELLOW}Fetching system statistics...${NC}"
curl -s $API_URL/stats | python3 -m json.tool
pause

# Scene 2: Run Security Audit
echo -e "\n${CYAN}═══ SCENE 2: AI Security Auditor in Action ═══${NC}\n"
echo -e "${YELLOW}Starting security audit of Juice Shop...${NC}"
echo -e "${BLUE}AI Agent #2 will:${NC}"
echo -e "  1. Scan source code for vulnerabilities"
echo -e "  2. Run automated attacks to validate findings"
echo -e "  3. Generate detailed security report\n"

curl -X POST $API_URL/auditor/scan \
    -H "Content-Type: application/json" \
    -d '{"target": "juiceshop", "validate_attacks": true}'

echo -e "\n${YELLOW}Audit in progress... (waiting 10 seconds)${NC}"
sleep 10

echo -e "\n${GREEN}Fetching audit results...${NC}\n"
curl -s $API_URL/auditor/results | python3 -m json.tool | head -100

pause

# Scene 3: Create Test Alerts
echo -e "\n${CYAN}═══ SCENE 3: Simulating Security Attacks ═══${NC}\n"
echo -e "${YELLOW}Simulating SQL injection attack...${NC}"

curl -X POST $API_URL/alerts \
    -H "Content-Type: application/json" \
    -d '{
        "rule_id": "SQLI-001",
        "rule_description": "SQL Injection - Admin Bypass",
        "host": "juiceshop",
        "severity": 12,
        "raw_data": {
            "log": "POST /rest/user/login email=admin'\''-- password=test",
            "source_ip": "10.0.0.100",
            "attack_pattern": "admin'\''--"
        }
    }'

echo -e "\n${GREEN}✓ Alert created${NC}"
sleep 2

echo -e "\n${YELLOW}Simulating XSS attack...${NC}"

curl -X POST $API_URL/alerts \
    -H "Content-Type: application/json" \
    -d '{
        "rule_id": "XSS-001",
        "rule_description": "Cross-Site Scripting",
        "host": "juiceshop",
        "severity": 9,
        "raw_data": {
            "log": "GET /profile?name=<script>alert('\''XSS'\'')</script>",
            "source_ip": "10.0.0.101",
            "attack_pattern": "<script>alert"
        }
    }'

echo -e "\n${GREEN}✓ Alert created${NC}"

pause

# Scene 4: AI SOC Analyst Analysis
echo -e "\n${CYAN}═══ SCENE 4: AI SOC Analyst Analyzing Alerts ═══${NC}\n"
echo -e "${YELLOW}AI Agent #1 is analyzing alerts...${NC}"
echo -e "${BLUE}The AI will:${NC}"
echo -e "  1. Identify attack patterns"
echo -e "  2. Recommend new detection rules"
echo -e "  3. Suggest modifications to existing rules"
echo -e "  4. Learn from false positives\n"

# Trigger analysis for recent alerts
echo -e "${YELLOW}Analyzing alert #1...${NC}"
curl -X POST $API_URL/soc/analyze/1

sleep 3

echo -e "\n${YELLOW}Analyzing alert #2...${NC}"
curl -X POST $API_URL/soc/analyze/2

echo -e "\n\n${YELLOW}Waiting for AI analysis... (10 seconds)${NC}"
sleep 10

# Scene 5: Show Rule Recommendations
echo -e "\n${CYAN}═══ SCENE 5: AI-Generated Rule Recommendations ═══${NC}\n"
echo -e "${YELLOW}Fetching AI recommendations...${NC}\n"

curl -s $API_URL/soc/rule-recommendations | python3 -m json.tool

pause

# Scene 6: Apply Recommendations
echo -e "\n${CYAN}═══ SCENE 6: Applying AI Recommendations ═══${NC}\n"
echo -e "${YELLOW}Let's apply the first recommendation...${NC}\n"

# Get first recommendation ID
REC_ID=$(curl -s $API_URL/soc/rule-recommendations | python3 -c "import sys, json; data=json.load(sys.stdin); print(data[0]['id'] if data else 1)")

if [ ! -z "$REC_ID" ]; then
    echo -e "${BLUE}Applying recommendation #${REC_ID}...${NC}"
    curl -X POST $API_URL/soc/apply-recommendation/$REC_ID
    echo -e "\n${GREEN}✓ Rule recommendation applied!${NC}"
else
    echo -e "${YELLOW}No recommendations to apply yet${NC}"
fi

pause

# Scene 7: Final Statistics
echo -e "\n${CYAN}═══ SCENE 7: Updated System Statistics ═══${NC}\n"
echo -e "${YELLOW}System statistics after AI analysis:${NC}\n"

curl -s $API_URL/stats | python3 -m json.tool

# Scene 8: Summary
echo -e "\n${CYAN}═══ DEMO COMPLETE! ═══${NC}\n"

cat << EOF
${GREEN}✓ AI Security Auditor:${NC}
  - Scanned Juice Shop source code
  - Identified multiple vulnerabilities
  - Validated findings with real attacks
  - Generated remediation recommendations

${GREEN}✓ AI SOC Analyst:${NC}
  - Analyzed security alerts in real-time
  - Identified attack patterns
  - Recommended new detection rules
  - Suggested optimizations to existing rules

${BLUE}Key Innovation:${NC}
  Both AI agents work together in a feedback loop:
  Security Auditor → Finds Vulns → Validates with Attacks
         ↓
  SOC Analyst → Detects Attacks → Creates Rules
         ↓
  Rules prevent future attacks on the same vulnerabilities!

${YELLOW}Next Steps:${NC}
  1. Open dashboard: ${CYAN}http://localhost:3001${NC}
  2. Explore all tabs to see detailed results
  3. Run more audits and watch the system learn!

${MAGENTA}Thank you for watching! 🎉${NC}
EOF

echo -e "\n"

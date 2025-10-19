#!/bin/bash
# Test SOC Analyst functionality

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="http://localhost:8000"

echo -e "${BLUE}Testing SOC Analyst Functionality${NC}\n"

# Step 1: Check if alerts exist
echo -e "${YELLOW}1. Checking existing alerts...${NC}"
ALERT_COUNT=$(curl -s $API_URL/alerts | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null)
echo -e "Found ${GREEN}${ALERT_COUNT}${NC} alerts\n"

if [ "$ALERT_COUNT" -eq "0" ]; then
    echo -e "${YELLOW}Creating test alert...${NC}"
    curl -X POST $API_URL/alerts \
        -H "Content-Type: application/json" \
        -d '{
            "rule_id": "SQLI-001",
            "rule_description": "SQL Injection - Authentication Bypass",
            "host": "juiceshop",
            "severity": 12,
            "raw_data": {
                "log": "POST /rest/user/login email=admin'\''-- password=test",
                "source_ip": "192.168.1.100",
                "user_agent": "sqlmap/1.4",
                "attack_pattern": "admin'\''--"
            }
        }'
    echo -e "\n${GREEN}✓ Test alert created${NC}\n"
    sleep 2
fi

# Step 2: Trigger analysis
echo -e "${YELLOW}2. Triggering AI analysis...${NC}"
curl -X POST $API_URL/soc/analyze/1
echo -e "\n"

# Step 3: Check backend logs
echo -e "${YELLOW}3. Checking backend logs (last 20 lines)...${NC}"
docker-compose logs --tail=20 fastapi
echo -e "\n"

# Step 4: Wait and check recommendations
echo -e "${YELLOW}4. Waiting 15 seconds for analysis to complete...${NC}"
for i in {15..1}; do
    echo -ne "\r${BLUE}Time remaining: ${i} seconds ${NC}"
    sleep 1
done
echo -e "\n"

echo -e "${YELLOW}5. Fetching rule recommendations...${NC}"
RECS=$(curl -s $API_URL/soc/rule-recommendations)
echo "$RECS" | python3 -m json.tool 2>/dev/null || echo "$RECS"
echo -e "\n"

REC_COUNT=$(echo "$RECS" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
if [ "$REC_COUNT" -gt "0" ]; then
    echo -e "${GREEN}✓ SUCCESS: ${REC_COUNT} recommendations generated${NC}"
else
    echo -e "${RED}✗ ISSUE: No recommendations generated${NC}"
    echo -e "${YELLOW}Checking for errors...${NC}\n"
    
    # Check if soc_analyst.py has issues
    echo -e "${YELLOW}Verifying soc_analyst.py exists...${NC}"
    docker-compose exec fastapi ls -la soc_analyst.py 2>/dev/null
    
    echo -e "\n${YELLOW}Checking Python imports...${NC}"
    docker-compose exec fastapi python3 -c "import soc_analyst; print('soc_analyst imported successfully')" 2>&1
    
    echo -e "\n${YELLOW}Full backend logs:${NC}"
    docker-compose logs --tail=50 fastapi | grep -i "error\|exception\|soc\|analyz"
fi

echo -e "\n${YELLOW}6. Checking incident reports...${NC}"
INCIDENTS=$(curl -s $API_URL/soc/incidents)
echo "$INCIDENTS" | python3 -m json.tool 2>/dev/null | head -50
echo -e "\n"

INC_COUNT=$(echo "$INCIDENTS" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
if [ "$INC_COUNT" -gt "0" ]; then
    echo -e "${GREEN}✓ SUCCESS: ${INC_COUNT} incident reports generated${NC}"
else
    echo -e "${RED}✗ ISSUE: No incident reports generated${NC}"
fi

echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}Test Complete${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"

#!/bin/bash
# Fix ML Cyber Consultant Integration

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║         FIXING ML CYBER CONSULTANT INTEGRATION           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${RED}Error: docker-compose.yml not found. Run this from project root.${NC}"
    exit 1
fi

# Step 1: Backup current soc_analyst.py
echo -e "${YELLOW}1. Backing up current soc_analyst.py...${NC}"
if [ -f "backend/soc_analyst.py" ]; then
    cp backend/soc_analyst.py backend/soc_analyst.py.backup
    echo -e "${GREEN}✓ Backup created: backend/soc_analyst.py.backup${NC}"
else
    echo -e "${RED}✗ backend/soc_analyst.py not found${NC}"
fi

# Step 2: Update main.py import
echo -e "\n${YELLOW}2. Checking main.py imports...${NC}"
if grep -q "from soc_analyst_enhanced import" backend/main.py 2>/dev/null; then
    echo -e "${GREEN}✓ Already using enhanced SOC analyst${NC}"
elif grep -q "from soc_analyst import" backend/main.py 2>/dev/null; then
    echo -e "${YELLOW}⚠ Using traditional SOC analyst. Update recommended.${NC}"
    echo -e "${BLUE}   Note: The unified soc_analyst.py will handle this automatically${NC}"
fi

# Step 3: Test if cyber_consultant.py exists
echo -e "\n${YELLOW}3. Checking ML Cyber Consultant module...${NC}"
if [ -f "backend/cyber_consultant.py" ]; then
    echo -e "${GREEN}✓ cyber_consultant.py found${NC}"
    
    # Test import
    docker-compose exec -T fastapi python3 -c "from cyber_consultant import CyberConsultant" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ cyber_consultant module imports successfully${NC}"
    else
        echo -e "${RED}✗ cyber_consultant module has import errors${NC}"
        echo -e "${YELLOW}  Checking dependencies...${NC}"
        docker-compose exec -T fastapi python3 -c "import sklearn; print('✓ sklearn available')" 2>/dev/null || echo -e "${RED}  ✗ sklearn not installed${NC}"
    fi
else
    echo -e "${RED}✗ cyber_consultant.py not found${NC}"
    echo -e "${YELLOW}  Please copy cyber_consultant.py from the artifacts to backend/${NC}"
    exit 1
fi

# Step 4: Clear old incident reports and re-analyze
echo -e "\n${YELLOW}4. Would you like to clear old incident reports and re-analyze? (y/n)${NC}"
read -p "Choice: " clear_choice

if [ "$clear_choice" = "y" ] || [ "$clear_choice" = "Y" ]; then
    echo -e "${YELLOW}Clearing incident reports...${NC}"
    docker-compose exec -T postgres psql -U admin -d security_ai -c "DELETE FROM incident_reports;" 2>/dev/null
    echo -e "${GREEN}✓ Incident reports cleared${NC}"
    
    echo -e "\n${YELLOW}Re-analyzing alerts with ML...${NC}"
    
    # Get alert IDs
    ALERT_IDS=$(curl -s http://localhost:8000/alerts | python3 -c "import sys, json; alerts=json.load(sys.stdin); print(' '.join(str(a['id']) for a in alerts[:3]))" 2>/dev/null)
    
    if [ -n "$ALERT_IDS" ]; then
        for alert_id in $ALERT_IDS; do
            echo -e "${BLUE}  Analyzing alert #${alert_id}...${NC}"
            curl -s -X POST http://localhost:8000/soc/analyze/$alert_id >/dev/null
            sleep 2
        done
        
        echo -e "\n${YELLOW}Waiting 20 seconds for ML analysis to complete...${NC}"
        for i in {20..1}; do
            echo -ne "\r  Time remaining: ${i} seconds "
            sleep 1
        done
        echo -e "\n"
        
        echo -e "${GREEN}✓ Re-analysis complete${NC}"
    else
        echo -e "${YELLOW}⚠ No alerts found to analyze${NC}"
    fi
fi

# Step 5: Restart backend to apply changes
echo -e "\n${YELLOW}5. Restarting backend services...${NC}"
docker-compose restart fastapi
echo -e "${GREEN}✓ Backend restarted${NC}"

echo -e "\n${YELLOW}Waiting for backend to be ready...${NC}"
sleep 5
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
    echo -ne "\r  Waiting for FastAPI..."
    sleep 2
done
echo -e "\n${GREEN}✓ Backend is ready${NC}"

# Step 6: Test ML functionality
echo -e "\n${YELLOW}6. Testing ML functionality...${NC}"

# Create test alert
echo -e "${BLUE}  Creating test alert...${NC}"
TEST_ALERT=$(curl -s -X POST http://localhost:8000/alerts \
    -H "Content-Type: application/json" \
    -d '{
        "rule_id": "ML-TEST",
        "rule_description": "ML Functionality Test",
        "host": "juiceshop",
        "severity": 10,
        "raw_data": {
            "log": "POST /api/test payload=mltest",
            "source_ip": "192.168.100.100"
        }
    }')

TEST_ALERT_ID=$(echo "$TEST_ALERT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 0))" 2>/dev/null)

if [ "$TEST_ALERT_ID" -gt 0 ]; then
    echo -e "${GREEN}✓ Test alert created (ID: ${TEST_ALERT_ID})${NC}"
    
    # Trigger ML analysis
    echo -e "${BLUE}  Triggering ML analysis...${NC}"
    curl -s -X POST http://localhost:8000/soc/analyze/$TEST_ALERT_ID >/dev/null
    
    echo -e "${YELLOW}  Waiting 20 seconds for ML analysis...${NC}"
    for i in {20..1}; do
        echo -ne "\r    Time remaining: ${i} seconds "
        sleep 1
    done
    echo -e "\n"
    
    # Check for ML report
    echo -e "${BLUE}  Checking for ML report...${NC}"
    ML_CHECK=$(curl -s http://localhost:8000/soc/incidents | python3 << 'PYEOF'
import sys, json
try:
    reports = json.load(sys.stdin)
    if reports:
        report = reports[0]
        if 'full_report' in report and report['full_report']:
            try:
                full_report = json.loads(report['full_report'])
                if 'behavioral_analysis' in full_report:
                    print("ML_SUCCESS")
                    print(f"  ✓ Behavioral Analysis: {full_report['behavioral_analysis'].get('status', 'unknown')}")
                    if 'risk_assessment' in full_report:
                        print(f"  ✓ Risk Assessment: {full_report['risk_assessment'].get('risk_level', 'unknown')}")
                    if 'threat_predictions' in full_report:
                        preds = full_report['threat_predictions'].get('predictions', [])
                        print(f"  ✓ Predictions: {len(preds)} threats predicted")
                    if 'strategic_recommendations' in full_report:
                        recs = full_report['strategic_recommendations']
                        print(f"  ✓ Recommendations: {len(recs)} strategic actions")
                else:
                    print("NO_ML")
            except:
                print("NO_ML")
        else:
            print("NO_REPORT")
    else:
        print("NO_REPORTS")
except Exception as e:
    print(f"ERROR: {e}")
PYEOF
)
    
    if echo "$ML_CHECK" | grep -q "ML_SUCCESS"; then
        echo -e "${GREEN}✓✓✓ ML CYBER CONSULTANT IS WORKING! ✓✓✓${NC}"
        echo "$ML_CHECK" | grep "✓"
    elif echo "$ML_CHECK" | grep -q "NO_ML"; then
        echo -e "${RED}✗ ML data not in report (traditional analysis only)${NC}"
        echo -e "${YELLOW}  This means cyber_consultant.py is not being called${NC}"
    elif echo "$ML_CHECK" | grep -q "NO_REPORT"; then
        echo -e "${YELLOW}⚠ No incident report generated yet${NC}"
    else
        echo -e "${YELLOW}⚠ ${ML_CHECK}${NC}"
    fi
else
    echo -e "${RED}✗ Failed to create test alert${NC}"
fi

# Summary
echo -e "\n${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}FIX SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Open dashboard: ${GREEN}http://localhost:3001${NC}"
echo -e "  2. Go to '${BLUE}ML Cyber Consultant${NC}' tab"
echo -e "  3. You should see ML analysis with:"
echo -e "     - Behavioral Analysis (anomaly detection)"
echo -e "     - Risk Assessment (scoring)"
echo -e "     - Threat Predictions"
echo -e "     - Strategic Recommendations"
echo ""

echo -e "${YELLOW}If ML still not working:${NC}"
echo -e "  1. Check logs: ${GREEN}docker-compose logs -f fastapi | grep ML${NC}"
echo -e "  2. Verify: ${GREEN}docker-compose exec fastapi python3 -c 'from cyber_consultant import CyberConsultant'${NC}"
echo -e "  3. Re-run: ${GREEN}./fix-ml.sh${NC}"
echo ""

echo -e "${YELLOW}Manual Test:${NC}"
echo -e "  ${GREEN}curl -X POST http://localhost:8000/soc/analyze/1${NC}"
echo -e "  Wait 20 seconds, then:"
echo -e "  ${GREEN}curl http://localhost:8000/soc/incidents | python3 -m json.tool | grep -A 5 behavioral${NC}"
echo ""

echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"

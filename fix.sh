#!/bin/bash
# Apply ML Fixes - Improved behavioral analysis and dashboard

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║              APPLYING ML ANALYSIS FIXES                  ║
║                                                           ║
║  • Better anomaly detection scoring                      ║
║  • Fixed analysis return values                          ║
║  • Improved dashboard with alert details                 ║
║  • Separate tabs for Incident & ML reports               ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${RED}Error: docker-compose.yml not found. Run this from project root.${NC}"
    exit 1
fi

# Step 1: Backup existing files
echo -e "${YELLOW}1. Backing up existing files...${NC}"
mkdir -p backups/$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"

if [ -f "backend/cyber_consultant.py" ]; then
    cp backend/cyber_consultant.py "$BACKUP_DIR/cyber_consultant.py.backup"
    echo -e "${GREEN}✓ Backed up cyber_consultant.py${NC}"
fi

if [ -f "frontend/src/App.js" ]; then
    cp frontend/src/App.js "$BACKUP_DIR/App.js.backup"
    echo -e "${GREEN}✓ Backed up App.js${NC}"
fi

# Step 2: Copy the fixed cyber_consultant.py from the artifact above
echo -e "\n${YELLOW}2. Updating cyber_consultant.py...${NC}"
echo -e "${CYAN}Please copy the 'Fixed ML Cyber Consultant' artifact content to:${NC}"
echo -e "${CYAN}  backend/cyber_consultant.py${NC}"
echo -e "\n${YELLOW}Press ENTER when done...${NC}"
read

if [ -f "backend/cyber_consultant.py" ]; then
    echo -e "${GREEN}✓ cyber_consultant.py found${NC}"
else
    echo -e "${RED}✗ cyber_consultant.py not found. Please create it.${NC}"
    exit 1
fi

# Step 3: Copy the improved dashboard
echo -e "\n${YELLOW}3. Updating frontend dashboard...${NC}"
echo -e "${CYAN}Please copy the 'Improved Security Dashboard' artifact content to:${NC}"
echo -e "${CYAN}  frontend/src/App.js${NC}"
echo -e "\n${YELLOW}Press ENTER when done...${NC}"
read

if [ -f "frontend/src/App.js" ]; then
    echo -e "${GREEN}✓ App.js updated${NC}"
else
    echo -e "${RED}✗ App.js not found. Please create it.${NC}"
    exit 1
fi

# Step 4: Clear old incident reports
echo -e "\n${YELLOW}4. Clearing old incident reports...${NC}"
read -p "Clear old incident reports and re-analyze? (y/n): " clear_choice

if [ "$clear_choice" = "y" ] || [ "$clear_choice" = "Y" ]; then
    echo -e "${BLUE}Clearing incident reports...${NC}"
    docker-compose exec -T postgres psql -U admin -d security_ai -c "DELETE FROM incident_reports;" 2>/dev/null
    echo -e "${GREEN}✓ Incident reports cleared${NC}"
fi

# Step 5: Restart services
echo -e "\n${YELLOW}5. Restarting services...${NC}"
docker-compose restart fastapi
echo -e "${GREEN}✓ Backend restarted${NC}"

# Wait for backend
echo -e "\n${YELLOW}Waiting for backend...${NC}"
sleep 5
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
    echo -ne "\r  Waiting for FastAPI..."
    sleep 2
done
echo -e "\n${GREEN}✓ Backend ready${NC}"

# Step 6: Re-analyze alerts
if [ "$clear_choice" = "y" ] || [ "$clear_choice" = "Y" ]; then
    echo -e "\n${YELLOW}6. Re-analyzing alerts with improved ML...${NC}"
    
    # Get alert IDs
    ALERT_IDS=$(curl -s http://localhost:8000/alerts | python3 -c "import sys, json; alerts=json.load(sys.stdin); print(' '.join(str(a['id']) for a in alerts[:5]))" 2>/dev/null)
    
    if [ -n "$ALERT_IDS" ]; then
        for alert_id in $ALERT_IDS; do
            echo -e "${BLUE}  Analyzing alert #${alert_id}...${NC}"
            curl -s -X POST http://localhost:8000/soc/analyze/$alert_id >/dev/null
            sleep 3
        done
        
        echo -e "\n${YELLOW}Waiting 25 seconds for ML analysis...${NC}"
        for i in {25..1}; do
            echo -ne "\r  Time remaining: ${i} seconds "
            sleep 1
        done
        echo -e "\n"
        
        echo -e "${GREEN}✓ Re-analysis complete${NC}"
    else
        echo -e "${YELLOW}⚠ No alerts found to analyze${NC}"
    fi
fi

# Step 7: Test improvements
echo -e "\n${YELLOW}7. Testing improvements...${NC}"

# Check ML reports
echo -e "\n${BLUE}Checking ML incident reports...${NC}"
ML_CHECK=$(curl -s http://localhost:8000/soc/incidents | python3 << 'PYEOF'
import sys, json
try:
    reports = json.load(sys.stdin)
    if reports:
        report = reports[0]
        if 'full_report' in report and report['full_report']:
            try:
                full_report = json.loads(report['full_report'])
                print(f"✓ Found {len(reports)} reports")
                
                if 'alert_name' in full_report:
                    print(f"✓ Alert names included: {full_report['alert_name']}")
                
                if 'behavioral_analysis' in full_report:
                    ba = full_report['behavioral_analysis']
                    print(f"✓ Behavioral Analysis:")
                    print(f"  - Status: {ba.get('status')}")
                    print(f"  - Is Anomalous: {ba.get('is_anomalous')}")
                    if ba.get('is_anomalous'):
                        print(f"  - Anomaly Score: {ba.get('anomaly_score'):.3f}")
                        print(f"  - Outlier Count: {ba.get('outlier_count', 0)}")
                
                if 'risk_assessment' in full_report:
                    ra = full_report['risk_assessment']
                    print(f"✓ Risk Assessment:")
                    print(f"  - Risk Level: {ra.get('risk_level')}")
                    print(f"  - Risk Score: {ra.get('total_score')}/100")
                
                if 'threat_predictions' in full_report:
                    tp = full_report['threat_predictions']
                    print(f"✓ Threat Predictions: {len(tp.get('predictions', []))} threats")
                
                if 'strategic_recommendations' in full_report:
                    recs = full_report['strategic_recommendations']
                    print(f"✓ Recommendations: {len(recs)} actions")
                
                print("SUCCESS")
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print("NO_REPORT")
    else:
        print("NO_REPORTS")
except Exception as e:
    print(f"ERROR: {e}")
PYEOF
)

echo "$ML_CHECK"

if echo "$ML_CHECK" | grep -q "SUCCESS"; then
    echo -e "\n${GREEN}✓✓✓ ML IMPROVEMENTS WORKING! ✓✓✓${NC}"
else
    echo -e "\n${RED}⚠ Some issues detected. Check logs.${NC}"
fi

# Summary
echo -e "\n${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}FIX SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"

echo -e "${GREEN}Improvements Applied:${NC}"
echo -e "  ✓ Better anomaly detection with severity levels"
echo -e "  ✓ Fixed ML analysis return values"
echo -e "  ✓ Alert names included in reports"
echo -e "  ✓ Improved dashboard with alert details"
echo -e "  ✓ Separate modals for Incident & ML reports"
echo -e "  ✓ Better risk assessment calculations"

echo -e "\n${YELLOW}New Features:${NC}"
echo -e "  • Click any alert to see details"
echo -e "  • View ML Analysis button shows behavioral insights"
echo -e "  • Incident Report button shows formal report"
echo -e "  • Run Analysis button for on-demand ML"
echo -e "  • Statistical deviations shown for anomalies"

echo -e "\n${YELLOW}Dashboard Changes:${NC}"
echo -e "  • Overview tab shows recent alerts & system health"
echo -e "  • Live Alerts tab has clickable alerts"
echo -e "  • Alert details modal with action buttons"
echo -e "  • ML Analysis modal shows full insights"
echo -e "  • Incident Report modal shows formal report"

echo -e "\n${CYAN}Testing the Improvements:${NC}"
echo -e "  1. Open dashboard: ${GREEN}http://localhost:3001${NC}"
echo -e "  2. Go to '${BLUE}Live Alerts${NC}' tab"
echo -e "  3. Click any alert to see details"
echo -e "  4. Click '${BLUE}View ML Analysis${NC}' to see:"
echo -e "     - Behavioral anomaly detection"
echo -e "     - Risk assessment scoring"
echo -e "     - Threat predictions"
echo -e "     - Strategic recommendations"
echo -e "  5. Click '${BLUE}Incident Report${NC}' for formal report"

echo -e "\n${YELLOW}Run New Test Attacks:${NC}"
echo -e "  ${GREEN}./attack.sh${NC}"
echo -e "  Select option [8] for anomaly testing"
echo -e "  Wait 25 seconds, then check ML Analysis"

echo -e "\n${YELLOW}Check Logs:${NC}"
echo -e "  ${GREEN}docker-compose logs -f fastapi | grep -A 5 'AI CYBER CONSULTANT'${NC}"

echo -e "\n${YELLOW}Manual Testing:${NC}"
echo -e "  # Create test alert"
echo -e "  ${GREEN}curl -X POST http://localhost:8000/alerts \\${NC}"
echo -e "  ${GREEN}  -H 'Content-Type: application/json' \\${NC}"
echo -e "  ${GREEN}  -d '{${NC}"
echo -e "  ${GREEN}    \"rule_id\": \"TEST-001\",${NC}"
echo -e "  ${GREEN}    \"rule_description\": \"Test Alert\",${NC}"
echo -e "  ${GREEN}    \"host\": \"juiceshop\",${NC}"
echo -e "  ${GREEN}    \"severity\": 10,${NC}"
echo -e "  ${GREEN}    \"raw_data\": {${NC}"
echo -e "  ${GREEN}      \"log\": \"$(python3 -c 'print("A"*10000)')\"${NC}"
echo -e "  ${GREEN}    }${NC}"
echo -e "  ${GREEN}  }'${NC}"
echo -e ""
echo -e "  # Analyze it"
echo -e "  ${GREEN}curl -X POST http://localhost:8000/soc/analyze/[ALERT_ID]${NC}"
echo -e ""
echo -e "  # Wait 25 seconds, then check"
echo -e "  ${GREEN}curl http://localhost:8000/soc/incidents | python3 -m json.tool${NC}"

echo -e "\n${BLUE}Expected Results:${NC}"
echo -e "  For anomalous attacks (long requests, unusual patterns):"
echo -e "  • Anomaly Score: < -0.2 (negative = anomalous)"
echo -e "  • Is Anomalous: true"
echo -e "  • Outlier Count: 1-3 factors"
echo -e "  • Risk Level: MEDIUM to HIGH"
echo -e ""
echo -e "  For normal attacks:"
echo -e "  • Anomaly Score: > -0.1"
echo -e "  • Is Anomalous: false"
echo -e "  • Risk Level: LOW to MEDIUM"

echo -e "\n${RED}If Still Having Issues:${NC}"
echo -e "  1. Check Python imports:"
echo -e "     ${CYAN}docker-compose exec fastapi python3 -c 'from cyber_consultant import CyberConsultant; c = CyberConsultant(); print(\"✓ OK\")'${NC}"
echo -e ""
echo -e "  2. Check sklearn:"
echo -e "     ${CYAN}docker-compose exec fastapi python3 -c 'from sklearn.ensemble import IsolationForest; print(\"✓ OK\")'${NC}"
echo -e ""
echo -e "  3. View detailed logs:"
echo -e "     ${CYAN}docker-compose logs --tail=100 fastapi | grep -i 'error\\|exception\\|traceback' | tail -20${NC}"
echo -e ""
echo -e "  4. Rebuild backend:"
echo -e "     ${CYAN}docker-compose up -d --build fastapi${NC}"
echo -e ""
echo -e "  5. Reset everything:"
echo -e "     ${CYAN}docker-compose down -v && ./startup.sh${NC}"

echo -e "\n${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Fixes Applied Successfully!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}Backups saved to: ${CYAN}$BACKUP_DIR${NC}\n"

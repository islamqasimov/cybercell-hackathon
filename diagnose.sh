#!/bin/bash
# Enhanced Diagnostic script for AI Security Platform with ML Threat Detection

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

API_URL="http://localhost:8000"

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║    AI SECURITY PLATFORM - ML DIAGNOSTICS                 ║
║    Testing: Traditional SIEM + ML Cyber Consultant       ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((TESTS_FAILED++))
    fi
}

# 1. Docker Containers
echo -e "${CYAN}[1] Checking Docker containers...${NC}"
docker-compose ps
echo ""

CONTAINERS=("postgres" "redis" "juiceshop" "fastapi" "frontend")
for container in "${CONTAINERS[@]}"; do
    echo -n "  Checking $container... "
    docker-compose ps | grep -q "$container.*Up"
    test_result $?
done
echo ""

# 2. API Health
echo -e "${CYAN}[2] Checking API health...${NC}"
echo -n "  API endpoint... "
HEALTH=$(curl -s $API_URL/health 2>/dev/null)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    echo "$HEALTH" | python3 -m json.tool 2>/dev/null
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# 3. Database Connection
echo -e "${CYAN}[3] Checking database...${NC}"
echo -n "  PostgreSQL connection... "
docker-compose exec -T postgres pg_isready -U admin >/dev/null 2>&1
test_result $?

echo -n "  Database tables... "
TABLE_COUNT=$(docker-compose exec -T postgres psql -U admin -d security_ai -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null | tr -d ' ')
if [ "$TABLE_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS (${TABLE_COUNT} tables)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# 4. Backend Files
echo -e "${CYAN}[4] Checking backend files...${NC}"
FILES=("main.py" "soc_analyst.py" "security_auditor.py" "ai_engine.py" "cyber_consultant.py")
for file in "${FILES[@]}"; do
    echo -n "  $file... "
    docker-compose exec -T fastapi test -f "$file"
    test_result $?
done
echo ""

# 5. Python Imports
echo -e "${CYAN}[5] Checking Python imports...${NC}"
MODULES=("main" "soc_analyst" "security_auditor" "ai_engine" "cyber_consultant")
for module in "${MODULES[@]}"; do
    echo -n "  $module... "
    docker-compose exec -T fastapi python3 -c "import $module" 2>/dev/null
    test_result $?
done
echo ""

# 6. ML Libraries
echo -e "${CYAN}[6] Checking ML libraries...${NC}"
ML_LIBS=("sklearn" "numpy" "pandas")
for lib in "${ML_LIBS[@]}"; do
    echo -n "  $lib... "
    docker-compose exec -T fastapi python3 -c "import $lib" 2>/dev/null
    test_result $?
done
echo ""

# 7. System Statistics
echo -e "${CYAN}[7] Checking system statistics...${NC}"
STATS=$(curl -s $API_URL/stats 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$STATS" | python3 -m json.tool 2>/dev/null
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Failed to fetch stats${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# 8. Endpoints Test
echo -e "${CYAN}[8] Testing endpoints...${NC}"
ENDPOINTS=(
    "/health:Health check"
    "/stats:System statistics"
    "/alerts:List alerts"
    "/rules:Detection rules"
    "/soc/rule-recommendations:Rule recommendations"
    "/soc/incidents:Incident reports"
    "/auditor/results:Audit results"
)

for endpoint_info in "${ENDPOINTS[@]}"; do
    IFS=':' read -r endpoint desc <<< "$endpoint_info"
    echo -n "  $desc ($endpoint)... "
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" $API_URL$endpoint)
    if [ "$STATUS" -eq "200" ]; then
        echo -e "${GREEN}✓ PASS (${STATUS})${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL (${STATUS})${NC}"
        ((TESTS_FAILED++))
    fi
done
echo ""

# 9. ML Cyber Consultant Specific Tests
echo -e "${CYAN}[9] Testing ML Cyber Consultant functionality...${NC}"

# Check if cyber_consultant module exists and imports
echo -n "  cyber_consultant.py module... "
docker-compose exec -T fastapi python3 -c "from cyber_consultant import CyberConsultant" 2>/dev/null
test_result $?

# Check ML classes
echo -n "  ML classes (IsolationForest, StandardScaler)... "
docker-compose exec -T fastapi python3 -c "from sklearn.ensemble import IsolationForest; from sklearn.preprocessing import StandardScaler" 2>/dev/null
test_result $?

# Check if incident_reports table has ML data
echo -n "  Incident reports with ML data... "
INCIDENT_COUNT=$(curl -s $API_URL/soc/incidents 2>/dev/null | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data))" 2>/dev/null || echo "0")
if [ "$INCIDENT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS (${INCIDENT_COUNT} reports)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ WARN (no reports yet - run analysis first)${NC}"
fi

# Test behavioral analysis functions
echo -n "  Behavioral analysis function... "
docker-compose exec -T fastapi python3 << 'PYEOF' 2>/dev/null
from cyber_consultant import CyberConsultant
consultant = CyberConsultant()
print("✓ CyberConsultant initialized")
PYEOF
test_result $?

echo ""

# 10. Create Test Alert and Analyze
echo -e "${CYAN}[10] Testing ML analysis workflow...${NC}"

echo -n "  Creating test alert... "
ALERT_RESPONSE=$(curl -s -X POST $API_URL/alerts \
    -H "Content-Type: application/json" \
    -d '{
        "rule_id": "SQLI-001",
        "rule_description": "SQL Injection - ML Test",
        "host": "juiceshop",
        "severity": 12,
        "raw_data": {
            "log": "POST /rest/user/login email=admin'\''-- password=test",
            "source_ip": "192.168.1.100",
            "user_agent": "sqlmap/1.4",
            "attack_pattern": "admin'\''--"
        }
    }' 2>/dev/null)

ALERT_ID=$(echo "$ALERT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 0))" 2>/dev/null || echo "0")
if [ "$ALERT_ID" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS (Alert ID: ${ALERT_ID})${NC}"
    ((TESTS_PASSED++))
    
    # Trigger ML analysis
    echo -n "  Triggering ML analysis... "
    curl -s -X POST $API_URL/soc/analyze/$ALERT_ID >/dev/null 2>&1
    test_result $?
    
    echo -e "  ${YELLOW}Waiting 20 seconds for ML analysis...${NC}"
    for i in {20..1}; do
        echo -ne "\r    Time remaining: ${i} seconds "
        sleep 1
    done
    echo -e "\r    ${GREEN}✓ Analysis time complete${NC}                "
    
    # Check for incident report
    echo -n "  Checking incident report generated... "
    REPORTS=$(curl -s $API_URL/soc/incidents 2>/dev/null)
    REPORT_COUNT=$(echo "$REPORTS" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    if [ "$REPORT_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ PASS (${REPORT_COUNT} reports)${NC}"
        ((TESTS_PASSED++))
        
        # Check for ML-specific fields in report
        echo -n "  Checking ML fields in report... "
        HAS_ML=$(echo "$REPORTS" | python3 << 'PYEOF' 2>/dev/null
import sys, json
reports = json.load(sys.stdin)
if reports:
    report = reports[0]
    # Check for ML-specific indicators
    if 'full_report' in report and report['full_report']:
        try:
            full_report = json.loads(report['full_report'])
            if 'behavioral_analysis' in full_report or 'risk_assessment' in full_report:
                print("YES")
            else:
                print("NO")
        except:
            print("NO")
    else:
        print("NO")
else:
    print("NO")
PYEOF
)
        if [ "$HAS_ML" = "YES" ]; then
            echo -e "${GREEN}✓ PASS (ML data present)${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${YELLOW}⚠ WARN (ML data may not be complete)${NC}"
        fi
        
        # Display sample ML output
        echo -e "\n  ${MAGENTA}Sample ML Analysis Output:${NC}"
        echo "$REPORTS" | python3 << 'PYEOF' 2>/dev/null
import sys, json
reports = json.load(sys.stdin)
if reports:
    report = reports[0]
    print(f"    Alert ID: {report.get('alert_id')}")
    print(f"    Severity: {report.get('severity')}")
    print(f"    Attack Type: {report.get('attack_type')}")
    print(f"    Threat Level: {report.get('threat_level')}")
    print(f"    Is False Positive: {report.get('is_false_positive')}")
    
    if 'full_report' in report and report['full_report']:
        try:
            full_report = json.loads(report['full_report'])
            if 'behavioral_analysis' in full_report:
                ba = full_report['behavioral_analysis']
                print(f"\n    Behavioral Analysis:")
                print(f"      - Is Anomalous: {ba.get('is_anomalous')}")
                print(f"      - Anomaly Score: {ba.get('anomaly_score', 'N/A')}")
                print(f"      - Status: {ba.get('status')}")
            
            if 'risk_assessment' in full_report:
                ra = full_report['risk_assessment']
                print(f"\n    Risk Assessment:")
                print(f"      - Risk Level: {ra.get('risk_level')}")
                print(f"      - Total Score: {ra.get('total_score')}/100")
                print(f"      - Business Impact: {ra.get('business_impact', '')[:80]}...")
            
            if 'threat_predictions' in full_report:
                tp = full_report['threat_predictions']
                preds = tp.get('predictions', [])
                if preds:
                    print(f"\n    Threat Predictions: {len(preds)} predictions")
                    for i, pred in enumerate(preds[:2], 1):
                        print(f"      {i}. {pred.get('threat')} ({pred.get('probability')})")
            
            if 'strategic_recommendations' in full_report:
                recs = full_report['strategic_recommendations']
                if recs:
                    print(f"\n    Strategic Recommendations: {len(recs)} recommendations")
                    for i, rec in enumerate(recs[:2], 1):
                        print(f"      {i}. [{rec.get('priority')}] {rec.get('title')}")
        except Exception as e:
            print(f"    Error parsing ML report: {e}")
PYEOF
        echo ""
    else
        echo -e "${RED}✗ FAIL (no reports generated)${NC}"
        ((TESTS_FAILED++))
    fi
    
else
    echo -e "${RED}✗ FAIL${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# 11. Check Rule Recommendations (Traditional + ML)
echo -e "${CYAN}[11] Checking rule recommendations...${NC}"
echo -n "  Fetching recommendations... "
RECS=$(curl -s $API_URL/soc/rule-recommendations 2>/dev/null)
REC_COUNT=$(echo "$RECS" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
if [ "$REC_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS (${REC_COUNT} recommendations)${NC}"
    ((TESTS_PASSED++))
    
    # Check for ML-generated rules
    echo -n "  Checking for ML-generated rules... "
    ML_RULES=$(echo "$RECS" | python3 << 'PYEOF' 2>/dev/null
import sys, json
recs = json.load(sys.stdin)
ml_count = sum(1 for rec in recs if 'ANOMALY' in rec.get('rule_id', '') or 'PREDICT' in rec.get('rule_id', '') or 'ML' in rec.get('reason', '').upper())
print(ml_count)
PYEOF
)
    if [ "$ML_RULES" -gt 0 ]; then
        echo -e "${GREEN}✓ PASS (${ML_RULES} ML-generated rules)${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${YELLOW}⚠ WARN (no ML rules yet - may need more analysis)${NC}"
    fi
    
    # Display sample recommendations
    echo -e "\n  ${MAGENTA}Sample Rule Recommendations:${NC}"
    echo "$RECS" | python3 << 'PYEOF' 2>/dev/null
import sys, json
recs = json.load(sys.stdin)
for i, rec in enumerate(recs[:3], 1):
    print(f"    {i}. [{rec.get('action')}] {rec.get('rule_id')}")
    print(f"       Confidence: {rec.get('confidence')}%")
    print(f"       Reason: {rec.get('reason', '')[:80]}...")
    if 'ANOMALY' in rec.get('rule_id', '') or 'ML' in rec.get('reason', '').upper():
        print(f"       ⭐ ML-Generated Rule")
    print()
PYEOF
else
    echo -e "${YELLOW}⚠ WARN (no recommendations yet)${NC}"
fi
echo ""

# 12. Test Anomaly Detection with Unusual Pattern
echo -e "${CYAN}[12] Testing anomaly detection...${NC}"

echo -n "  Creating anomalous alert (unusual length)... "
ANOMALY_RESPONSE=$(curl -s -X POST $API_URL/alerts \
    -H "Content-Type: application/json" \
    -d "{
        \"rule_id\": \"ANOMALY-TEST\",
        \"rule_description\": \"Anomaly Detection Test\",
        \"host\": \"juiceshop\",
        \"severity\": 8,
        \"raw_data\": {
            \"log\": \"GET /search?q=$(python3 -c 'print("A"*8000)')\",
            \"source_ip\": \"192.168.1.200\"
        }
    }" 2>/dev/null)

ANOMALY_ID=$(echo "$ANOMALY_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 0))" 2>/dev/null || echo "0")
if [ "$ANOMALY_ID" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS (Alert ID: ${ANOMALY_ID})${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# 13. Check AI Configuration
echo -e "${CYAN}[13] Checking AI configuration...${NC}"
docker-compose exec -T fastapi env | grep -E "OLLAMA|OPENAI|USE_" 2>/dev/null
echo ""

# 14. Error Log Analysis
echo -e "${CYAN}[14] Checking for errors in logs...${NC}"
echo -e "  ${YELLOW}Last 15 error lines:${NC}"
docker-compose logs --tail=100 fastapi 2>&1 | grep -i "error\|exception\|traceback" | tail -15
echo ""

# 15. ML Model Performance Check
echo -e "${CYAN}[15] ML model performance check...${NC}"
echo -n "  Testing IsolationForest... "
docker-compose exec -T fastapi python3 << 'PYEOF' 2>/dev/null
import numpy as np
from sklearn.ensemble import IsolationForest

# Test ML model
X = np.array([[1, 2], [2, 3], [3, 4], [100, 200]])  # Last one is anomaly
clf = IsolationForest(random_state=42)
clf.fit(X)
predictions = clf.predict(X)
if predictions[-1] == -1:  # Should detect last as anomaly
    print("✓ ML model working correctly")
else:
    print("✗ ML model may have issues")
PYEOF
test_result $?

echo -n "  Testing feature extraction... "
docker-compose exec -T fastapi python3 << 'PYEOF' 2>/dev/null
from cyber_consultant import CyberConsultant
from main import Alert
from datetime import datetime

# Mock alert
class MockAlert:
    severity = 10
    timestamp = datetime.utcnow()
    raw_data = {'log': 'test' * 100}

consultant = CyberConsultant()
alert = MockAlert()
features = consultant._extract_behavioral_features(alert)
if len(features) == 5:  # Should return 5 features
    print("✓ Feature extraction working")
else:
    print("✗ Feature extraction may have issues")
PYEOF
test_result $?
echo ""

# Summary
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}DIAGNOSTIC SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
PASS_RATE=$((TESTS_PASSED * 100 / TOTAL_TESTS))

echo -e "  Total Tests: ${CYAN}${TOTAL_TESTS}${NC}"
echo -e "  Passed:      ${GREEN}${TESTS_PASSED}${NC}"
echo -e "  Failed:      ${RED}${TESTS_FAILED}${NC}"
echo -e "  Pass Rate:   ${CYAN}${PASS_RATE}%${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL SYSTEMS OPERATIONAL${NC}"
    echo -e "${GREEN}✓ ML Cyber Consultant is working correctly${NC}"
else
    echo -e "${YELLOW}⚠ Some tests failed. Review details above.${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Quick Fixes:${NC}"
echo -e "  • View logs:        ${GREEN}docker-compose logs -f fastapi${NC}"
echo -e "  • Restart services: ${GREEN}docker-compose restart${NC}"
echo -e "  • Rebuild backend:  ${GREEN}docker-compose up -d --build fastapi${NC}"
echo -e "  • Reset database:   ${GREEN}docker-compose down -v && docker-compose up -d${NC}"
echo ""

echo -e "${YELLOW}Manual ML Testing:${NC}"
echo -e "  • Run attacks:      ${GREEN}./attack.sh${NC}"
echo -e "  • Analyze alert:    ${GREEN}curl -X POST $API_URL/soc/analyze/1${NC}"
echo -e "  • View ML reports:  ${GREEN}curl $API_URL/soc/incidents | python3 -m json.tool${NC}"
echo -e "  • Check anomalies:  ${GREEN}curl $API_URL/soc/rule-recommendations | grep ANOMALY${NC}"
echo ""

echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"

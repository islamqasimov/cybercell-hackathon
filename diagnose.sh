#!/bin/bash
# Diagnostic script for AI Security Platform

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║         AI SECURITY PLATFORM - DIAGNOSTICS               ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Check Docker containers
echo -e "${YELLOW}1. Checking Docker containers...${NC}"
docker-compose ps
echo -e "\n"

# Check API health
echo -e "${YELLOW}2. Checking API health...${NC}"
HEALTH=$(curl -s http://localhost:8000/health)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ API is responsive${NC}"
    echo "$HEALTH" | python3 -m json.tool 2>/dev/null
else
    echo -e "${RED}✗ API is not responding${NC}"
fi
echo -e "\n"

# Check database connection
echo -e "${YELLOW}3. Checking database...${NC}"
docker-compose exec -T postgres pg_isready -U admin
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Database is ready${NC}"
else
    echo -e "${RED}✗ Database connection failed${NC}"
fi
echo -e "\n"

# Check backend files
echo -e "${YELLOW}4. Checking backend files...${NC}"
FILES=("main.py" "soc_analyst.py" "security_auditor.py" "ai_engine.py" "init_system.py")
for file in "${FILES[@]}"; do
    if docker-compose exec -T fastapi test -f "$file"; then
        echo -e "${GREEN}✓${NC} $file exists"
    else
        echo -e "${RED}✗${NC} $file missing"
    fi
done
echo -e "\n"

# Check Python imports
echo -e "${YELLOW}5. Checking Python imports...${NC}"
docker-compose exec -T fastapi python3 << 'PYEOF'
import sys
errors = []

try:
    import main
    print("✓ main.py imported")
except Exception as e:
    print(f"✗ main.py: {e}")
    errors.append("main")

try:
    import soc_analyst
    print("✓ soc_analyst.py imported")
except Exception as e:
    print(f"✗ soc_analyst.py: {e}")
    errors.append("soc_analyst")

try:
    import security_auditor
    print("✓ security_auditor.py imported")
except Exception as e:
    print(f"✗ security_auditor.py: {e}")
    errors.append("security_auditor")

try:
    import ai_engine
    print("✓ ai_engine.py imported")
except Exception as e:
    print(f"✗ ai_engine.py: {e}")
    errors.append("ai_engine")

if errors:
    sys.exit(1)
PYEOF
echo -e "\n"

# Check database tables
echo -e "${YELLOW}6. Checking database tables...${NC}"
docker-compose exec -T postgres psql -U admin -d security_ai -c "\dt" 2>/dev/null
echo -e "\n"

# Check data counts
echo -e "${YELLOW}7. Checking data counts...${NC}"
STATS=$(curl -s http://localhost:8000/stats)
echo "$STATS" | python3 -m json.tool 2>/dev/null
echo -e "\n"

# Check recent logs for errors
echo -e "${YELLOW}8. Checking for errors in logs...${NC}"
echo -e "${BLUE}Last 10 error lines:${NC}"
docker-compose logs fastapi 2>&1 | grep -i "error\|exception\|traceback" | tail -10
echo -e "\n"

# Test endpoints
echo -e "${YELLOW}9. Testing endpoints...${NC}"
ENDPOINTS=("/health" "/stats" "/alerts" "/rules" "/soc/rule-recommendations" "/soc/incidents" "/auditor/results")
for endpoint in "${ENDPOINTS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000$endpoint)
    if [ "$STATUS" -eq "200" ]; then
        echo -e "${GREEN}✓${NC} $endpoint (${STATUS})"
    else
        echo -e "${RED}✗${NC} $endpoint (${STATUS})"
    fi
done
echo -e "\n"

# Check AI configuration
echo -e "${YELLOW}10. Checking AI configuration...${NC}"
docker-compose exec -T fastapi env | grep -E "OLLAMA|OPENAI|USE_"
echo -e "\n"

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}Diagnostics Complete${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

echo -e "${YELLOW}Quick Fixes:${NC}"
echo -e "  • Restart services: ${GREEN}docker-compose restart${NC}"
echo -e "  • View logs: ${GREEN}docker-compose logs -f fastapi${NC}"
echo -e "  • Rebuild: ${GREEN}docker-compose up -d --build fastapi${NC}"
echo -e "  • Reset DB: ${GREEN}docker-compose down -v && docker-compose up -d${NC}"
echo -e "\n"

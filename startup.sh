#!/bin/bash
# AI Security Platform - Complete Startup Script

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║   AI SECURITY PLATFORM - TWO AI AGENTS SYSTEM            ║
║                                                           ║
║   🤖 AI Agent #1: SOC Analyst (Alert Responder)          ║
║   🤖 AI Agent #2: Security Auditor (Code Scanner)        ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if Docker is running
echo -e "\n${YELLOW}Checking Docker...${NC}"
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}✗ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker is running${NC}"

# Check for .env file
if [ ! -f ".env" ]; then
    echo -e "\n${YELLOW}Creating .env file...${NC}"
    cat > .env << 'ENVFILE'
# AI Configuration
USE_OLLAMA=true
OLLAMA_URL=http://localhost:11434
OPENAI_API_KEY=

# Database
DATABASE_URL=postgresql://admin:hackathon2024@postgres:5432/security_ai

# Juice Shop
JUICESHOP_URL=http://juiceshop:3000
JUICESHOP_SOURCE=/app/juiceshop-source
ENVFILE
    echo -e "${GREEN}✓ Created .env file${NC}"
fi

# Build and start services
echo -e "\n${YELLOW}Building and starting services...${NC}"
docker-compose down -v 2>/dev/null || true
docker-compose up -d --build

# Wait for services
echo -e "\n${YELLOW}Waiting for services to be ready...${NC}"

echo -e "  ${BLUE}→${NC} PostgreSQL..."
sleep 5
until docker-compose exec -T postgres pg_isready -U admin > /dev/null 2>&1; do
    echo -e "    Waiting for PostgreSQL..."
    sleep 2
done
echo -e "  ${GREEN}✓${NC} PostgreSQL ready"

echo -e "  ${BLUE}→${NC} FastAPI Backend..."
sleep 3
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
    echo -e "    Waiting for FastAPI..."
    sleep 2
done
echo -e "  ${GREEN}✓${NC} FastAPI ready"

echo -e "  ${BLUE}→${NC} Juice Shop..."
until curl -s http://localhost:3000 > /dev/null 2>&1; do
    echo -e "    Waiting for Juice Shop..."
    sleep 2
done
echo -e "  ${GREEN}✓${NC} Juice Shop ready"

# Initialize system
echo -e "\n${YELLOW}Initializing AI Security Platform...${NC}"
docker-compose exec -T fastapi python init_system.py

# Show status
echo -e "\n${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ System is READY!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}Access Points:${NC}"
echo -e "  🌐 Dashboard:     ${GREEN}http://localhost:3001${NC}"
echo -e "  🔧 Backend API:   ${GREEN}http://localhost:8000${NC}"
echo -e "  🎯 Juice Shop:    ${GREEN}http://localhost:3000${NC}"
echo -e "  📊 API Docs:      ${GREEN}http://localhost:8000/docs${NC}"

echo -e "\n${YELLOW}Quick Start:${NC}"
echo -e "  1. Open dashboard: ${GREEN}http://localhost:3001${NC}"
echo -e "  2. Click '${BLUE}Run Security Audit${NC}' button"
echo -e "  3. View AI recommendations in '${BLUE}AI SOC Analyst${NC}' tab"
echo -e "  4. Check validated vulnerabilities in '${BLUE}AI Security Auditor${NC}' tab"

echo -e "\n${YELLOW}Demo Script:${NC}"
echo -e "  Run: ${GREEN}./demo.sh${NC} for automated demo"

echo -e "\n${YELLOW}Logs:${NC}"
echo -e "  docker-compose logs -f fastapi    # Backend logs"
echo -e "  docker-compose logs -f frontend   # Frontend logs"

echo -e "\n${YELLOW}Stop System:${NC}"
echo -e "  docker-compose down"

echo -e "\n${BLUE}═══════════════════════════════════════════════${NC}\n"

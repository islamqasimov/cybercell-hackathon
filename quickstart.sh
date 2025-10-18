#!/bin/bash
# quickstart.sh - One-command setup for Security AI System
# Usage: curl -fsSL https://your-repo/quickstart.sh | bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                 SECURITY AI SYSTEM - QUICKSTART               ║
║        AI-Powered Threat Detection & Response Platform        ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

print_step() {
    echo -e "\n${GREEN}[STEP $1/$2]${NC} $3"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check prerequisites
print_step 1 10 "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_error "Docker not found. Please install Docker first."
    exit 1
fi
print_success "Docker installed"

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose not found. Please install Docker Compose first."
    exit 1
fi
print_success "Docker Compose installed"

# Check Docker is running
if ! docker info &> /dev/null; then
    print_error "Docker is not running. Please start Docker."
    exit 1
fi
print_success "Docker is running"

# Create project structure
print_step 2 10 "Creating project structure..."

PROJECT_DIR="${PROJECT_DIR:-security-ai}"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

mkdir -p fastapi frontend/public frontend/src scripts models logs/juiceshop data

print_success "Project structure created"

# Create .env file
print_step 3 10 "Creating configuration files..."

cat > .env << 'ENVEOF'
# Database
POSTGRES_DB=security_ai
POSTGRES_USER=admin
POSTGRES_PASSWORD=hackathon2024

# Wazuh
WAZUH_URL=https://wazuh:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-

# Nessus (Optional)
NESSUS_URL=https://nessus:8834
NESSUS_ACCESS_KEY=your_key_here
NESSUS_SECRET_KEY=your_secret_here

# Application
DEBUG=true
LOG_LEVEL=INFO
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000/ws
ENVEOF

print_success "Configuration created"

# Create README
print_step 4 10 "Generating documentation..."

cat > README.md << 'READMEEOF'
# Security AI System

## Quick Start

```bash
# Start all services
docker-compose up -d

# Wait for Wazuh to initialize (2-3 minutes)
docker-compose logs -f wazuh | grep "Wazuh API is ready"

# Train anomaly detection model
docker-compose exec fastapi python anomaly_detector.py

# Launch attack simulation
./scripts/attack_simulator.sh sqli

# View dashboard
open http://localhost:3001
```

## Services

- **Frontend Dashboard**: http://localhost:3001
- **FastAPI**: http://localhost:8000
- **Wazuh Dashboard**: https://localhost:443 (admin/SecretPassword)
- **Juice Shop**: http://localhost:3000

## Architecture

```
Attack → Juice Shop → Wazuh → FastAPI (AI) → Frontend
                         ↓
                     Nessus Scans
```

## Components

1. **Anomaly Detector**: ML-based behavioral analysis
2. **SOC Analyst AI**: Automated incident reporting
3. **Risk Correlator**: Multi-source threat scoring
4. **Automated Response**: Playbook execution

## Demo

```bash
./scripts/demo.sh
```

For detailed documentation, see INTEGRATION_GUIDE.md
READMEEOF

print_success "Documentation generated"

# Download/create necessary files
print_step 5 10 "Setting up application files..."

print_info "You'll need to copy the following files from the artifacts:"
echo ""
echo "Backend (copy to fastapi/):"
echo "  - main.py"
echo "  - anomaly_detector.py"
echo "  - soc_analyst_ai.py"
echo "  - integration_service.py"
echo "  - requirements.txt"
echo "  - Dockerfile"
echo ""
echo "Frontend (copy to frontend/):"
echo "  - package.json"
echo "  - Dockerfile"
echo "  - nginx.conf"
echo "  - public/index.html"
echo "  - src/index.js"
echo "  - src/index.css"
echo "  - src/App.js"
echo ""
echo "Scripts (copy to scripts/):"
echo "  - attack_simulator.sh"
echo "  - demo.sh"
echo ""
echo "Root:"
echo "  - docker-compose.yml"
echo ""

read -p "Have you copied all files? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Please copy the files and run this script again"
    exit 0
fi

# Make scripts executable
chmod +x scripts/*.sh 2>/dev/null || true

print_success "Application files ready"

# Pull Docker images
print_step 6 10 "Pulling Docker images (this may take a while)..."

print_info "Pulling base images..."
docker pull postgres:15-alpine
docker pull redis:7-alpine
docker pull bkimminich/juice-shop:latest

print_info "Pulling Wazuh images..."
docker pull wazuh/wazuh-manager:4.7.0
docker pull wazuh/wazuh-indexer:4.7.0
docker pull wazuh/wazuh-dashboard:4.7.0

print_success "Docker images downloaded"

# Build custom images
print_step 7 10 "Building custom images..."

if [ -f "fastapi/Dockerfile" ]; then
    docker-compose build fastapi
    print_success "FastAPI image built"
else
    print_info "FastAPI Dockerfile not found - skipping"
fi

if [ -f "frontend/Dockerfile" ]; then
    docker-compose build frontend
    print_success "Frontend image built"
else
    print_info "Frontend Dockerfile not found - skipping"
fi

# Start services
print_step 8 10 "Starting services..."

print_info "Starting PostgreSQL and Redis..."
docker-compose up -d postgres redis
sleep 5

print_info "Starting Juice Shop..."
docker-compose up -d juiceshop
sleep 3

print_info "Starting Wazuh (this will take 2-3 minutes)..."
docker-compose up -d wazuh wazuh-indexer wazuh-dashboard
print_info "Waiting for Wazuh to initialize..."
echo -e "${YELLOW}This may take 2-3 minutes. Please be patient...${NC}"

# Wait for

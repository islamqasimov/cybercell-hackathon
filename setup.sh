#!/bin/bash
# setup.sh - Initialize the Security AI system

set -e

echo "==================================="
echo "Security AI Setup Script"
echo "==================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check prerequisites
echo ""
echo "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi
print_status "Docker is installed"

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi
print_status "Docker Compose is installed"

# Create project structure
echo ""
echo "Creating project structure..."

mkdir -p fastapi
mkdir -p frontend/src
mkdir -p models
mkdir -p logs/juiceshop
mkdir -p scripts
mkdir -p data

print_status "Project directories created"

# Create FastAPI requirements file
cat > fastapi/requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
httpx==0.25.2
pydantic==2.5.0
pydantic-settings==2.1.0
python-multipart==0.0.6
pandas==2.1.3
numpy==1.26.2
scikit-learn==1.3.2
joblib==1.3.2
redis==5.0.1
websockets==12.0
jinja2==3.1.2
python-dotenv==1.0.0
EOF

print_status "Requirements file created"

# Create .env file
cat > .env << 'EOF'
# Database
POSTGRES_DB=security_ai
POSTGRES_USER=admin
POSTGRES_PASSWORD=hackathon2024

# Wazuh
WAZUH_URL=https://wazuh:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-

# Nessus (Optional - use mock data if not available)
NESSUS_URL=https://nessus:8834
NESSUS_ACCESS_KEY=your_key_here
NESSUS_SECRET_KEY=your_secret_here

# Application
DEBUG=true
LOG_LEVEL=INFO
EOF

print_status ".env file created"

# Create frontend Dockerfile
cat > frontend/Dockerfile << 'EOF'
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build app
RUN npm run build

# Install serve to run the app
RUN npm install -g serve

EXPOSE 3000

CMD ["serve", "-s", "build", "-l", "3000"]
EOF

# Create basic frontend package.json
cat > frontend/package.json << 'EOF'
{
  "name": "security-ai-dashboard",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    "recharts": "^2.10.0",
    "axios": "^1.6.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
EOF

print_status "Frontend configuration created"

# Make scripts executable
chmod +x scripts/*.sh 2>/dev/null || true

print_status "Scripts made executable"

# Create a simple README
cat > README.md << 'EOF'
# Security AI System

AI-powered cybersecurity detection and response system combining Wazuh, Nessus, and custom ML models.

## Quick Start

1. **Start the system:**
   ```bash
   docker-compose up -d
   ```

2. **Check service health:**
   ```bash
   docker-compose ps
   ```

3. **Access services:**
   - Juice Shop: http://localhost:3000
   - Wazuh Dashboard: https://localhost:443 (admin/SecretPassword)
   - FastAPI: http://localhost:8000
   - Frontend Dashboard: http://localhost:3001

4. **Train anomaly model:**
   ```bash
   docker-compose exec fastapi python anomaly_detector.py
   ```

5. **Run attack simulation:**
   ```bash
   ./scripts/attack_simulator.sh sqli
   ```

## Available Attack Scenarios

- `sqli` - SQL Injection
- `brute` - Brute Force Login
- `xss` - Cross-Site Scripting
- `scan` - Port/Directory Scanning
- `dos` - Denial of Service
- `combo` - Multi-stage Attack
- `normal` - Normal Traffic (for baseline)

## API Endpoints

- `GET /health` - Health check
- `GET /alerts` - List recent alerts
- `GET /anomalies` - List anomaly detections
- `GET /risk?host=juiceshop` - Get risk score for host
- `POST /response/action` - Execute automated response
- `GET /soc/report/{alert_id}` - Generate SOC report

## Architecture

```
Attack Traffic → Juice Shop → Wazuh → FastAPI (AI) → Dashboard
                                ↓
                            Nessus Scans
```

## Components

1. **Anomaly Detector**: Isolation Forest model for behavioral analysis
2. **SOC Analyst AI**: Automated incident report generation
3. **Risk Correlator**: Composite scoring from multiple sources
4. **Automated Response**: Playbook execution system

## Metrics

- **MTTD**: Mean Time To Detect
- **MTTR**: Mean Time To Respond
- **Precision/Recall**: Detection accuracy
- **Risk Prediction**: Proactive threat scoring

## Development

- FastAPI logs: `docker-compose logs -f fastapi`
- Database: `docker-compose exec postgres psql -U admin -d security_ai`
- Wazuh logs: `docker-compose logs -f wazuh`

## Troubleshooting

- **Wazuh not starting**: Increase Docker memory to 4GB+
- **FastAPI connection errors**: Wait 2-3 minutes for Wazuh to fully start
- **No alerts**: Run attack scripts and check Wazuh dashboard

## License

MIT
EOF

print_status "README created"

echo ""
echo "==================================="
print_status "Setup completed successfully!"
echo "==================================="
echo ""
echo "Next steps:"
echo "  1. Review and customize .env file"
echo "  2. Copy the provided code files to their directories:"
echo "     - main.py → fastapi/"
echo "     - anomaly_detector.py → fastapi/"
echo "     - soc_analyst_ai.py → fastapi/"
echo "     - Dockerfile → fastapi/"
echo "  3. Run: docker-compose up -d"
echo "  4. Train model: docker-compose exec fastapi python anomaly_detector.py"
echo "  5. Run attacks: ./scripts/attack_simulator.sh sqli"
echo ""
print_warning "Note: Wazuh takes 2-3 minutes to fully initialize"
echo ""

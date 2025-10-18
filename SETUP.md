# AI Security Platform - Complete Setup Guide

## 🎯 What This System Does

Two AI Agents working together:
- **AI Agent #1 (SOC Analyst)**: Analyzes alerts, recommends detection rules, learns from attacks
- **AI Agent #2 (Security Auditor)**: Scans code, finds vulnerabilities, validates with real attacks

## 📋 Prerequisites

- Docker & Docker Compose
- 8GB RAM minimum
- Python 3.11+ (for local testing)
- Node.js 18+ (for frontend)

## 🚀 Quick Start (5 Minutes)

### 1. Clone and Setup

```bash
# Clone your repository
cd ai-security-platform

# Make scripts executable
chmod +x startup.sh demo.sh frontend-setup.sh

# Create necessary files in backend/
cd backend
touch ai_engine.py init_system.py

# Copy the ai_engine.py content from artifacts
# Copy the init_system.py content from artifacts
# Copy the updated soc_analyst.py from artifacts
# Copy the updated security_auditor.py from artifacts
# Copy the updated main.py from artifacts

cd ..
```

### 2. Place All Files

Create this structure:
```
ai-security-platform/
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py              (updated)
│   ├── ai_engine.py         (NEW - from artifacts)
│   ├── soc_analyst.py       (updated)
│   ├── security_auditor.py  (updated)
│   ├── init_system.py       (NEW - from artifacts)
│   └── log_collector.py
├── frontend/
│   ├── package.json
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── index.js
│       ├── index.css
│       └── App.js
├── docker-compose.yml
├── startup.sh              (NEW - from artifacts)
├── demo.sh                 (NEW - from artifacts)
└── .env
```

### 3. Start the System

```bash
./startup.sh
```

This will:
- Build all Docker containers
- Start PostgreSQL, Redis, Juice Shop, FastAPI, Frontend
- Initialize database with default rules
- Create sample alerts
- Generate demo data

### 4. Access the Dashboard

Open: **http://localhost:3001**

## 🎬 Running the Demo

```bash
./demo.sh
```

This automated demo will:
1. Show current system state
2. Run security audit (AI Agent #2)
3. Simulate attacks
4. Trigger AI analysis (AI Agent #1)
5. Display rule recommendations
6. Apply recommendations
7. Show final statistics

## 🔧 Manual Testing

### Test AI Security Auditor

```bash
# Run security scan
curl -X POST http://localhost:8000/auditor/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "juiceshop", "validate_attacks": true}'

# Wait 10 seconds, then get results
curl http://localhost:8000/auditor/results | python3 -m json.tool
```

### Test AI SOC Analyst

```bash
# Create a test alert
curl -X POST http://localhost:8000/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "SQLI-001",
    "rule_description": "SQL Injection Detected",
    "host": "juiceshop",
    "severity": 12,
    "raw_data": {
      "log": "POST /login email=admin'\''-- password=test"
    }
  }'

# Trigger AI analysis
curl -X POST http://localhost:8000/soc/analyze/1

# Wait 5 seconds, then get recommendations
curl http://localhost:8000/soc/rule-recommendations | python3 -m json.tool
```

### Apply Rule Recommendation

```bash
# Apply first recommendation
curl -X POST http://localhost:8000/soc/apply-recommendation/1

# Check updated rules
curl http://localhost:8000/rules | python3 -m json.tool
```

## 🤖 AI Configuration

### Option 1: Use Ollama (Local, Free)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama2

# Update .env
USE_OLLAMA=true
OLLAMA_URL=http://host.docker.internal:11434
```

### Option 2: Use OpenAI (Cloud)

```bash
# Update .env
USE_OLLAMA=false
OPENAI_API_KEY=sk-your-key-here
```

### Option 3: Demo Mode (No AI)

System works without AI using fallback pattern-based analysis.

## 📊 Dashboard Features

### Overview Tab
- Real-time statistics
- Recent alerts
- Rule recommendations preview

### AI SOC Analyst Tab
- All rule recommendations
- Action types: CREATE, MODIFY, DISABLE
- Confidence scores
- Apply recommendations with one click

### AI Security Auditor Tab
- Vulnerability scan results
- Attack validation status
- CVSS scores
- Remediation code

### Live Alerts Tab
- All security alerts
- Analyze individual alerts with AI
- Filter by severity

## 🛠️ Troubleshooting

### Frontend won't start

```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### Backend errors

```bash
# Check logs
docker-compose logs -f fastapi

# Restart backend
docker-compose restart fastapi

# Rebuild
docker-compose up -d --build fastapi
```

### Database issues

```bash
# Reset database
docker-compose down -v
docker-compose up -d postgres
sleep 10
docker-compose up -d fastapi
```

### Can't connect to Ollama

```bash
# Check if Ollama is running
ollama list

# Update .env with correct URL
# For Docker on Mac/Windows:
OLLAMA_URL=http://host.docker.internal:11434

# For Docker on Linux:
OLLAMA_URL=http://172.17.0.1:11434
```

## 📝 Environment Variables

```bash
# .env file
DATABASE_URL=postgresql://admin:hackathon2024@postgres:5432/security_ai
USE_OLLAMA=true
OLLAMA_URL=http://host.docker.internal:11434
OPENAI_API_KEY=
JUICESHOP_URL=http://juiceshop:3000
JUICESHOP_SOURCE=/app/juiceshop-source
```

## 🎯 Demo Script for Presentation

**Minute 1: Introduction**
- "We built an AI Security Platform with two intelligent agents"
- Show dashboard with statistics

**Minute 2: AI Security Auditor**
- Click "Run Security Audit"
- Show: Code analysis → Vulnerabilities found → Attack validation
- Result: "5 vulnerabilities found, 3 validated with real attacks"

**Minute 3: AI SOC Analyst**
- Show: Attacks triggered alerts
- AI analyzed patterns
- Generated rule recommendations
- Click "Apply Recommendation"
- Show: New rule created automatically

**Finale:**
"Both agents work together: Auditor finds and proves vulnerabilities, SOC Analyst learns from attacks and creates rules to prevent them. The system continuously improves itself!"

## 📈 System Architecture

```
Juice Shop (Target)
    ↓
    ├─→ Logs → SIEM → AI SOC Analyst → Rule Recommendations
    └─→ Code → AI Security Auditor → Vulnerabilities + Attack Validation
```

## 🔍 Key Endpoints

- `GET /health` - Health check
- `GET /stats` - System statistics
- `GET /alerts` - List alerts
- `POST /alerts` - Create alert
- `GET /soc/rule-recommendations` - AI recommendations
- `POST /soc/apply-recommendation/:id` - Apply rule
- `POST /auditor/scan` - Run security audit
- `GET /auditor/results` - Get scan results
- `GET /docs` - Interactive API docs

## 🎉 Success Criteria

Your system is working correctly if:
1. ✅ Dashboard loads at http://localhost:3001
2. ✅ Statistics show non-zero values
3. ✅ "Run Security Audit" finds vulnerabilities
4. ✅ Alerts appear in "Live Alerts" tab
5. ✅ Rule recommendations appear in "AI SOC Analyst" tab
6. ✅ You can apply recommendations successfully

## 💡 Tips for Hackathon

1. **Run the demo script first** to populate data
2. **Use the dashboard** for presentation (looks professional)
3. **Mention the innovations**:
   - Self-improving rule engine
   - Attack-validated auditing
   - Unified AI intelligence
4. **Show the feedback loop**: Auditor → Attacks → Analyst → Rules
5. **Emphasize**: No Wazuh, built from scratch in 10 hours

## 📞 Support

If you get stuck:
1. Check logs: `docker-compose logs -f`
2. Reset everything: `docker-compose down -v && ./startup.sh`
3. Verify all files are in place
4. Make sure Docker has enough resources (8GB RAM)

## 🚀 Good Luck with Your Hackathon!

Remember: The innovation is in the AI-driven rule recommendations and attack validation, not just running security scans!

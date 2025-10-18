#!/bin/bash
# setup-frontend-complete.sh - Complete frontend setup for AI Security Platform

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║      AI Security Platform - Frontend Setup               ║
║      Two AI Agents: SOC Analyst + Security Auditor       ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Create directory structure
echo -e "\n${YELLOW}Creating directory structure...${NC}"
mkdir -p frontend/public
mkdir -p frontend/src

# Create package.json
echo -e "${YELLOW}Creating package.json...${NC}"
cat > frontend/package.json << 'EOF'
{
  "name": "ai-security-platform",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    "lucide-react": "^0.263.1"
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
  },
  "proxy": "http://localhost:8000"
}
EOF

# Create public/index.html
echo -e "${YELLOW}Creating index.html...${NC}"
cat > frontend/public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <meta name="description" content="AI Security Platform - SOC Analyst + Security Auditor" />
    <title>AI Security Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
          'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
          sans-serif;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
        background-color: #111827;
      }
      
      ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
      }
      
      ::-webkit-scrollbar-track {
        background: #1f2937;
      }
      
      ::-webkit-scrollbar-thumb {
        background: #4b5563;
        border-radius: 4px;
      }
      
      ::-webkit-scrollbar-thumb:hover {
        background: #6b7280;
      }
      
      @keyframes pulse {
        0%, 100% {
          opacity: 1;
        }
        50% {
          opacity: 0.5;
        }
      }
      
      @keyframes spin {
        to {
          transform: rotate(360deg);
        }
      }
      
      .animate-pulse {
        animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
      }
      
      .animate-spin {
        animation: spin 1s linear infinite;
      }
    </style>
  </head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
</html>
EOF

# Create src/index.js
echo -e "${YELLOW}Creating index.js...${NC}"
cat > frontend/src/index.js << 'EOF'
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOF

# Create src/index.css
echo -e "${YELLOW}Creating index.css...${NC}"
cat > frontend/src/index.css << 'EOF'
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background-color: #111827;
}

code {
  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',
    monospace;
}
EOF

# Create .gitignore
echo -e "${YELLOW}Creating .gitignore...${NC}"
cat > frontend/.gitignore << 'EOF'
# Dependencies
node_modules
/.pnp
.pnp.js

# Testing
/coverage

# Production
/build

# Misc
.DS_Store
.env.local
.env.development.local
.env.test.local
.env.production.local

npm-debug.log*
yarn-debug.log*
yarn-error.log*
EOF

# Create README
echo -e "${YELLOW}Creating README...${NC}"
cat > frontend/README.md << 'EOF'
# AI Security Platform - Frontend

## Features

- **AI SOC Analyst Tab**: Shows rule recommendations from AI
- **AI Security Auditor Tab**: Displays code analysis and attack validation
- **Live Alerts Tab**: Real-time security alerts
- **Overview Dashboard**: Summary of all activities

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm start

# Access at http://localhost:3000
```

## API Endpoints Expected

The frontend expects these backend endpoints:

- `GET /alerts` - List of security alerts
- `GET /soc/rule-recommendations` - AI-generated rule recommendations
- `POST /soc/apply-recommendation/:id` - Apply a rule recommendation
- `POST /soc/analyze/:alertId` - Analyze an alert with AI
- `POST /auditor/scan` - Run security audit with attack validation
- `GET /stats` - System statistics

## Environment Variables

Create `.env` file:
```
REACT_APP_API_URL=http://localhost:8000
```
EOF

echo -e "\n${GREEN}✓ Frontend structure created!${NC}\n"

# Instructions
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}Next Steps${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}1. Copy the Main Dashboard Component${NC}"
echo "   Copy the 'Main Dashboard - Two AI Agents System' artifact"
echo "   into frontend/src/App.js"
echo ""

echo -e "${YELLOW}2. Install Dependencies${NC}"
echo "   cd frontend"
echo "   npm install"
echo ""

echo -e "${YELLOW}3. Start Development Server${NC}"
echo "   npm start"
echo ""

echo -e "${YELLOW}4. Access Dashboard${NC}"
echo "   Open http://localhost:3000"
echo ""

echo -e "${GREEN}Frontend setup complete! 🎉${NC}\n"

# Verify structure
echo -e "${YELLOW}Verifying structure...${NC}"
echo ""
tree -L 2 frontend/ 2>/dev/null || find frontend -type f -o -type d | sort

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}Ready to build!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"

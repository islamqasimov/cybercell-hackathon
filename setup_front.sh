#!/bin/bash
# setup-frontend.sh - Quick setup for React frontend

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Setting up Security AI Frontend...${NC}\n"

# Create frontend directory structure
echo "Creating directory structure..."
mkdir -p frontend/public
mkdir -p frontend/src

# Create package.json
echo "Creating package.json..."
cat > frontend/package.json << 'EOF'
{
  "name": "security-ai-dashboard",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    "lucide-react": "^0.263.1",
    "web-vitals": "^2.1.4"
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
  "proxy": "http://fastapi:8000"
}
EOF

# Create public/index.html
echo "Creating index.html..."
cat > frontend/public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <meta name="description" content="Security AI Dashboard" />
    <title>Security AI Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
</html>
EOF

# Create src/index.js
echo "Creating index.js..."
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
echo "Creating index.css..."
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

* {
  box-sizing: border-box;
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
EOF

# Create src/App.js placeholder
echo "Creating App.js..."
cat > frontend/src/App.js << 'EOF'
// Copy the React component from the frontend_dashboard artifact here
// Or use the simple version below for testing

import React, { useState, useEffect } from 'react';

function App() {
  const [status, setStatus] = useState('connecting...');
  
  useEffect(() => {
    fetch('http://localhost:8000/health')
      .then(res => res.json())
      .then(() => setStatus('connected'))
      .catch(() => setStatus('disconnected'));
  }, []);
  
  return (
    <div style={{ 
      padding: '2rem', 
      color: 'white', 
      minHeight: '100vh',
      backgroundColor: '#111827'
    }}>
      <h1>Security AI Dashboard</h1>
      <p>Status: {status}</p>
      <p>Copy the full dashboard code from the frontend_dashboard artifact to src/App.js</p>
    </div>
  );
}

export default App;
EOF

# Create .gitignore
echo "Creating .gitignore..."
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

echo -e "\n${GREEN}✓ Frontend structure created!${NC}\n"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Copy the full React component from 'frontend_dashboard' artifact"
echo "2. Paste it into frontend/src/App.js (replacing the placeholder)"
echo "3. Run: docker-compose up -d frontend"
echo "4. Wait for npm install to complete"
echo "5. Access dashboard at: http://localhost:3001"
echo ""
echo -e "${YELLOW}Or run locally:${NC}"
echo "cd frontend && npm install && npm start"

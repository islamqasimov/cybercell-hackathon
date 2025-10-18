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

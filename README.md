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

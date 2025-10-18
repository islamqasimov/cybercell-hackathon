from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import httpx
import asyncio
import os
import json
import hashlib
from contextlib import asynccontextmanager

# Environment variables
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:hackathon2024@postgres:5432/security_ai")
WAZUH_URL = os.getenv("WAZUH_URL", "https://wazuh:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "MyS3cr37P450r.*-")
NESSUS_URL = os.getenv("NESSUS_URL", "https://nessus:8834")

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    host = Column(String, index=True)
    rule_id = Column(String)
    rule_description = Column(String)
    severity = Column(Integer)
    raw_data = Column(JSON)
    anomaly_score = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    status = Column(String, default="new")

class Anomaly(Base):
    __tablename__ = "anomalies"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    host = Column(String, index=True)
    anomaly_score = Column(Float)
    features = Column(JSON)
    is_anomaly = Column(Integer)

class Response(Base):
    __tablename__ = "responses"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String)
    target = Column(String)
    status = Column(String)
    details = Column(JSON)

class SOCReport(Base):
    __tablename__ = "soc_reports"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    title = Column(String)
    severity = Column(String)
    summary = Column(String)
    evidence = Column(JSON)
    immediate_actions = Column(JSON)
    next_steps = Column(JSON)
    confidence = Column(Float)

Base.metadata.create_all(bind=engine)

# Pydantic schemas
class AlertResponse(BaseModel):
    id: int
    alert_id: str
    timestamp: datetime
    host: str
    rule_description: str
    severity: int
    anomaly_score: float
    risk_score: float
    status: str

class AnomalyResponse(BaseModel):
    host: str
    timestamp: datetime
    anomaly_score: float
    is_anomaly: bool
    top_features: Dict[str, float]

class ActionRequest(BaseModel):
    action: str
    target: str
    alert_id: str
    params: Optional[Dict[str, Any]] = {}

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Global state
active_connections: List[WebSocket] = []
wazuh_token_cache = {"token": None, "expires": datetime.utcnow()}

# Wazuh API functions
async def get_wazuh_token():
    global wazuh_token_cache
    if wazuh_token_cache["expires"] > datetime.utcnow():
        return wazuh_token_cache["token"]
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.post(
                f"{WAZUH_URL}/security/user/authenticate",
                auth=(WAZUH_USER, WAZUH_PASSWORD),
                timeout=10.0
            )
            if response.status_code == 200:
                token = response.json()["data"]["token"]
                wazuh_token_cache = {
                    "token": token,
                    "expires": datetime.utcnow() + timedelta(minutes=15)
                }
                return token
        except Exception as e:
            print(f"Error getting Wazuh token: {e}")
            return None

async def fetch_wazuh_alerts(token: str, limit: int = 50):
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.get(
                f"{WAZUH_URL}/security/alerts",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "sort": "-timestamp"},
                timeout=10.0
            )
            if response.status_code == 200:
                return response.json().get("data", {}).get("affected_items", [])
        except Exception as e:
            print(f"Error fetching alerts: {e}")
    return []

# Background task for polling
async def poll_wazuh_alerts(db: Session):
    while True:
        try:
            token = await get_wazuh_token()
            if token:
                alerts = await fetch_wazuh_alerts(token)
                for alert_data in alerts:
                    alert_id = alert_data.get("id", hashlib.md5(json.dumps(alert_data).encode()).hexdigest())
                    
                    existing = db.query(Alert).filter(Alert.alert_id == alert_id).first()
                    if not existing:
                        host = alert_data.get("agent", {}).get("name", "unknown")
                        rule = alert_data.get("rule", {})
                        
                        new_alert = Alert(
                            alert_id=alert_id,
                            host=host,
                            rule_id=rule.get("id", ""),
                            rule_description=rule.get("description", ""),
                            severity=rule.get("level", 0),
                            raw_data=alert_data,
                            timestamp=datetime.utcnow()
                        )
                        db.add(new_alert)
                        db.commit()
                        
                        # Broadcast to websockets
                        await broadcast_update({
                            "type": "new_alert",
                            "data": {
                                "id": new_alert.id,
                                "alert_id": alert_id,
                                "host": host,
                                "description": new_alert.rule_description
                            }
                        })
        except Exception as e:
            print(f"Polling error: {e}")
        
        await asyncio.sleep(5)

async def broadcast_update(message: dict):
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except:
            active_connections.remove(connection)

# Lifespan context
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    db = SessionLocal()
    asyncio.create_task(poll_wazuh_alerts(db))
    yield
    # Shutdown
    db.close()

# FastAPI app
app = FastAPI(title="Security AI Orchestrator", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    limit: int = 50,
    host: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Alert).order_by(Alert.timestamp.desc())
    if host:
        query = query.filter(Alert.host == host)
    alerts = query.limit(limit).all()
    return alerts

@app.post("/alerts/webhook")
async def webhook_receiver(data: dict, db: Session = Depends(get_db)):
    """Receive alerts pushed from Wazuh"""
    alert_id = data.get("id", hashlib.md5(json.dumps(data).encode()).hexdigest())
    
    existing = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not existing:
        host = data.get("agent", {}).get("name", "unknown")
        rule = data.get("rule", {})
        
        new_alert = Alert(
            alert_id=alert_id,
            host=host,
            rule_id=rule.get("id", ""),
            rule_description=rule.get("description", ""),
            severity=rule.get("level", 0),
            raw_data=data
        )
        db.add(new_alert)
        db.commit()
        
        await broadcast_update({
            "type": "new_alert",
            "data": {"id": new_alert.id, "host": host}
        })
    
    return {"status": "received"}

@app.get("/anomalies")
async def get_anomalies(
    host: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(Anomaly).order_by(Anomaly.timestamp.desc())
    if host:
        query = query.filter(Anomaly.host == host)
    anomalies = query.limit(limit).all()
    
    result = []
    for a in anomalies:
        result.append({
            "host": a.host,
            "timestamp": a.timestamp,
            "anomaly_score": a.anomaly_score,
            "is_anomaly": bool(a.is_anomaly),
            "top_features": a.features or {}
        })
    return result

@app.get("/nessus/scans")
async def get_nessus_scans():
    """Mock Nessus scan results"""
    return {
        "scans": [
            {
                "id": 1,
                "name": "Juice Shop Scan",
                "targets": "juiceshop",
                "status": "completed",
                "vulnerabilities": {
                    "critical": 2,
                    "high": 5,
                    "medium": 12,
                    "low": 8
                }
            }
        ]
    }

@app.get("/risk")
async def get_risk_score(
    host: str,
    db: Session = Depends(get_db)
):
    """Calculate composite risk score"""
    recent_alerts = db.query(Alert).filter(
        Alert.host == host,
        Alert.timestamp >= datetime.utcnow() - timedelta(hours=1)
    ).all()
    
    recent_anomalies = db.query(Anomaly).filter(
        Anomaly.host == host,
        Anomaly.timestamp >= datetime.utcnow() - timedelta(hours=1)
    ).all()
    
    # Composite risk calculation
    alert_score = sum(a.severity for a in recent_alerts) / 10.0 if recent_alerts else 0
    anomaly_score = max([a.anomaly_score for a in recent_anomalies], default=0)
    vuln_score = 7.5  # Mock Nessus CVSS
    
    risk = (0.35 * min(alert_score, 10) + 
            0.30 * min(anomaly_score * 10, 10) + 
            0.25 * vuln_score + 
            0.10 * len(recent_alerts))
    
    severity = "low" if risk < 3 else "medium" if risk < 6 else "high"
    
    return {
        "host": host,
        "risk_score": round(risk, 2),
        "severity": severity,
        "components": {
            "alerts": alert_score,
            "anomaly": anomaly_score,
            "vulnerabilities": vuln_score
        },
        "recent_alerts": len(recent_alerts),
        "recent_anomalies": len(recent_anomalies)
    }

@app.post("/response/action")
async def execute_action(
    action: ActionRequest,
    db: Session = Depends(get_db)
):
    """Execute automated response action"""
    response = Response(
        alert_id=action.alert_id,
        action=action.action,
        target=action.target,
        status="executed",
        details=action.params
    )
    db.add(response)
    db.commit()
    
    # Simulate Wazuh active response
    if action.action == "block_ip":
        print(f"[SIMULATED] Blocking IP: {action.target}")
    elif action.action == "isolate_host":
        print(f"[SIMULATED] Isolating host: {action.target}")
    
    await broadcast_update({
        "type": "action_executed",
        "data": {
            "action": action.action,
            "target": action.target
        }
    })
    
    return {"status": "success", "action_id": response.id}

@app.get("/soc/report/{alert_id}")
async def get_soc_report(alert_id: str, db: Session = Depends(get_db)):
    """Generate or retrieve SOC analyst report"""
    existing_report = db.query(SOCReport).filter(SOCReport.alert_id == alert_id).first()
    if existing_report:
        return {
            "alert_id": alert_id,
            "title": existing_report.title,
            "severity": existing_report.severity,
            "summary": existing_report.summary,
            "evidence": existing_report.evidence,
            "immediate_actions": existing_report.immediate_actions,
            "next_steps": existing_report.next_steps,
            "confidence": existing_report.confidence
        }
    
    # Generate new report
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    report = SOCReport(
        alert_id=alert_id,
        title=f"Security Incident: {alert.rule_description}",
        severity="high" if alert.severity >= 10 else "medium" if alert.severity >= 5 else "low",
        summary=f"Detected suspicious activity on {alert.host} at {alert.timestamp}. Rule {alert.rule_id} triggered.",
        evidence={
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "anomaly_score": alert.anomaly_score
        },
        immediate_actions=["Review logs", "Verify activity", "Block if malicious"],
        next_steps=["Forensic analysis", "Patch vulnerabilities", "Update rules"],
        confidence=0.85
    )
    db.add(report)
    db.commit()
    
    return {
        "alert_id": alert_id,
        "title": report.title,
        "severity": report.severity,
        "summary": report.summary,
        "evidence": report.evidence,
        "immediate_actions": report.immediate_actions,
        "next_steps": report.next_steps,
        "confidence": report.confidence
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        active_connections.remove(websocket)

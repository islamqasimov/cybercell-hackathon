from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional, Dict
import os
import asyncio

# Config
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:hackathon2024@postgres:5432/security_ai")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Models
class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    rule_id = Column(String)
    rule_description = Column(String)
    host = Column(String)
    severity = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
    raw_data = Column(JSON)

class RuleRecommendation(Base):
    __tablename__ = "rule_recommendations"
    id = Column(Integer, primary_key=True)
    action = Column(String)  # CREATE, MODIFY, DISABLE
    rule_id = Column(String)
    reason = Column(Text)
    current_pattern = Column(String, nullable=True)
    suggested_pattern = Column(String, nullable=True)
    severity = Column(String)
    confidence = Column(Integer)
    evidence_count = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
    applied = Column(Boolean, default=False)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    vuln_type = Column(String)
    file_path = Column(String)
    line_number = Column(Integer)
    code_snippet = Column(Text)
    severity = Column(String)
    cvss_score = Column(Float)
    cwe_id = Column(String)
    validated = Column(Boolean, default=False)
    attack_payload = Column(String, nullable=True)
    remediation = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(Integer, primary_key=True)
    rule_id = Column(String, unique=True)
    name = Column(String)
    pattern = Column(String)
    severity = Column(String)
    enabled = Column(Boolean, default=True)
    auto_generated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class IncidentReport(Base):
    __tablename__ = "incident_reports"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer)
    severity = Column(String)
    attack_type = Column(String)
    attack_pattern = Column(String)
    is_false_positive = Column(Boolean, default=False)
    is_true_positive = Column(Boolean, default=True)
    threat_level = Column(String)
    source_ip = Column(String)
    affected_host = Column(String)
    attack_success = Column(String)
    evidence = Column(Text)
    analysis_summary = Column(Text)
    recommended_actions = Column(JSON)
    full_report = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

# FastAPI app
app = FastAPI(title="AI Security Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic schemas
class AlertCreate(BaseModel):
    rule_id: str
    rule_description: str
    host: str
    severity: int
    raw_data: Optional[Dict] = {}

class ScanRequest(BaseModel):
    target: str
    validate_attacks: bool = True

class RuleCreate(BaseModel):
    rule_id: str
    name: str
    pattern: str
    severity: str

# Helper functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Endpoints
@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.get("/stats")
async def get_stats():
    db = SessionLocal()
    try:
        total_alerts = db.query(Alert).count()
        critical_alerts = db.query(Alert).filter(Alert.severity >= 10).count()
        rules_created = db.query(RuleRecommendation).filter(
            RuleRecommendation.applied == True,
            RuleRecommendation.action == "CREATE"
        ).count()
        vulns_found = db.query(Vulnerability).count()
        attacks_validated = db.query(Vulnerability).filter(Vulnerability.validated == True).count()
        
        return {
            "totalAlerts": total_alerts,
            "criticalAlerts": critical_alerts,
            "rulesCreated": rules_created,
            "vulnerabilitiesFound": vulns_found,
            "attacksValidated": attacks_validated
        }
    finally:
        db.close()

@app.get("/alerts")
async def get_alerts(limit: int = 50):
    db = SessionLocal()
    try:
        alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": a.id,
                "rule_id": a.rule_id,
                "rule_description": a.rule_description,
                "host": a.host,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat(),
                "raw_data": a.raw_data
            }
            for a in alerts
        ]
    finally:
        db.close()

@app.post("/alerts")
async def create_alert(alert: AlertCreate, background_tasks: BackgroundTasks):
    db = SessionLocal()
    try:
        new_alert = Alert(**alert.dict())
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        
        # Trigger AI analysis in background
        background_tasks.add_task(analyze_alert_for_rules, new_alert.id)
        
        return {"id": new_alert.id, "status": "created"}
    finally:
        db.close()

@app.get("/rules")
async def get_rules():
    db = SessionLocal()
    try:
        rules = db.query(DetectionRule).order_by(DetectionRule.created_at.desc()).all()
        return [
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "name": r.name,
                "pattern": r.pattern,
                "severity": r.severity,
                "enabled": r.enabled,
                "auto_generated": r.auto_generated,
                "created_at": r.created_at.isoformat()
            }
            for r in rules
        ]
    finally:
        db.close()

@app.post("/rules")
async def create_rule(rule: RuleCreate):
    db = SessionLocal()
    try:
        new_rule = DetectionRule(**rule.dict())
        db.add(new_rule)
        db.commit()
        return {"status": "created", "rule_id": new_rule.rule_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(400, f"Error creating rule: {str(e)}")
    finally:
        db.close()

@app.get("/soc/incidents")
async def get_incident_reports(limit: int = 20):
    db = SessionLocal()
    try:
        reports = db.query(IncidentReport).order_by(
            IncidentReport.timestamp.desc()
        ).limit(limit).all()
        
        return [
            {
                "id": r.id,
                "alert_id": r.alert_id,
                "severity": r.severity,
                "attack_type": r.attack_type,
                "attack_pattern": r.attack_pattern,
                "is_false_positive": r.is_false_positive,
                "is_true_positive": r.is_true_positive,
                "threat_level": r.threat_level,
                "source_ip": r.source_ip,
                "affected_host": r.affected_host,
                "attack_success": r.attack_success,
                "analysis_summary": r.analysis_summary,
                "recommended_actions": r.recommended_actions,
                "full_report": r.full_report,
                "timestamp": r.timestamp.isoformat()
            }
            for r in reports
        ]
    finally:
        db.close()

@app.get("/soc/rule-recommendations")
async def get_rule_recommendations():
    db = SessionLocal()
    try:
        recs = db.query(RuleRecommendation).filter(
            RuleRecommendation.applied == False
        ).order_by(RuleRecommendation.confidence.desc()).limit(20).all()
        
        return [
            {
                "id": r.id,
                "action": r.action,
                "rule_id": r.rule_id,
                "reason": r.reason,
                "current_pattern": r.current_pattern,
                "suggested_pattern": r.suggested_pattern,
                "severity": r.severity,
                "confidence": r.confidence,
                "evidence_count": r.evidence_count,
                "timestamp": r.timestamp.isoformat()
            }
            for r in recs
        ]
    finally:
        db.close()

@app.post("/soc/apply-recommendation/{rec_id}")
async def apply_recommendation(rec_id: int):
    db = SessionLocal()
    try:
        rec = db.query(RuleRecommendation).get(rec_id)
        if not rec:
            raise HTTPException(404, "Recommendation not found")
        
        # Create or modify rule
        if rec.action == "CREATE":
            # Check if rule already exists
            existing = db.query(DetectionRule).filter(
                DetectionRule.rule_id == rec.rule_id
            ).first()
            
            if not existing:
                rule = DetectionRule(
                    rule_id=rec.rule_id,
                    name=rec.rule_id,
                    pattern=rec.suggested_pattern,
                    severity=rec.severity,
                    auto_generated=True
                )
                db.add(rule)
        
        elif rec.action == "MODIFY":
            rule = db.query(DetectionRule).filter(
                DetectionRule.rule_id == rec.rule_id
            ).first()
            if rule:
                rule.pattern = rec.suggested_pattern
        
        elif rec.action == "DISABLE":
            rule = db.query(DetectionRule).filter(
                DetectionRule.rule_id == rec.rule_id
            ).first()
            if rule:
                rule.enabled = False
        
        rec.applied = True
        db.commit()
        return {"status": "success", "action": rec.action, "rule_id": rec.rule_id}
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(400, f"Error applying recommendation: {str(e)}")
    finally:
        db.close()

@app.post("/soc/analyze/{alert_id}")
async def analyze_alert(alert_id: int, background_tasks: BackgroundTasks):
    # Trigger background analysis
    background_tasks.add_task(analyze_alert_for_rules, alert_id)
    return {"status": "analyzing", "alert_id": alert_id}

@app.post("/auditor/scan")
async def run_security_audit(request: ScanRequest, background_tasks: BackgroundTasks):
    # Start scan immediately in background
    background_tasks.add_task(perform_security_scan, request.target, request.validate_attacks)
    return {"status": "started", "target": request.target, "message": "Scan started, check /auditor/results in 10-15 seconds"}

@app.get("/auditor/results")
async def get_audit_results():
    db = SessionLocal()
    try:
        vulns = db.query(Vulnerability).order_by(Vulnerability.timestamp.desc()).limit(50).all()
        
        total_vulns = len(vulns)
        cvss_scores = [v.cvss_score for v in vulns if v.cvss_score]
        cvss_avg = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        
        return {
            "files_analyzed": 247,  # Mock count
            "cvss_avg": cvss_avg,
            "total_vulnerabilities": total_vulns,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.vuln_type,
                    "file": v.file_path,
                    "line": v.line_number,
                    "code": v.code_snippet,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "cwe_id": v.cwe_id,
                    "validated": v.validated,
                    "attack_payload": v.attack_payload,
                    "remediation": v.remediation,
                    "timestamp": v.timestamp.isoformat()
                }
                for v in vulns
            ]
        }
    finally:
        db.close()

# Background tasks
async def analyze_alert_for_rules(alert_id: int):
    """AI analyzes alert and generates rule recommendations"""
    try:
        from soc_analyst import analyze_and_recommend
        await analyze_and_recommend(alert_id)
        print(f"✓ Alert {alert_id} analyzed successfully")
    except Exception as e:
        print(f"✗ Error analyzing alert {alert_id}: {e}")

async def perform_security_scan(target: str, validate: bool):
    """Scan code and validate vulnerabilities"""
    try:
        from security_auditor import scan_and_validate
        await scan_and_validate(target, validate)
        print(f"✓ Security scan complete for {target}")
    except Exception as e:
        print(f"✗ Error scanning {target}: {e}")

# Startup event
@app.on_event("startup")
async def startup_event():
    print("=" * 60)
    print("AI Security Platform - Starting Up")
    print("=" * 60)
    print(f"Database: {DATABASE_URL.split('@')[1]}")
    print("API Docs: http://localhost:8000/docs")
    print("=" * 60)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

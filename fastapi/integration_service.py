"""
integration_service.py - Core integration logic
Orchestrates Wazuh, Anomaly Detection, Nessus, and SOC AI
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
from sqlalchemy.orm import Session
import json

from anomaly_detector import AnomalyDetector
from soc_analyst_ai import SOCAnalystAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityOrchestrator:
    """
    Main orchestration service that integrates all components
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.anomaly_detector = AnomalyDetector()
        self.soc_ai = SOCAnalystAI()
        
        # Load or train anomaly model
        try:
            self.anomaly_detector.load_model()
            logger.info("Anomaly detection model loaded")
        except:
            logger.warning("No trained model found. Will need to train first.")
        
        # Metrics tracking
        self.metrics = {
            'total_alerts': 0,
            'total_anomalies': 0,
            'total_responses': 0,
            'avg_mttd': 0,
            'avg_mttr': 0,
            'detection_rate': 0,
            'false_positive_rate': 0
        }
    
    async def process_wazuh_alert(self, alert_data: Dict) -> Dict:
        """
        Process a Wazuh alert through the full pipeline
        
        Pipeline:
        1. Extract alert metadata
        2. Fetch related logs
        3. Run anomaly detection
        4. Query Nessus for vulnerabilities
        5. Calculate composite risk
        6. Generate SOC report
        7. Execute automated response if needed
        8. Update metrics
        
        Returns enriched alert with all AI analysis
        """
        alert_id = alert_data.get('id', 'unknown')
        host = alert_data.get('agent', {}).get('name', 'unknown')
        timestamp = datetime.utcnow()
        
        logger.info(f"Processing alert {alert_id} for host {host}")
        
        enriched_alert = {
            'alert_id': alert_id,
            'original': alert_data,
            'host': host,
            'timestamp': timestamp,
            'processing_stages': {}
        }
        
        try:
            # Stage 1: Extract alert metadata
            rule = alert_data.get('rule', {})
            enriched_alert['rule_id'] = rule.get('id', '')
            enriched_alert['rule_description'] = rule.get('description', '')
            enriched_alert['severity'] = rule.get('level', 0)
            enriched_alert['processing_stages']['metadata'] = 'completed'
            
            # Stage 2: Fetch related logs (mock for now, would query Elastic/Wazuh)
            logs = await self._fetch_related_logs(host, timestamp)
            enriched_alert['log_count'] = len(logs)
            enriched_alert['processing_stages']['logs'] = 'completed'
            
            # Stage 3: Run anomaly detection
            if logs:
                anomaly_results = self.anomaly_detector.predict(logs)
                if anomaly_results:
                    latest_anomaly = anomaly_results[0]
                    enriched_alert['anomaly_score'] = latest_anomaly['anomaly_score']
                    enriched_alert['is_anomaly'] = latest_anomaly['is_anomaly']
                    enriched_alert['anomaly_features'] = latest_anomaly['top_features']
                    enriched_alert['processing_stages']['anomaly'] = 'completed'
                    
                    # Store anomaly in database
                    await self._store_anomaly(latest_anomaly)
                else:
                    enriched_alert['anomaly_score'] = 0.0
                    enriched_alert['is_anomaly'] = False
            else:
                enriched_alert['anomaly_score'] = 0.0
                enriched_alert['is_anomaly'] = False
                enriched_alert['processing_stages']['anomaly'] = 'no_data'
            
            # Stage 4: Query Nessus vulnerabilities
            vuln_data = await self._get_nessus_vulns(host)
            enriched_alert['vulnerabilities'] = vuln_data
            enriched_alert['processing_stages']['vulnerabilities'] = 'completed'
            
            # Stage 5: Calculate composite risk
            risk_score = self._calculate_risk_score(
                enriched_alert['severity'],
                enriched_alert.get('anomaly_score', 0),
                vuln_data
            )
            enriched_alert['risk_score'] = risk_score
            enriched_alert['risk_level'] = self._get_risk_level(risk_score)
            enriched_alert['processing_stages']['risk'] = 'completed'
            
            # Stage 6: Generate SOC report
            soc_report = self.soc_ai.analyze_alert(
                {
                    'alert_id': alert_id,
                    'rule_id': enriched_alert['rule_id'],
                    'rule_description': enriched_alert['rule_description'],
                    'host': host,
                    'severity': enriched_alert['severity'],
                    'src_ip': alert_data.get('data', {}).get('srcip', 'N/A'),
                    'timestamp': timestamp
                },
                {
                    'anomaly_score': enriched_alert.get('anomaly_score', 0),
                    'top_features': enriched_alert.get('anomaly_features', {})
                },
                vuln_data,
                logs
            )
            enriched_alert['soc_report'] = soc_report
            enriched_alert['processing_stages']['soc_report'] = 'completed'
            
            # Stage 7: Automated response
            if self._should_auto_respond(risk_score, enriched_alert['severity']):
                response_result = await self._execute_response(enriched_alert)
                enriched_alert['auto_response'] = response_result
                enriched_alert['processing_stages']['response'] = 'executed'
            else:
                enriched_alert['auto_response'] = {'status': 'manual_review_required'}
                enriched_alert['processing_stages']['response'] = 'skipped'
            
            # Stage 8: Update metrics
            await self._update_metrics(enriched_alert)
            
            enriched_alert['status'] = 'processed'
            enriched_alert['processing_time'] = (datetime.utcnow() - timestamp).total_seconds()
            
        except Exception as e:
            logger.error(f"Error processing alert {alert_id}: {e}")
            enriched_alert['status'] = 'error'
            enriched_alert['error'] = str(e)
        
        return enriched_alert
    
    async def _fetch_related_logs(
        self,
        host: str,
        timestamp: datetime,
        window_minutes: int = 5
    ) -> List[Dict]:
        """
        Fetch logs related to the alert from Elastic/Wazuh
        In production, this would query the Wazuh/Elastic index
        """
        # Mock implementation - in production, query Elastic
        # Example query: GET /wazuh-alerts-*/_search with time range filter
        
        logger.info(f"Fetching logs for {host} around {timestamp}")
        
        # For demo, generate sample logs
        sample_logs = []
        base_time = timestamp - timedelta(minutes=window_minutes)
        
        for i in range(20):
            sample_logs.append({
                'timestamp': base_time + timedelta(seconds=i * 15),
                'host': host,
                'uri': '/api/products',
                'status': 200 if i % 5 != 0 else 500,
                'response_time': 0.05 + (i * 0.01),
                'src_ip': '192.168.1.100',
                'user_agent': 'Mozilla/5.0',
                'bytes_out': 1500,
                'bytes_in': 200,
                'auth_failed': False,
                'is_alert': i % 10 == 0,
                'severity': 5 if i % 10 == 0 else 0
            })
        
        return sample_logs
    
    async def _get_nessus_vulns(self, host: str) -> Dict:
        """
        Get Nessus vulnerability data for host
        In production, this queries Nessus API
        """
        logger.info(f"Fetching Nessus vulnerabilities for {host}")
        
        # Mock implementation - in production, call Nessus API
        # Example: GET /scans/{scan_id}/hosts/{host_id}
        
        return {
            'host': host,
            'vulnerabilities': [
                {
                    'cve': 'CVE-2023-1234',
                    'name': 'SQL Injection in Web Framework',
                    'severity': 'critical',
                    'cvss': 9.8,
                    'exploitable': True
                },
                {
                    'cve': 'CVE-2023-5678',
                    'name': 'XSS in User Input',
                    'severity': 'high',
                    'cvss': 7.5,
                    'exploitable': True
                },
                {
                    'cve': 'CVE-2023-9999',
                    'name': 'Outdated Library with Known Vulnerabilities',
                    'severity': 'medium',
                    'cvss': 5.3,
                    'exploitable': False
                }
            ],
            'max_cvss': 9.8,
            'critical_count': 1,
            'high_count': 1,
            'scan_timestamp': datetime.utcnow().isoformat()
        }
    
    def _calculate_risk_score(
        self,
        wazuh_severity: int,
        anomaly_score: float,
        vuln_data: Dict
    ) -> float:
        """
        Calculate composite risk score (0-10)
        
        Formula:
        risk = w1*wazuh_norm + w2*anomaly + w3*cvss_norm + w4*frequency
        """
        # Normalize Wazuh severity (0-15 scale to 0-10)
        wazuh_norm = min(wazuh_severity / 1.5, 10)
        
        # Anomaly score is already 0-1, scale to 0-10
        anomaly_norm = anomaly_score * 10
        
        # Get max CVSS from vulnerabilities (already 0-10)
        cvss_norm = vuln_data.get('max_cvss', 0)
        
        # Frequency factor (placeholder - would be calculated from recent history)
        frequency = 5 if anomaly_score > 0.7 else 0
        
        # Weights
        w1, w2, w3, w4 = 0.35, 0.30, 0.25, 0.10
        
        risk = (w1 * wazuh_norm + 
                w2 * anomaly_norm + 
                w3 * cvss_norm + 
                w4 * frequency)
        
        return round(min(risk, 10), 2)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Map risk score to severity level"""
        if risk_score >= 7:
            return "critical"
        elif risk_score >= 5:
            return "high"
        elif risk_score >= 3:
            return "medium"
        else:
            return "low"
    
    def _should_auto_respond(self, risk_score: float, severity: int) -> bool:
        """
        Determine if automated response should be triggered
        
        Criteria:
        - Risk score >= 7 (critical)
        - OR Wazuh severity >= 12
        - AND not in maintenance window
        """
        if risk_score >= 7 or severity >= 12:
            # Check if in maintenance window (placeholder)
            # In production, check schedule/calendar
            return True
        return False
    
    async def _execute_response(self, enriched_alert: Dict) -> Dict:
        """
        Execute automated response based on alert type and severity
        
        Response actions:
        - Block source IP
        - Isolate host
        - Kill suspicious process
        - Disable user account
        - Snapshot system for forensics
        """
        alert_id = enriched_alert['alert_id']
        host = enriched_alert['host']
        risk_level = enriched_alert['risk_level']
        
        logger.info(f"Executing automated response for alert {alert_id}")
        
        actions_taken = []
        
        # Determine actions based on risk level
        if risk_level == "critical":
            actions_taken.extend([
                {'action': 'isolate_host', 'target': host, 'status': 'simulated'},
                {'action': 'snapshot_logs', 'target': host, 'status': 'simulated'},
                {'action': 'block_ip', 'target': enriched_alert['original'].get('data', {}).get('srcip', 'N/A'), 'status': 'simulated'}
            ])
        elif risk_level == "high":
            actions_taken.extend([
                {'action': 'block_ip', 'target': enriched_alert['original'].get('data', {}).get('srcip', 'N/A'), 'status': 'simulated'},
                {'action': 'rate_limit', 'target': host, 'status': 'simulated'}
            ])
        else:
            actions_taken.append({
                'action': 'create_ticket',
                'target': alert_id,
                'status': 'simulated'
            })
        
        # Log actions
        for action in actions_taken:
            logger.info(f"[SIMULATED] {action['action']} on {action['target']}")
        
        # Calculate MTTR (simulated - in production, track actual execution time)
        mttr = 2.5  # seconds
        
        return {
            'status': 'success',
            'actions': actions_taken,
            'mttr': mttr,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _store_anomaly(self, anomaly_data: Dict):
        """Store anomaly detection result in database"""
        from main import Anomaly
        
        try:
            anomaly = Anomaly(
                host=anomaly_data['host'],
                timestamp=anomaly_data['timestamp'],
                anomaly_score=anomaly_data['anomaly_score'],
                features=anomaly_data['top_features'],
                is_anomaly=1 if anomaly_data['is_anomaly'] else 0
            )
            self.db.add(anomaly)
            self.db.commit()
            logger.info(f"Stored anomaly for host {anomaly_data['host']}")
        except Exception as e:
            logger.error(f"Error storing anomaly: {e}")
            self.db.rollback()
    
    async def _update_metrics(self, enriched_alert: Dict):
        """Update system metrics based on processed alert"""
        self.metrics['total_alerts'] += 1
        
        if enriched_alert.get('is_anomaly'):
            self.metrics['total_anomalies'] += 1
        
        if enriched_alert.get('auto_response', {}).get('status') == 'success':
            self.metrics['total_responses'] += 1
            
            # Update MTTR
            mttr = enriched_alert['auto_response'].get('mttr', 0)
            current_avg = self.metrics['avg_mttr']
            count = self.metrics['total_responses']
            self.metrics['avg_mttr'] = ((current_avg * (count - 1)) + mttr) / count
        
        # Update MTTD (time to detect)
        processing_time = enriched_alert.get('processing_time', 0)
        current_avg_mttd = self.metrics['avg_mttd']
        count = self.metrics['total_alerts']
        self.metrics['avg_mttd'] = ((current_avg_mttd * (count - 1)) + processing_time) / count
        
        logger.info(f"Metrics updated - Total alerts: {self.metrics['total_alerts']}, "
                   f"Avg MTTD: {self.metrics['avg_mttd']:.2f}s, "
                   f"Avg MTTR: {self.metrics['avg_mttr']:.2f}s")
    
    def get_metrics(self) -> Dict:
        """Get current system metrics"""
        return {
            **self.metrics,
            'timestamp': datetime.utcnow().isoformat(),
            'detection_rate': round(
                (self.metrics['total_anomalies'] / max(self.metrics['total_alerts'], 1)) * 100,
                2
            )
        }
    
    async def train_anomaly_model(self, normal_traffic_logs: List[Dict]):
        """
        Train the anomaly detection model on normal traffic
        Should be run during system initialization or periodically
        """
        logger.info(f"Training anomaly model on {len(normal_traffic_logs)} normal logs")
        
        try:
            self.anomaly_detector.train(normal_traffic_logs, contamination=0.01)
            logger.info("Anomaly model training completed")
            return {'status': 'success', 'samples': len(normal_traffic_logs)}
        except Exception as e:
            logger.error(f"Error training anomaly model: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def batch_process_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """
        Process multiple alerts in batch
        Useful for catching up on backlog or bulk analysis
        """
        logger.info(f"Batch processing {len(alerts)} alerts")
        
        results = []
        for alert in alerts:
            try:
                enriched = await self.process_wazuh_alert(alert)
                results.append(enriched)
            except Exception as e:
                logger.error(f"Error in batch processing: {e}")
                results.append({
                    'alert_id': alert.get('id', 'unknown'),
                    'status': 'error',
                    'error': str(e)
                })
        
        return results
    
    async def generate_summary_report(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> Dict:
        """
        Generate summary report for a time period
        Useful for daily/weekly security briefings
        """
        from main import Alert, Anomaly, Response
        
        # Query database for period
        alerts = self.db.query(Alert).filter(
            Alert.timestamp >= start_time,
            Alert.timestamp <= end_time
        ).all()
        
        anomalies = self.db.query(Anomaly).filter(
            Anomaly.timestamp >= start_time,
            Anomaly.timestamp <= end_time,
            Anomaly.is_anomaly == 1
        ).all()
        
        responses = self.db.query(Response).filter(
            Response.timestamp >= start_time,
            Response.timestamp <= end_time
        ).all()
        
        # Calculate statistics
        severity_distribution = {}
        attack_types = {}
        top_targets = {}
        
        for alert in alerts:
            # Severity distribution
            sev = f"level_{alert.severity}"
            severity_distribution[sev] = severity_distribution.get(sev, 0) + 1
            
            # Top targets
            top_targets[alert.host] = top_targets.get(alert.host, 0) + 1
        
        report = {
            'period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_hours': (end_time - start_time).total_seconds() / 3600
            },
            'summary': {
                'total_alerts': len(alerts),
                'total_anomalies': len(anomalies),
                'total_responses': len(responses),
                'avg_risk_score': round(
                    sum(a.risk_score for a in alerts) / max(len(alerts), 1),
                    2
                )
            },
            'severity_distribution': severity_distribution,
            'top_targets': dict(sorted(
                top_targets.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            'metrics': self.get_metrics()
        }
        
        return report


# Utility functions for integration with FastAPI
async def process_alert_pipeline(alert_data: Dict, db: Session) -> Dict:
    """
    Convenience function to process an alert through the full pipeline
    Can be called from FastAPI endpoints or background tasks
    """
    orchestrator = SecurityOrchestrator(db)
    return await orchestrator.process_wazuh_alert(alert_data)


async def get_system_health(db: Session) -> Dict:
    """Get overall system health status"""
    from main import Alert, Anomaly
    
    recent_time = datetime.utcnow() - timedelta(minutes=5)
    
    recent_alerts = db.query(Alert).filter(
        Alert.timestamp >= recent_time
    ).count()
    
    recent_anomalies = db.query(Anomaly).filter(
        Anomaly.timestamp >= recent_time
    ).count()
    
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'recent_activity': {
            'alerts_last_5min': recent_alerts,
            'anomalies_last_5min': recent_anomalies
        },
        'components': {
            'database': 'connected',
            'anomaly_detector': 'ready',
            'soc_ai': 'ready',
            'wazuh_integration': 'active'
        }
    }


# Testing
if __name__ == "__main__":
    import sys
    
    # Mock database session for testing
    class MockDB:
        def add(self, obj): pass
        def commit(self): pass
        def rollback(self): pass
        def query(self, *args): 
            class MockQuery:
                def filter(self, *args): return self
                def all(self): return []
                def count(self): return 0
            return MockQuery()
    
    async def test_orchestrator():
        db = MockDB()
        orchestrator = SecurityOrchestrator(db)
        
        # Test alert processing
        test_alert = {
            'id': 'test-001',
            'rule': {
                'id': '31103',
                'description': 'SQL injection attempt detected',
                'level': 12
            },
            'agent': {
                'name': 'juiceshop'
            },
            'data': {
                'srcip': '10.0.0.100'
            }
        }
        
        print("Testing alert processing pipeline...")
        result = await orchestrator.process_wazuh_alert(test_alert)
        
        print("\n=== PROCESSING RESULT ===")
        print(json.dumps(result, indent=2, default=str))
        
        print("\n=== SYSTEM METRICS ===")
        print(json.dumps(orchestrator.get_metrics(), indent=2))
    
    # Run test
    asyncio.run(test_orchestrator())

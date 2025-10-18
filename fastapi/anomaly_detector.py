import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime, timedelta
import json
from typing import Dict, List, Tuple

class AnomalyDetector:
    def __init__(self, model_path: str = "models/anomaly_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_names = None
        
    def extract_features(self, logs: List[Dict], time_window: int = 300) -> pd.DataFrame:
        """
        Extract features from raw logs for a time window (seconds)
        
        Features per host per window:
        - conn_count: Number of HTTP requests
        - unique_uris: Distinct endpoints accessed
        - 4xx_count, 5xx_count: Error responses
        - avg_response_time: Average response time
        - failed_auth_count: Failed authentication attempts
        - user_agent_entropy: Entropy of user agent strings
        - distinct_src_ips: Number of unique source IPs
        - avg_bytes_out, avg_bytes_in: Average payload sizes
        - alerts_count: Number of Wazuh alerts in window
        - severity_sum: Sum of alert severities
        """
        if not logs:
            return pd.DataFrame()
        
        df = pd.DataFrame(logs)
        
        # Ensure timestamp column
        if 'timestamp' not in df.columns:
            df['timestamp'] = datetime.utcnow()
        else:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by host and time window
        df['time_window'] = df['timestamp'].dt.floor(f'{time_window}s')
        
        features = []
        for (host, window), group in df.groupby(['host', 'time_window']):
            feature_dict = {
                'host': host,
                'timestamp': window,
                'conn_count': len(group),
                'unique_uris': group['uri'].nunique() if 'uri' in group.columns else 0,
                '4xx_count': len(group[group['status'].between(400, 499)]) if 'status' in group.columns else 0,
                '5xx_count': len(group[group['status'].between(500, 599)]) if 'status' in group.columns else 0,
                'avg_response_time': group['response_time'].mean() if 'response_time' in group.columns else 0,
                'failed_auth_count': len(group[group.get('auth_failed', False)]) if 'auth_failed' in group.columns else 0,
                'distinct_src_ips': group['src_ip'].nunique() if 'src_ip' in group.columns else 1,
                'avg_bytes_out': group['bytes_out'].mean() if 'bytes_out' in group.columns else 0,
                'avg_bytes_in': group['bytes_in'].mean() if 'bytes_in' in group.columns else 0,
                'alerts_count': group['is_alert'].sum() if 'is_alert' in group.columns else 0,
                'severity_sum': group['severity'].sum() if 'severity' in group.columns else 0,
            }
            
            # User agent entropy
            if 'user_agent' in group.columns:
                ua_counts = group['user_agent'].value_counts()
                ua_probs = ua_counts / len(group)
                feature_dict['user_agent_entropy'] = -np.sum(ua_probs * np.log2(ua_probs + 1e-10))
            else:
                feature_dict['user_agent_entropy'] = 0
            
            # Add rolling statistics (deviation from baseline)
            if len(group) > 1:
                feature_dict['conn_count_std'] = group.groupby('host')['timestamp'].count().std()
            else:
                feature_dict['conn_count_std'] = 0
            
            features.append(feature_dict)
        
        return pd.DataFrame(features)
    
    def train(self, normal_logs: List[Dict], contamination: float = 0.01):
        """
        Train Isolation Forest on normal traffic
        
        Args:
            normal_logs: List of log dictionaries from normal traffic
            contamination: Expected proportion of anomalies (default 1%)
        """
        print(f"Extracting features from {len(normal_logs)} normal logs...")
        features_df = self.extract_features(normal_logs)
        
        if features_df.empty:
            raise ValueError("No features extracted from logs")
        
        # Store feature names
        self.feature_names = [col for col in features_df.columns if col not in ['host', 'timestamp']]
        
        X = features_df[self.feature_names].values
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        print(f"Training Isolation Forest with contamination={contamination}...")
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)
        
        # Save model
        self.save_model()
        print(f"Model trained and saved to {self.model_path}")
        
        return self
    
    def predict(self, logs: List[Dict]) -> List[Dict]:
        """
        Predict anomaly scores for new logs
        
        Returns:
            List of dicts with {host, timestamp, anomaly_score, is_anomaly, top_features}
        """
        if self.model is None:
            self.load_model()
        
        features_df = self.extract_features(logs)
        
        if features_df.empty:
            return []
        
        X = features_df[self.feature_names].values
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly scores (lower is more anomalous)
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        # Convert to 0-1 scale (higher = more anomalous)
        anomaly_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        
        results = []
        for idx, row in features_df.iterrows():
            # Get top contributing features
            feature_values = X_scaled[idx]
            feature_importance = np.abs(feature_values)
            top_indices = np.argsort(feature_importance)[-3:][::-1]
            
            top_features = {
                self.feature_names[i]: float(X[idx][i])
                for i in top_indices
            }
            
            results.append({
                'host': row['host'],
                'timestamp': row['timestamp'],
                'anomaly_score': float(anomaly_scores[idx]),
                'is_anomaly': predictions[idx] == -1,
                'top_features': top_features
            })
        
        return results
    
    def save_model(self):
        """Save model and scaler"""
        import os
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        joblib.dump(model_data, self.model_path)
    
    def load_model(self):
        """Load trained model"""
        try:
            model_data = joblib.load(self.model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            print(f"Model loaded from {self.model_path}")
        except FileNotFoundError:
            print(f"Model file not found at {self.model_path}. Train a model first.")
            raise


# Generate synthetic normal traffic for training
def generate_normal_traffic(num_samples: int = 1000) -> List[Dict]:
    """Generate synthetic normal traffic logs for training"""
    np.random.seed(42)
    logs = []
    
    hosts = ['juiceshop', 'web-server-1', 'web-server-2']
    uris = ['/api/products', '/api/users', '/api/basket', '/login', '/search']
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'curl/7.68.0'
    ]
    
    base_time = datetime.utcnow() - timedelta(hours=24)
    
    for i in range(num_samples):
        log = {
            'timestamp': base_time + timedelta(seconds=i * 30),
            'host': np.random.choice(hosts),
            'uri': np.random.choice(uris),
            'status': np.random.choice([200, 200, 200, 304, 404], p=[0.7, 0.15, 0.1, 0.03, 0.02]),
            'response_time': np.random.normal(0.05, 0.02),
            'src_ip': f'192.168.1.{np.random.randint(10, 50)}',
            'user_agent': np.random.choice(user_agents),
            'bytes_out': np.random.randint(200, 5000),
            'bytes_in': np.random.randint(50, 500),
            'auth_failed': False,
            'is_alert': False,
            'severity': 0
        }
        logs.append(log)
    
    return logs


# Generate attack traffic for testing
def generate_attack_traffic(num_samples: int = 100) -> List[Dict]:
    """Generate synthetic attack traffic for testing"""
    np.random.seed(123)
    logs = []
    
    base_time = datetime.utcnow()
    attacker_ip = '10.0.0.100'
    
    for i in range(num_samples):
        # SQL injection attempts
        if i % 3 == 0:
            log = {
                'timestamp': base_time + timedelta(seconds=i),
                'host': 'juiceshop',
                'uri': f'/api/products?id={np.random.randint(1, 100)} OR 1=1',
                'status': 500,
                'response_time': np.random.normal(0.15, 0.05),
                'src_ip': attacker_ip,
                'user_agent': 'sqlmap/1.5',
                'bytes_out': np.random.randint(100, 1000),
                'bytes_in': np.random.randint(500, 2000),
                'auth_failed': False,
                'is_alert': True,
                'severity': 12
            }
        # Brute force attempts
        elif i % 3 == 1:
            log = {
                'timestamp': base_time + timedelta(seconds=i),
                'host': 'juiceshop',
                'uri': '/api/login',
                'status': 401,
                'response_time': np.random.normal(0.08, 0.02),
                'src_ip': attacker_ip,
                'user_agent': 'Hydra/9.0',
                'bytes_out': 150,
                'bytes_in': 200,
                'auth_failed': True,
                'is_alert': True,
                'severity': 8
            }
        # Port scanning
        else:
            log = {
                'timestamp': base_time + timedelta(seconds=i),
                'host': 'juiceshop',
                'uri': f'/api/{np.random.choice(["admin", "config", "backup", "debug"])}',
                'status': 404,
                'response_time': np.random.normal(0.02, 0.01),
                'src_ip': attacker_ip,
                'user_agent': 'Nmap/7.91',
                'bytes_out': 50,
                'bytes_in': 100,
                'auth_failed': False,
                'is_alert': True,
                'severity': 5
            }
        logs.append(log)
    
    return logs


# Main execution
if __name__ == "__main__":
    detector = AnomalyDetector()
    
    print("Generating normal traffic...")
    normal_traffic = generate_normal_traffic(1000)
    
    print("\nTraining anomaly detector...")
    detector.train(normal_traffic, contamination=0.01)
    
    print("\nGenerating attack traffic...")
    attack_traffic = generate_attack_traffic(100)
    
    print("\nTesting on attack traffic...")
    results = detector.predict(attack_traffic)
    
    print(f"\nResults: {len(results)} time windows analyzed")
    anomalies = [r for r in results if r['is_anomaly']]
    print(f"Anomalies detected: {len(anomalies)}")
    
    if anomalies:
        print("\nTop 3 anomalies:")
        for i, anomaly in enumerate(sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True)[:3]):
            print(f"\n{i+1}. Host: {anomaly['host']}")
            print(f"   Score: {anomaly['anomaly_score']:.3f}")
            print(f"   Top features: {anomaly['top_features']}")

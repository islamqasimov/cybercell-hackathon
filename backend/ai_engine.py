"""
AI Engine - Handles LLM interactions for both AI agents
Supports OpenAI API and local Ollama
"""
import os
import json
import requests
from typing import Dict, List, Optional

# Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
USE_OLLAMA = os.getenv("USE_OLLAMA", "true").lower() == "true"

class AIEngine:
    """Unified AI engine for both agents"""
    
    @staticmethod
    async def analyze_alert_with_llm(alert_data: Dict) -> Dict:
        """SOC Analyst: Analyze alert and generate recommendations"""
        
        prompt = f"""You are an expert SOC Analyst AI. Analyze this security alert and provide rule recommendations.

Alert Details:
- Rule ID: {alert_data.get('rule_id')}
- Description: {alert_data.get('rule_description')}
- Host: {alert_data.get('host')}
- Severity: {alert_data.get('severity')}
- Timestamp: {alert_data.get('timestamp')}
- Raw Data: {json.dumps(alert_data.get('raw_data', {}), indent=2)}

Based on this alert, analyze:
1. What attack pattern is being used?
2. Are there similar patterns not covered by existing rules?
3. Should any existing rules be modified?
4. Should any rules be disabled due to false positives?

Respond in JSON format:
{{
  "attack_analysis": "Brief analysis of the attack",
  "recommendations": [
    {{
      "action": "CREATE|MODIFY|DISABLE",
      "rule_id": "RULE-ID",
      "reason": "Detailed reason",
      "current_pattern": "existing pattern (for MODIFY only)",
      "suggested_pattern": "new or improved pattern",
      "severity": "low|medium|high|critical",
      "confidence": 85
    }}
  ]
}}"""

        try:
            response = await AIEngine._call_llm(prompt)
            return json.loads(response)
        except Exception as e:
            print(f"LLM Error: {e}")
            # Fallback to rule-based analysis
            return AIEngine._fallback_alert_analysis(alert_data)
    
    @staticmethod
    async def analyze_code_with_llm(code_snippet: str, file_path: str) -> List[Dict]:
        """Security Auditor: Analyze code for vulnerabilities"""
        
        prompt = f"""You are an expert Security Auditor AI. Analyze this code for security vulnerabilities.

File: {file_path}
Code:
```
{code_snippet}
```

Identify all security vulnerabilities and respond in JSON format:
{{
  "vulnerabilities": [
    {{
      "type": "SQL Injection|XSS|Path Traversal|etc",
      "line_number": 45,
      "code_snippet": "vulnerable code",
      "severity": "critical|high|medium|low",
      "cvss_score": 9.8,
      "cwe_id": "CWE-89",
      "description": "Brief description",
      "attack_payload": "Example exploit payload",
      "remediation": "Secure code example"
    }}
  ]
}}"""

        try:
            response = await AIEngine._call_llm(prompt)
            result = json.loads(response)
            return result.get('vulnerabilities', [])
        except Exception as e:
            print(f"LLM Error: {e}")
            return []
    
    @staticmethod
    async def _call_llm(prompt: str) -> str:
        """Call LLM (OpenAI or Ollama)"""
        
        if USE_OLLAMA:
            return await AIEngine._call_ollama(prompt)
        else:
            return await AIEngine._call_openai(prompt)
    
    @staticmethod
    async def _call_openai(prompt: str) -> str:
        """Call OpenAI API"""
        if not OPENAI_API_KEY:
            raise Exception("OpenAI API key not configured")
        
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a security expert AI assistant."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 2000
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=60
        )
        response.raise_for_status()
        
        result = response.json()
        return result['choices'][0]['message']['content']
    
    @staticmethod
    async def _call_ollama(prompt: str) -> str:
        """Call local Ollama"""
        data = {
            "model": "llama2",  # or "mistral", "codellama"
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3
            }
        }
        
        try:
            response = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json=data,
                timeout=120
            )
            response.raise_for_status()
            result = response.json()
            return result.get('response', '')
        except Exception as e:
            print(f"Ollama error: {e}")
            raise
    
    @staticmethod
    def _fallback_alert_analysis(alert_data: Dict) -> Dict:
        """Fallback rule-based analysis when LLM unavailable"""
        rule_id = alert_data.get('rule_id', '')
        
        recommendations = []
        
        # Simple pattern-based recommendations
        if 'SQLI' in rule_id:
            recommendations.append({
                "action": "CREATE",
                "rule_id": "SQLI-COMMENT-001",
                "reason": "SQL comment injection pattern detected",
                "suggested_pattern": r"['\"]--",
                "severity": "high",
                "confidence": 80
            })
        
        if 'XSS' in rule_id:
            recommendations.append({
                "action": "CREATE",
                "rule_id": "XSS-EVENT-001",
                "reason": "Event handler XSS pattern detected",
                "suggested_pattern": r"on\w+\s*=",
                "severity": "medium",
                "confidence": 75
            })
        
        return {
            "attack_analysis": f"Pattern-based analysis for {rule_id}",
            "recommendations": recommendations
        }


# Utility functions
async def generate_incident_report(alert_id: int, analysis: Dict) -> str:
    """Generate formatted incident report"""
    
    report = f"""
═══════════════════════════════════════════════
  AI SOC ANALYST - INCIDENT REPORT
═══════════════════════════════════════════════

ALERT ID: INC-{alert_id}
TIMESTAMP: {analysis.get('timestamp', 'N/A')}
SEVERITY: {analysis.get('severity', 'UNKNOWN')}

ATTACK ANALYSIS:
{analysis.get('attack_analysis', 'No analysis available')}

RULE RECOMMENDATIONS:
──────────────────────────────────────────────
"""
    
    for rec in analysis.get('recommendations', []):
        report += f"""
[{rec['action']} RULE]
Rule ID: {rec['rule_id']}
Reason: {rec['reason']}
Confidence: {rec['confidence']}%
"""
        
        if rec.get('current_pattern'):
            report += f"Current: {rec['current_pattern']}\n"
        if rec.get('suggested_pattern'):
            report += f"Suggested: {rec['suggested_pattern']}\n"
    
    report += "\n═══════════════════════════════════════════════\n"
    
    return report


async def generate_security_report(vulnerabilities: List[Dict]) -> str:
    """Generate formatted security audit report"""
    
    critical = len([v for v in vulnerabilities if v['severity'] == 'critical'])
    high = len([v for v in vulnerabilities if v['severity'] == 'high'])
    
    report = f"""
═══════════════════════════════════════════════
  AI SECURITY AUDITOR REPORT
═══════════════════════════════════════════════

VULNERABILITIES FOUND: {len(vulnerabilities)}
CRITICAL: {critical} | HIGH: {high}

"""
    
    for vuln in vulnerabilities:
        report += f"""
─────────────────────────────────────────────────
[{vuln['severity'].upper()}] {vuln['type']}
─────────────────────────────────────────────────
Line: {vuln['line_number']}
Code: {vuln['code_snippet']}

CVSS Score: {vuln['cvss_score']}
CWE-{vuln['cwe_id']}

ATTACK PAYLOAD: {vuln.get('attack_payload', 'N/A')}

REMEDIATION:
{vuln['remediation']}

"""
    
    return report

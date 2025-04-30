import numpy as np
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from sklearn.ensemble import IsolationForest
from .pattern_analyzer import PatternAnalyzer
from .anomaly_detector import AnomalyDetector
from .threat_classifier import ThreatClassifier
from urllib.parse import urlparse, parse_qs
import re
import torch

class AIEngine:
    def __init__(self):
        # Initialize base analyzers
        self.pattern_analyzer = PatternAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.threat_classifier = ThreatClassifier()
        
        # Initialize AI models
        print("Loading AI models...")
        
        # Pattern Recognition - CodeBERT
        try:
            self.pattern_tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
            self.pattern_model = AutoModelForSequenceClassification.from_pretrained(
                "microsoft/codebert-base",
                num_labels=3  # safe, suspicious, malicious
            )
            print("✓ Pattern Recognition (CodeBERT) loaded")
        except Exception as e:
            print(f"× Pattern Recognition model loading failed: {str(e)}")
            self.pattern_model = None
        
        # Anomaly Detection - Isolation Forest
        try:
            self.anomaly_model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            print("✓ Anomaly Detection (Isolation Forest) initialized")
        except Exception as e:
            print(f"× Anomaly Detection model loading failed: {str(e)}")
            self.anomaly_model = None
        
        # Threat Classification - DistilBERT
        try:
            self.threat_tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
            self.threat_model = AutoModelForSequenceClassification.from_pretrained(
                "distilbert-base-uncased",
                num_labels=4  # low, medium, high, critical
            )
            print("✓ Threat Classification (DistilBERT) loaded")
        except Exception as e:
            print(f"× Threat Classification model loading failed: {str(e)}")
            self.threat_model = None
    
    def analyze_request(self, request_data):
        """Analyze incoming request for potential security threats"""
        # Pattern analysis
        pattern_score = self._analyze_patterns(request_data)
        
        # Anomaly detection
        anomaly_score = self._detect_anomalies(request_data)
        
        # Threat classification
        threat_level = self._classify_threat(request_data)
        
        # Calculate final risk score
        risk_score = self._calculate_risk_score(pattern_score, anomaly_score, threat_level)
        
        return {
            'pattern_score': pattern_score,
            'anomaly_score': anomaly_score,
            'threat_level': threat_level,
            'risk_score': risk_score
        }
    
    def _analyze_patterns(self, request_data):
        """Analyze patterns using CodeBERT"""
        if not self.pattern_model:
            return self.pattern_analyzer.analyze(request_data)
        
        try:
            text = self._prepare_text(request_data)
            inputs = self.pattern_tokenizer(text, return_tensors="pt", truncation=True)
            
            with torch.no_grad():
                outputs = self.pattern_model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)
                risk_score = float(probs[0][2])  # probability of 'malicious' class
            
            return risk_score
        except Exception:
            return self.pattern_analyzer.analyze(request_data)
    
    def _detect_anomalies(self, request_data):
        """Detect anomalies using Isolation Forest"""
        if not self.anomaly_model:
            return self.anomaly_detector.detect(request_data)
        
        try:
            features = self._extract_features(request_data)
            score = self.anomaly_model.predict([features])[0]
            return float((score + 1) / 2)  # Convert to 0-1 range
        except Exception:
            return self.anomaly_detector.detect(request_data)
    
    def _classify_threat(self, request_data):
        """Classify threat level using DistilBERT"""
        if not self.threat_model:
            return self.threat_classifier.classify(request_data)
        
        try:
            text = self._prepare_text(request_data)
            inputs = self.threat_tokenizer(text, return_tensors="pt", truncation=True)
            
            with torch.no_grad():
                outputs = self.threat_model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)
                
                # Calculate weighted threat level
                weights = [0.1, 0.3, 0.6, 0.9]  # weights for [low, medium, high, critical]
                threat_level = sum(float(p) * w for p, w in zip(probs[0], weights))
            
            return threat_level
        except Exception:
            return self.threat_classifier.classify(request_data)
    
    def _prepare_text(self, request_data):
        """Prepare request data as text for model input"""
        parts = []
        
        if isinstance(request_data, str):
            return request_data
        
        if isinstance(request_data, dict):
            for key, value in request_data.items():
                parts.append(f"{key}: {value}")
        
        return " ".join(parts)
    
    def _extract_features(self, request_data):
        """Extract numerical features for anomaly detection"""
        text = self._prepare_text(request_data)
        
        # Basic features
        features = [
            len(text),  # request length
            sum(not c.isalnum() for c in text) / len(text) if text else 0,  # special char ratio
            len(set(text)) / len(text) if text else 0,  # character diversity
            text.count('/'),  # path depth
            text.count('='),  # parameter count
        ]
        
        return features
    
    def _calculate_risk_score(self, pattern_score, anomaly_score, threat_level):
        """Calculate overall risk score"""
        weights = {
            'pattern': 0.3,
            'anomaly': 0.4,
            'threat': 0.3
        }
        
        return min(1.0, (
            pattern_score * weights['pattern'] +
            anomaly_score * weights['anomaly'] +
            threat_level * weights['threat']
        ))

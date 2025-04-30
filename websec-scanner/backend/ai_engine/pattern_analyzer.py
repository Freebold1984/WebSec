import re
from typing import Dict, List, Any
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from collections import defaultdict

class PatternAnalyzer:
    def __init__(self):
        # Initialize common attack patterns
        self.attack_patterns = {
            'xss': [
                r'<script.*?>.*?</script>',
                r'javascript:.*?',
                r'onerror=.*?',
                r'onload=.*?',
                r'eval\(.*?\)',
                r'alert\(.*?\)'
            ],
            'sql_injection': [
                r'\bUNION\b.*?\bSELECT\b',
                r'--.*?$',
                r'/\*.*?\*/',
                r'\bOR\b.*?=.*?',
                r'\bAND\b.*?=.*?',
                r"'.*?'.*?=.*?'",
                r'1=1'
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%252e%252e%252f'
            ],
            'command_injection': [
                r';&',
                r'\|.*?\w+',
                r'`.*?`',
                r'\$\(.*?\)',
                r'\w+\/\.\.'
            ],
            'file_inclusion': [
                r'php://filter',
                r'php://input',
                r'data://text/plain',
                r'expect://',
                r'file://'
            ]
        }
        
        # Initialize vectorizer for text analysis
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 3)
        )
        
        # Initialize pattern weights
        self.pattern_weights = defaultdict(lambda: 1.0)
        self._initialize_weights()
    
    def analyze(self, request_data: Dict[str, Any]) -> float:
        """
        Analyze request data for suspicious patterns
        Returns a risk score between 0 and 1
        """
        total_score = 0
        total_weight = 0
        
        # Analyze URL patterns
        if 'url' in request_data:
            url_score = self._analyze_url(request_data['url'])
            total_score += url_score * self.pattern_weights['url']
            total_weight += self.pattern_weights['url']
        
        # Analyze parameters
        if 'params' in request_data:
            params_score = self._analyze_parameters(request_data['params'])
            total_score += params_score * self.pattern_weights['params']
            total_weight += self.pattern_weights['params']
        
        # Analyze headers
        if 'headers' in request_data:
            headers_score = self._analyze_headers(request_data['headers'])
            total_score += headers_score * self.pattern_weights['headers']
            total_weight += self.pattern_weights['headers']
        
        # Analyze body content if present
        if 'body' in request_data:
            body_score = self._analyze_body(request_data['body'])
            total_score += body_score * self.pattern_weights['body']
            total_weight += self.pattern_weights['body']
        
        # Calculate normalized risk score
        return min(1.0, total_score / total_weight) if total_weight > 0 else 0.0
    
    def _analyze_url(self, url: str) -> float:
        """Analyze URL for suspicious patterns"""
        score = 0
        
        # Check for encoded characters
        encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', url))
        if encoded_chars > 0:
            score += min(0.3, encoded_chars * 0.05)
        
        # Check for suspicious path traversal
        if any(re.search(pattern, url) for pattern in self.attack_patterns['path_traversal']):
            score += 0.4
        
        # Check for suspicious file inclusion
        if any(re.search(pattern, url) for pattern in self.attack_patterns['file_inclusion']):
            score += 0.5
        
        # Check for SQL injection attempts in URL
        if any(re.search(pattern, url, re.IGNORECASE) for pattern in self.attack_patterns['sql_injection']):
            score += 0.6
        
        return min(1.0, score)
    
    def _analyze_parameters(self, params: Dict[str, str]) -> float:
        """Analyze request parameters for suspicious patterns"""
        score = 0
        
        for param_name, param_value in params.items():
            # Check for common attack patterns in parameter names
            if re.search(r'(pass|admin|root|cmd|exec|system)', param_name, re.IGNORECASE):
                score += 0.2
            
            # Check for XSS patterns
            if any(re.search(pattern, str(param_value), re.IGNORECASE) for pattern in self.attack_patterns['xss']):
                score += 0.4
            
            # Check for SQL injection patterns
            if any(re.search(pattern, str(param_value), re.IGNORECASE) for pattern in self.attack_patterns['sql_injection']):
                score += 0.5
            
            # Check for command injection patterns
            if any(re.search(pattern, str(param_value)) for pattern in self.attack_patterns['command_injection']):
                score += 0.6
        
        return min(1.0, score)
    
    def _analyze_headers(self, headers: Dict[str, str]) -> float:
        """Analyze request headers for suspicious patterns"""
        score = 0
        
        suspicious_headers = {
            'User-Agent': r'(curl|wget|nikto|sqlmap|w3af|acunetix|nessus)',
            'Referer': r'(\.\.\/|%2e%2e%2f|javascript:)',
            'Cookie': r'(\'|"|\-\-|\+union\+)',
            'Accept': r'(../|\.\.\\|\.\./|\./)',
            'Host': r'(\.\.|\\\\|\/\/)'
        }
        
        for header, pattern in suspicious_headers.items():
            if header in headers and re.search(pattern, headers[header], re.IGNORECASE):
                score += 0.3
        
        return min(1.0, score)
    
    def _analyze_body(self, body: str) -> float:
        """Analyze request body for suspicious patterns"""
        score = 0
        
        # Convert body to string if it's not already
        body_str = str(body)
        
        # Check for all types of attack patterns
        for attack_type, patterns in self.attack_patterns.items():
            if any(re.search(pattern, body_str, re.IGNORECASE) for pattern in patterns):
                score += self.pattern_weights[attack_type]
        
        # Perform text analysis for suspicious content
        try:
            # Vectorize the content
            features = self.vectorizer.fit_transform([body_str])
            
            # Check for suspicious terms frequency
            suspicious_terms = ['admin', 'password', 'exec', 'system', 'root']
            term_scores = sum(1 for term in suspicious_terms if term in body_str.lower())
            score += min(0.3, term_scores * 0.1)
            
        except Exception:
            # If text analysis fails, fall back to basic pattern matching
            pass
        
        return min(1.0, score)
    
    def _initialize_weights(self):
        """Initialize weights for different pattern types"""
        self.pattern_weights.update({
            'url': 1.2,
            'params': 1.5,
            'headers': 1.0,
            'body': 1.3,
            'xss': 0.8,
            'sql_injection': 1.0,
            'path_traversal': 0.7,
            'command_injection': 1.0,
            'file_inclusion': 0.9
        })
    
    def update_pattern_weights(self, new_weights: Dict[str, float]):
        """Update pattern weights based on learning"""
        self.pattern_weights.update(new_weights)

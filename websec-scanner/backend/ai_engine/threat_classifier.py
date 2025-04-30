from typing import Dict, List, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from collections import defaultdict

class ThreatClassifier:
    def __init__(self):
        # Initialize the classifier
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Define threat categories and their base weights
        self.threat_categories = {
            'xss': {
                'weight': 0.8,
                'description': 'Cross-Site Scripting',
                'impact': 'High',
                'cvss_base': 6.1
            },
            'sql_injection': {
                'weight': 0.9,
                'description': 'SQL Injection',
                'impact': 'Critical',
                'cvss_base': 8.5
            },
            'rce': {
                'weight': 1.0,
                'description': 'Remote Code Execution',
                'impact': 'Critical',
                'cvss_base': 9.0
            },
            'file_inclusion': {
                'weight': 0.7,
                'description': 'File Inclusion',
                'impact': 'High',
                'cvss_base': 7.5
            },
            'csrf': {
                'weight': 0.6,
                'description': 'Cross-Site Request Forgery',
                'impact': 'Medium',
                'cvss_base': 6.8
            },
            'ssrf': {
                'weight': 0.75,
                'description': 'Server-Side Request Forgery',
                'impact': 'High',
                'cvss_base': 7.7
            }
        }
        
        # Initialize threat patterns database
        self.threat_patterns = self._initialize_threat_patterns()
        
        # Track historical classifications
        self.classification_history = defaultdict(list)
    
    def classify(self, request_data: Dict[str, Any]) -> float:
        """
        Classify the threat level of the request
        Returns a threat score between 0 and 1
        """
        # Extract threat indicators
        indicators = self._extract_threat_indicators(request_data)
        
        # Calculate base threat score
        base_score = self._calculate_base_threat_score(indicators)
        
        # Apply context-based adjustments
        context_score = self._apply_context_adjustments(request_data, indicators)
        
        # Calculate final threat score
        final_score = self._calculate_final_score(base_score, context_score)
        
        # Update classification history
        self._update_classification_history(request_data, indicators, final_score)
        
        return final_score
    
    def _initialize_threat_patterns(self) -> Dict[str, List[str]]:
        """Initialize database of threat patterns"""
        return {
            'xss': [
                r'<script.*?>',
                r'javascript:',
                r'onload=',
                r'onerror=',
                r'onclick=',
                r'alert\(',
                r'String\.fromCharCode',
                r'eval\('
            ],
            'sql_injection': [
                r'UNION.*SELECT',
                r'INSERT.*INTO',
                r'UPDATE.*SET',
                r'DELETE.*FROM',
                r'DROP.*TABLE',
                r'EXEC.*sp_',
                r'WAITFOR.*DELAY'
            ],
            'rce': [
                r'system\(',
                r'exec\(',
                r'shell_exec',
                r'passthru',
                r'eval\(',
                r'assert\(',
                r'preg_replace.*\/e'
            ],
            'file_inclusion': [
                r'include\(',
                r'require\(',
                r'include_once\(',
                r'require_once\(',
                r'php:\/\/input',
                r'php:\/\/filter',
                r'\.\.\/\.\.\\',
            ]
        }
    
    def _extract_threat_indicators(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract threat indicators from request data"""
        indicators = defaultdict(float)
        
        # Analyze URL
        if 'url' in request_data:
            url = request_data['url']
            for category, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    import re
                    if re.search(pattern, url, re.IGNORECASE):
                        indicators[category] += self.threat_categories[category]['weight']
        
        # Analyze parameters
        if 'params' in request_data:
            for param_name, param_value in request_data['params'].items():
                self._analyze_value(param_value, indicators)
        
        # Analyze headers
        if 'headers' in request_data:
            for header_name, header_value in request_data['headers'].items():
                self._analyze_value(header_value, indicators)
        
        # Analyze body
        if 'body' in request_data:
            self._analyze_value(request_data['body'], indicators)
        
        return indicators
    
    def _analyze_value(self, value: str, indicators: Dict[str, float]):
        """Analyze a value for threat patterns"""
        value_str = str(value)
        for category, patterns in self.threat_patterns.items():
            for pattern in patterns:
                import re
                if re.search(pattern, value_str, re.IGNORECASE):
                    indicators[category] += self.threat_categories[category]['weight']
    
    def _calculate_base_threat_score(self, indicators: Dict[str, float]) -> float:
        """Calculate base threat score from indicators"""
        if not indicators:
            return 0.0
        
        # Calculate weighted average of threat indicators
        total_weight = sum(self.threat_categories[cat]['weight'] for cat in indicators.keys())
        if total_weight == 0:
            return 0.0
        
        weighted_sum = sum(
            score * self.threat_categories[cat]['weight']
            for cat, score in indicators.items()
        )
        
        return min(1.0, weighted_sum / total_weight)
    
    def _apply_context_adjustments(self, request_data: Dict[str, Any], indicators: Dict[str, float]) -> float:
        """Apply context-based adjustments to threat score"""
        context_score = 0.0
        
        # Check for authentication context
        if 'headers' in request_data:
            headers = request_data['headers']
            if 'Authorization' in headers or 'Cookie' in headers:
                context_score += 0.2  # Increase score for authenticated contexts
        
        # Check for sensitive operations
        if 'url' in request_data:
            url = request_data['url'].lower()
            sensitive_patterns = ['admin', 'config', 'setup', 'install', 'backup']
            if any(pattern in url for pattern in sensitive_patterns):
                context_score += 0.15
        
        # Check for multiple threat categories
        if len(indicators) > 1:
            context_score += 0.1 * (len(indicators) - 1)
        
        return min(1.0, context_score)
    
    def _calculate_final_score(self, base_score: float, context_score: float) -> float:
        """Calculate final threat score"""
        # Combine base score and context score with weights
        final_score = (0.7 * base_score) + (0.3 * context_score)
        return min(1.0, final_score)
    
    def _update_classification_history(self, request_data: Dict[str, Any], 
                                    indicators: Dict[str, float], 
                                    final_score: float):
        """Update classification history"""
        from datetime import datetime
        
        # Create classification record
        record = {
            'timestamp': datetime.now().isoformat(),
            'score': final_score,
            'indicators': dict(indicators),
            'method': request_data.get('method', 'UNKNOWN'),
            'url': request_data.get('url', '')
        }
        
        # Add to history
        self.classification_history['classifications'].append(record)
        
        # Keep history size manageable
        if len(self.classification_history['classifications']) > 1000:
            self.classification_history['classifications'].pop(0)
    
    def get_threat_details(self, indicators: Dict[str, float]) -> List[Dict[str, Any]]:
        """Get detailed information about detected threats"""
        threats = []
        for category, score in indicators.items():
            if score > 0 and category in self.threat_categories:
                threat_info = self.threat_categories[category].copy()
                threat_info.update({
                    'category': category,
                    'score': score,
                    'confidence': min(1.0, score * threat_info['weight'])
                })
                threats.append(threat_info)
        
        return sorted(threats, key=lambda x: x['score'], reverse=True)
    
    def update_threat_patterns(self, new_patterns: Dict[str, List[str]]):
        """Update threat patterns database"""
        for category, patterns in new_patterns.items():
            if category in self.threat_patterns:
                self.threat_patterns[category].extend(patterns)
    
    def get_classification_history(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get classification history for analysis"""
        return dict(self.classification_history)

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Any
import re
from collections import defaultdict

class AnomalyDetector:
    def __init__(self):
        # Initialize isolation forest model for anomaly detection
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        
        # Initialize scaler for feature normalization
        self.scaler = StandardScaler()
        
        # Initialize baseline statistics
        self.baseline_stats = {
            'request_length': [],
            'param_count': [],
            'header_count': [],
            'special_char_ratio': [],
            'entropy_values': []
        }
        
        # Track historical patterns
        self.pattern_history = defaultdict(list)
        
        # Initialize thresholds
        self.thresholds = {
            'request_length': (100, 10000),  # min, max
            'param_count': (0, 50),
            'header_count': (3, 30),
            'special_char_ratio': (0.0, 0.3),
            'entropy_threshold': 5.0
        }
    
    def detect(self, request_data: Dict[str, Any]) -> float:
        """
        Detect anomalies in the request data
        Returns an anomaly score between 0 and 1
        """
        # Extract features from request data
        features = self._extract_features(request_data)
        
        # Update baseline statistics
        self._update_baseline(features)
        
        # Calculate basic anomaly indicators
        basic_score = self._calculate_basic_anomaly_score(features)
        
        # Prepare feature vector for ML model
        feature_vector = self._prepare_feature_vector(features)
        
        # Get ML-based anomaly score
        ml_score = self._get_ml_anomaly_score(feature_vector)
        
        # Combine scores with weights
        final_score = (0.6 * ml_score + 0.4 * basic_score)
        
        # Update pattern history
        self._update_pattern_history(request_data, final_score)
        
        return final_score
    
    def _extract_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract relevant features from request data"""
        features = {}
        
        # Calculate request length
        request_str = str(request_data)
        features['request_length'] = len(request_str)
        
        # Count parameters
        params = request_data.get('params', {})
        features['param_count'] = len(params)
        
        # Count headers
        headers = request_data.get('headers', {})
        features['header_count'] = len(headers)
        
        # Calculate special character ratio
        special_chars = re.findall(r'[^a-zA-Z0-9\s]', request_str)
        features['special_char_ratio'] = len(special_chars) / len(request_str) if request_str else 0
        
        # Calculate entropy
        features['entropy'] = self._calculate_entropy(request_str)
        
        # Additional feature: Unique character ratio
        unique_chars = len(set(request_str))
        features['unique_char_ratio'] = unique_chars / len(request_str) if request_str else 0
        
        return features
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of the data"""
        if not data:
            return 0
        
        # Calculate frequency of each character
        freq = defaultdict(int)
        for char in data:
            freq[char] += 1
        
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _update_baseline(self, features: Dict[str, float]):
        """Update baseline statistics with new features"""
        for key, value in features.items():
            if key in self.baseline_stats:
                self.baseline_stats[key].append(value)
                # Keep only recent history
                if len(self.baseline_stats[key]) > 1000:
                    self.baseline_stats[key].pop(0)
    
    def _calculate_basic_anomaly_score(self, features: Dict[str, float]) -> float:
        """Calculate basic anomaly score based on thresholds and statistics"""
        score = 0
        
        # Check request length
        if not self.thresholds['request_length'][0] <= features['request_length'] <= self.thresholds['request_length'][1]:
            score += 0.3
        
        # Check parameter count
        if not self.thresholds['param_count'][0] <= features['param_count'] <= self.thresholds['param_count'][1]:
            score += 0.2
        
        # Check header count
        if not self.thresholds['header_count'][0] <= features['header_count'] <= self.thresholds['header_count'][1]:
            score += 0.15
        
        # Check special character ratio
        if not self.thresholds['special_char_ratio'][0] <= features['special_char_ratio'] <= self.thresholds['special_char_ratio'][1]:
            score += 0.25
        
        # Check entropy
        if features['entropy'] > self.thresholds['entropy_threshold']:
            score += 0.2
        
        return min(1.0, score)
    
    def _prepare_feature_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Prepare feature vector for ML model"""
        feature_vector = np.array([
            features['request_length'],
            features['param_count'],
            features['header_count'],
            features['special_char_ratio'],
            features['entropy'],
            features['unique_char_ratio']
        ]).reshape(1, -1)
        
        # Scale features
        if len(self.baseline_stats['request_length']) > 10:  # Ensure enough data for scaling
            try:
                feature_vector = self.scaler.fit_transform(feature_vector)
            except Exception:
                # Fallback if scaling fails
                pass
        
        return feature_vector
    
    def _get_ml_anomaly_score(self, feature_vector: np.ndarray) -> float:
        """Get anomaly score from ML model"""
        try:
            # Train model if enough data is available
            if len(self.baseline_stats['request_length']) > 10:
                # Prepare training data from baseline stats
                training_data = np.array([
                    self.baseline_stats['request_length'],
                    self.baseline_stats['param_count'],
                    self.baseline_stats['header_count'],
                    self.baseline_stats['special_char_ratio'],
                    self.baseline_stats['entropy_values']
                ]).T
                
                # Fit model
                self.isolation_forest.fit(training_data)
                
                # Get anomaly score
                score = self.isolation_forest.score_samples(feature_vector)[0]
                
                # Normalize score to 0-1 range
                score = 1 - (score + 0.5)  # Convert to anomaly score
                return min(1.0, max(0.0, score))
            
        except Exception:
            # Fallback to basic score if ML fails
            pass
        
        return 0.5  # Default score if ML is not ready
    
    def _update_pattern_history(self, request_data: Dict[str, Any], anomaly_score: float):
        """Update pattern history with new request data"""
        # Store simplified request data with timestamp
        from datetime import datetime
        
        pattern_data = {
            'timestamp': datetime.now().isoformat(),
            'score': anomaly_score,
            'method': request_data.get('method', 'UNKNOWN'),
            'path': request_data.get('url', ''),
            'param_count': len(request_data.get('params', {}))
        }
        
        self.pattern_history['requests'].append(pattern_data)
        
        # Keep only recent history
        if len(self.pattern_history['requests']) > 1000:
            self.pattern_history['requests'].pop(0)
    
    def update_thresholds(self, new_thresholds: Dict[str, Any]):
        """Update anomaly detection thresholds"""
        self.thresholds.update(new_thresholds)
    
    def get_pattern_history(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get pattern history for analysis"""
        return dict(self.pattern_history)

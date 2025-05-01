import os
import pytest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from backend.ai_engine.model import AIEngine

@pytest.fixture
def ai_engine():
    return AIEngine()

def test_prepare_text_with_string(ai_engine):
    text = "sample request"
    assert ai_engine._prepare_text(text) == text

def test_prepare_text_with_dict(ai_engine):
    data = {"key1": "value1", "key2": "value2"}
    prepared = ai_engine._prepare_text(data)
    assert "key1: value1" in prepared and "key2: value2" in prepared

def test_prepare_text_with_other(ai_engine):
    data = 12345
    assert ai_engine._prepare_text(data) == "12345"

@patch('websec_scanner.backend.ai_engine.model.requests.post')
def test_analyze_patterns_api_success(mock_post, ai_engine):
    mock_response = MagicMock()
    mock_response.json.return_value = [{"score": 0.8}]
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    score = ai_engine._analyze_patterns("test data")
    assert score == 0.8

@patch('websec_scanner.backend.ai_engine.model.requests.post')
def test_analyze_patterns_api_failure_fallback(mock_post, ai_engine):
    mock_post.side_effect = Exception("API failure")
    fallback_score = 0.5
    ai_engine.pattern_analyzer.analyze = MagicMock(return_value=fallback_score)

    score = ai_engine._analyze_patterns("test data")
    assert score == fallback_score

@patch('websec_scanner.backend.ai_engine.model.requests.post')
def test_detect_anomalies_api_success(mock_post, ai_engine):
    mock_response = MagicMock()
    mock_response.json.return_value = [{"score": 0.7}]
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    score = ai_engine._detect_anomalies("test data")
    assert score == 0.7

@patch('websec_scanner.backend.ai_engine.model.requests.post')
def test_detect_anomalies_api_failure_fallback(mock_post, ai_engine):
    mock_post.side_effect = Exception("API failure")
    fallback_score = 0.4
    ai_engine.anomaly_detector.detect = MagicMock(return_value=fallback_score)

    score = ai_engine._detect_anomalies("test data")
    assert score == fallback_score

@patch('websec_scanner.backend.ai_engine.model.requests.post')
def test_classify_threat_api_success(mock_post, ai_engine):
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {"score": 0.1},
        {"score": 0.2},
        {"score": 0.3},
        {"score": 0.4}
    ]
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    expected_threat_level = 0.1*0.1 + 0.2*0.3 + 0.3*0.6 + 0.4*0.9
    threat_level = ai_engine._classify_threat("test data")
    assert abs(threat_level - expected_threat_level) < 1e-6

@patch('websec_scanner.backend.ai_engine.model.requests.post')
def test_classify_threat_api_failure_fallback(mock_post, ai_engine):
    mock_post.side_effect = Exception("API failure")
    fallback_level = 0.6
    ai_engine.threat_classifier.classify = MagicMock(return_value=fallback_level)

    threat_level = ai_engine._classify_threat("test data")
    assert threat_level == fallback_level

def test_calculate_risk_score(ai_engine):
    pattern_score = 0.5
    anomaly_score = 0.6
    threat_level = 0.7
    risk_score = ai_engine._calculate_risk_score(pattern_score, anomaly_score, threat_level)
    expected = min(1.0, 0.5*0.3 + 0.6*0.4 + 0.7*0.3)
    assert abs(risk_score - expected) < 1e-6

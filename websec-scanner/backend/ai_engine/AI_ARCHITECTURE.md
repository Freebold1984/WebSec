# AI Architecture - WebSec Scanner

## Overview
The WebSec Scanner uses a combination of three AI models for comprehensive security analysis:

1. **Pattern Recognition (CodeBERT)**
   - Model: microsoft/codebert-base
   - Purpose: Analyzes code patterns and identifies potential security vulnerabilities
   - Type: Transformer-based model
   - Training: Pre-trained on code repositories, fine-tuned for security patterns

2. **Anomaly Detection (Isolation Forest)**
   - Model: Scikit-learn Isolation Forest
   - Purpose: Detects unusual patterns in requests that might indicate attacks
   - Features:
     - Request length
     - Special character ratios
     - Shannon entropy
     - Parameter counts

3. **Threat Classification (DistilBERT)**
   - Model: distilbert-base-uncased
   - Purpose: Classifies potential threats and assigns risk levels
   - Labels: ['low', 'medium', 'high', 'critical']
   - Training: Fine-tuned on security vulnerability datasets

## Model Loading
Models are loaded from Hugging Face Hub for transformers and initialized locally for statistical models:
- CodeBERT and DistilBERT are downloaded from Hugging Face
- Isolation Forest is initialized with scikit-learn

## Risk Scoring
The final risk score is calculated using a weighted combination:
- Pattern Recognition: 30%
- Anomaly Detection: 40%
- Threat Classification: 30%

## Usage
The AI engine automatically downloads and initializes models on first use. Models are cached locally in the `models` directory for subsequent use.

## Dependencies
- transformers
- tensorflow
- scikit-learn
- numpy
- torch (for transformer models)

## Model Updates
Models can be updated by modifying the configuration in `models/config.py`. The system supports both transformer-based and traditional ML models.
